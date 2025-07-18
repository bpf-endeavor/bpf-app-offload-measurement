#define _GNU_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* If a value should be shared across multiple message of a socket place it in
 * this struct */
struct client_ctx { };

#include "userspace/log.h"
#include "userspace/sock_app.h"
#include "userspace/sock_app_udp.h"
#include "userspace/util.h"

#include <sys/socket.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <linux/if.h>
#include <sys/ioctl.h>

/* NOTE: enable ``USING_TIMESTAMP_FRAME_PATCH'' when you want to use the
 * timestamp added in the driver. It requires kernel patch/modification.
 * */
#define USING_TIMESTAMP_FRAME_PATCH 1
#define RECV_BUFSIZE 2048

#define RECV(fd, buf, size, flag)  {                  \
	ret = recv(fd, buf, size, flag);              \
	if (ret == 0)                                 \
		return 1;                             \
	if (ret < 0) {                                \
		if (errno != EWOULDBLOCK) {           \
			/* all message was received and connection is closed */ \
			return 1;                     \
		}                                     \
		return 0;                             \
	}                                             \
}


/* NOTE: these values are duplicated/shared with the BPF program. Every change
 * should also applied there.
 * */
#define XDP_OFF 0
#define TC_OFF  1
#define STREAM_VERDICT_OFF 2
#define COUNT_HOOKS 3
struct payload {
	unsigned long long timestamps[COUNT_HOOKS];
} __attribute__((packed));
/* ------------------------------------------------------------------------ */

typedef struct {
	uint64_t time_to_xdp;
	uint64_t time_to_tc;
	uint64_t time_to_stream_verdict;
	uint64_t time_to_app;
	uint64_t time_verdict_to_app;
} sample_t;
#define SAMPLE_SIZE 100000000LL
static sample_t *samples;
static size_t sample_index = 0;

static inline unsigned long int get_realtime_ns(void) {
	struct timespec spec = {};
	clock_gettime(CLOCK_REALTIME, &spec);
	unsigned long int rprt_ts = spec.tv_sec * 1000000000LL + spec.tv_nsec;
	return rprt_ts;
}

#ifdef USING_TIMESTAMP_FRAME_PATCH
/* NOTE:
 * THIS MUST MATCH WITH THE STRUCT DEFINED INSIDE THE KERNEL
 * (include/linux/test_timer.h)
 * */
struct timestamp_frame {
	uint32_t magic;
	uint64_t timestamp;
} __attribute__((packed));
#define TF_MAGIC 0x7591

typedef struct {
	uint64_t duration;
	uint32_t len;
} tsf_sample_t ;

void record_timestamp_frame(void *buf, int len)
{
	if (len < sizeof(struct timestamp_frame)) {
		ERROR("Request is smaller than timestamp_frame!\n");
		return;
	}
	struct timestamp_frame *tf = buf;
	uint64_t duration = get_ns() - tf->timestamp;
	if (tf->magic != TF_MAGIC) {
		ERROR("The timestamp_frame MAGIC does not match!\n");
		return;
	}
	size_t index = sample_index;
	sample_index += 1;
	struct payload *p = buf;
	tsf_sample_t *s = (tsf_sample_t *)&samples[index];
	s->duration = duration;
	s->len = len;
}


void report_timestamp_frame(void *buf, int len)
{
	if (len < sizeof(struct timestamp_frame)) {
		ERROR("Request is smaller than timestamp_frame!\n");
		return;
	}
	struct timestamp_frame *tf = buf;
	uint64_t duration = get_ns() - tf->timestamp;
	if (tf->magic != TF_MAGIC) {
		ERROR("The timestamp_frame MAGIC does not match!\n");
		return;
	}
	INFO("Farbod: It takes %llu to reach UDP socket (len: %d)\n", duration, len);
}
#endif

static inline
void record_sample(void *buf, int len, uint64_t raw_hw_ts)
{
	if (len < sizeof(struct payload)) {
		ERROR("Request is too small\n");
		return;
	}
	size_t index = sample_index;
	sample_index += 1;
	struct payload *p = buf;
	sample_t *s = &samples[index];
	if (raw_hw_ts == 0) {
		uint64_t ts = get_ns();
		/* There is no hardware timestamping */
		/* s->time_to_xdp = 0; */
		/* s->time_to_tc = p->timestamps[TC_OFF] - p->timestamps[XDP_OFF]; */
		/* s->time_to_stream_verdict = p->timestamps[STREAM_VERDICT_OFF] - p->timestamps[XDP_OFF]; */
		/* s->time_to_app = ts - p->timestamps[XDP_OFF]; */
		s->time_verdict_to_app = ts - p->timestamps[STREAM_VERDICT_OFF];
	} else {
		/* Use hardware time stamp */
		uint64_t monotonic_ts = get_ns();
		uint64_t ts = get_realtime_ns();
		int64_t addjustment = ts - monotonic_ts;
		/* BPF timestamps are set using MONOTONIC_CLOCK, convert them
		 * to REALTIME_CLOCK before comparison
		 * */
		s->time_to_xdp = addjustment + p->timestamps[XDP_OFF] - raw_hw_ts;
		s->time_to_tc = addjustment + p->timestamps[TC_OFF] - raw_hw_ts;
		s->time_to_stream_verdict = addjustment + p->timestamps[STREAM_VERDICT_OFF] - raw_hw_ts;
		/* We now the REALTIME_CLOCK in user */
		s->time_to_app = ts - raw_hw_ts;
	}
}

void report_samples(void)
{
	INFO("Number of samples: %d\n", sample_index);
	for (size_t i = 0; i < sample_index; i++) {
#ifdef USING_TIMESTAMP_FRAME_PATCH
		tsf_sample_t *s = (tsf_sample_t *)&samples[i];
		INFO("duration: %ld    len: %d\n", s->duration, s->len);
#else
		sample_t *s = &samples[i];
		/* INFO("xdp: %ld    tc: %ld    stream_verdict: %ld    socket: %ld\n", */
		/* 		s->time_to_xdp, */
		/* 		s->time_to_tc, */
		/* 		s->time_to_stream_verdict, */
		/* 		s->time_to_app); */
		INFO("socket_layer: %ld\n", s->time_verdict_to_app);
#endif
	}
}

static int connect_to_client = 0;
static char *client_ip = NULL;
static short client_port = 3000;

/* Handle a socket message
 * Return value:
 *     0: Keep connection open for more data.
 *     1: Close the conneection.
 * */
int handle_client(int client_fd, struct client_ctx *ctx)
{
	int ret, len;
	char buf[RECV_BUFSIZE];

	/* Receive message and check the return value */
	RECV(client_fd, buf, RECV_BUFSIZE, 0);
	len = ret;
	/* if (len == 0) */
	/* 	return 1; */
	/* buf[len] = 0; */
	/* printf("recv: (%d)\n%s", len, buf); */

	/* Send a reply */
	ret = send(client_fd, buf, len, 0);
	return 0;
}

int handle_client_udp(int client_fd, struct client_ctx *ctx)
{
	int ret, len;
	char buf[RECV_BUFSIZE];

	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);

	/* Receive message and check the return value */
	ret = recvfrom(client_fd, buf, RECV_BUFSIZE, 0 /*udp_flags*/,
			(struct sockaddr *)&client_addr, &addr_len);
	if (ret == 0) {
		ERROR("Receive no data!\n");
		return 1;
	}
	if (ret < 0) {
		if (errno != EWOULDBLOCK) {
			ERROR("Recving failed! %s\n", strerror(errno));
			return 1;
		}
		/* Would block continue polling */
		return 0;
	}
	len = ret;

#ifdef USING_TIMESTAMP_FRAME_PATCH
	record_timestamp_frame(buf, len);
#else
	record_sample(buf, len, 0);
#endif
	/* Send a drop */
	return 0;
}

static uint64_t handle_time(struct msghdr* _msg)
{
	/* Code from: https://eng-blog.iij.ad.jp/archives/21198 */
	struct timespec* ts = NULL;
	struct cmsghdr* cmsg;

	/*
	 * The kernel stores control messages for each packet. E.g., on which
	 * interface the packet was received on. Or, if as we configured it
	 * with the timestamps from the NIC and the kernel.
	 */
	for(cmsg = CMSG_FIRSTHDR(_msg); cmsg; cmsg = CMSG_NXTHDR(_msg,cmsg)) {
		if( cmsg->cmsg_level != SOL_SOCKET )
			continue;
		switch( cmsg->cmsg_type ) {
			case SO_TIMESTAMPING:
				ts = (struct timespec*) CMSG_DATA(cmsg);
				break;
			default:
				break;
		}
	}
	if (ts == NULL) {
		ERROR("The request does not have a timestamp!\n");
		return 0;
	}
	uint64_t hardware_raw = ts[2].tv_nsec + (ts[2].tv_sec * 1000000000L);
	return hardware_raw;
}

int handle_client_udp_with_hw_ts(int client_fd, struct client_ctx *ctx)
{
	/* Code from: https://eng-blog.iij.ad.jp/archives/21198 */
	struct msghdr _msg;
	struct iovec iov;
	struct sockaddr_in host_address;
	char buf[RECV_BUFSIZE];
	char control[1024];
	int ret, len;

	/* recvmsg header structure */
	memset(&host_address, 0, sizeof(host_address));
	iov.iov_base = buf;
	iov.iov_len = RECV_BUFSIZE;
	_msg.msg_iov = &iov;
	_msg.msg_iovlen = 1;
	_msg.msg_name = &host_address;
	_msg.msg_namelen = sizeof(struct sockaddr_in);
	_msg.msg_control = control;
	_msg.msg_controllen = 1024;

	/* block for message */
	ret = recvmsg(client_fd, &_msg, 0);

	if (ret == 0) {
		ERROR("Receive no data!\n");
		return 1;
	}
	if (ret < 0) {
		if (errno != EWOULDBLOCK) {
			ERROR("Recving failed! %s\n", strerror(errno));
			return 1;
		}
		/* Would block continue polling */
		return 0;
	}
	len = ret;
	/* INFO("received (%d)\n", len); */

	uint64_t raw_hw_ts = handle_time(&_msg);
	record_sample(buf, len, raw_hw_ts);
	/* Drop */
	return 0;
}

/* When the socket is ready, register it to the sock-map. This allows sk_skb
 * program to operate on traffic of this socket.
 * */
void register_socket(int fd)
{
	static int first = 0;
	int ret;
	int map_fd;
	int zero = 0;
	char cmd;

	if (!connect_to_client) {
		INFO("NOTE: bpf_sk_map_redirect will not work (change code to connect server socket if you need it)\n");
	} else {
		/* Connect the socket to a target so that I can use bpf_sk_map_redirect
		 * More description:
		 * For UDP sockets, we can not use bpf_sk_map_redirect in the
		 * stream_verdict eBPF program unless the socket is connected.
		 * */
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_port = htons(client_port);
		inet_pton(AF_INET, client_ip, &addr.sin_addr);
		socklen_t addrlen = sizeof(addr);
		ret = connect(fd, (struct sockaddr *)&addr, addrlen);
		if (ret != 0) {
			ERROR("Failed to connect the socket");
			exit(EXIT_FAILURE);
		}
	}

	if (first != 0) {
		ERROR("Multiple sockets, this code expects only one socket update it\n");
		exit(EXIT_FAILURE);
	}
	first = 1;

	map_fd = find_map("sock_map");
	if (map_fd <= 0) {
		ERROR("Did not found the socket map\n");
		goto sock_register_failure;
	}
	ret = bpf_map_update_elem(map_fd, &zero, &fd, BPF_NOEXIST);
	if (ret != 0) {
		ERROR("Failed to insert socket (%d) to the map\n", fd);
		goto sock_register_failure;
	}
	INFO("Inserted the socket (%d) into sock_map\n", fd);
	return;
sock_register_failure:
		INFO("Failed to register socket to sock_map. Should the program terminate? [Y/n] ");
		scanf("%c", &cmd);
		if (cmd == 'n' || cmd == 'N') {
			INFO("Continue...\n");
			return;
		}
		exit(EXIT_FAILURE);
}

/*
 * Enable hardware timestamping for this socket
 * */
void enable_hw_timestamp(int fd)
{
	int ret;
	int enable = SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_SYS_HARDWARE |
		SOF_TIMESTAMPING_SOFTWARE;
	ret = setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &enable,
			sizeof(int));
	if (ret != 0) {
		fprintf(stderr, "Failed to enable hardware timestamping\n");
		exit(EXIT_FAILURE);
	}
}

/* This requires a bit of explanation.
 * Typically, you have to enable hardware timestamping on an interface.
 * Any application can do it, and then it's available to everyone.
 * The easiest way to do this, is just to run sfptpd.
 *
 * But in case you need to do it manually; here is the code, but
 * that's only supported on reasonably recent versions
 *
 * Option: --ioctl ethX
 *
 * NOTE:
 * Usage of the ioctl call is discouraged. A better method, if using
 * hardware timestamping, would be to use sfptpd as it will effectively
 * make the ioctl call for you.
 *
 */
static void enable_hwts_on_iface(int sock) {
#ifdef SIOCSHWTSTAMP
	struct ifreq ifr;
	struct hwtstamp_config hwc;
#endif

#ifdef SIOCSHWTSTAMP
	bzero(&ifr, sizeof(ifr));
	printf("intreface name: ");
	char ifname[128];
	char x[32];
	scanf("%s", ifname);
	getc(stdin);
	printf("iface name is %s\n", ifname);
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

	/* Standard kernel ioctl options */
	hwc.flags = 0;
	hwc.tx_type = 0;
	hwc.rx_filter = HWTSTAMP_FILTER_ALL;

	ifr.ifr_data = (char *)&hwc;

	int ret;
	ret = ioctl(sock, SIOCSHWTSTAMP, &ifr);
	if (ret != 0) {
		ERROR("ioctl operation failed: trying to enable hardware timestamping on the interface!\n");
	}
	return;
#else
	(void)sock;
	printf("SIOCHWTSTAMP ioctl not supported on this kernel.\n");
	exit(-ENOTSUP);
	return;
#endif
}

static int hw_timestamp = 0;
static int sock_map_register = 0;

static int udp = 1;
void on_socket_ready(int fd) {
	if (hw_timestamp) {
		enable_hwts_on_iface(fd);
		enable_hw_timestamp(fd);
	}
	if (sock_map_register) {
		/* TODO: have a flag to check if we need to add the socket to
		 * sock_map or not */
		/* When we need to insert socket to the sock_map manually */
		register_socket(fd);
	}
}

int main(int argc, char *argv[])
{
	int ret;
	struct socket_app app = {};

	samples = calloc(SAMPLE_SIZE, sizeof(sample_t));

	/* parse args */
	if (argc < 5) {
		INFO("usage: prog <core> <ip> <port> <mode>\n"
		"  * mode: 0: UDP    1: TCP\n");
		INFO("NOTE: some parameters are hard-coded. E.g, (if HW Timestamping is used or not)\n");
		return 1;
	}

	if (atoi(argv[4]) == 1) {
		udp = 0;
		INFO("Running server in TCP mode.\n");
		ERROR("NOT IMPLEMENTED!\n");
		exit(EXIT_FAILURE);
	} else {
		INFO("Running server in UDP mode.\n");
	}


	for (int i=5; i < argc; i++) {
		if (strcmp("--connect-client", argv[i]) == 0) {
			connect_to_client = 1;
			client_ip = strdup(argv[i + 1]);
			i++;
		} else if (strcmp("--connect-client-port", argv[i]) == 0) {
			client_port = atoi(argv[i + 1]);
			i++;
		}
	}

	app.core_listener = 0;
	app.core_worker = atoi(argv[1]);
	app.ip = argv[2];
	app.port = atoi(argv[3]);
	app.count_workers = 1;
	if (udp) {
		hw_timestamp = 0;
		sock_map_register = 1;
		if (hw_timestamp) {
			app.sock_handler = handle_client_udp_with_hw_ts;
		} else {
			app.sock_handler = handle_client_udp;
		}
	} else {
		app.sock_handler = handle_client;
	}
	app.on_sockready = on_socket_ready;
	app.on_sockclose = NULL;
	app.on_events = NULL;

	if (hw_timestamp) {
		INFO("\nIn HW Timestamp mode\n");
		INFO("MUST BE RUNNING THE phc2sys");
		INFO("    sudo phc2sys -s <eth> -O 0 -m\n");
		INFO("More info:  https://eng-blog.iij.ad.jp/archives/21198\n\n");
	}
	if (sock_map_register)
		INFO("NOTE: will try to add the socket to sock_map\n");

	if (!udp) {
		ret = run_server(&app);
	} else {
		ret = run_udp_server(&app);
	}
	report_samples();
	if (ret != 0) {
		ERROR("Failed to run server!\n");
		return 1;
	}

	return 0;
}
