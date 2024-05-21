#define _GNU_SOURCE

#include <stdint.h>
#include <stdlib.h>

/* If a value should be shared across multiple message of a socket place it in
 * this struct */
struct client_ctx { };

#include "userspace/log.h"
#include "userspace/sock_app.h"
#include "userspace/sock_app_udp.h"
#include "userspace/util.h"

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
	uint64_t time_to_tc;
	uint64_t time_to_stream_verdict;
	uint64_t time_to_app;
} sample_t;
#define SAMPLE_SIZE 100000000LL
static sample_t *samples;
static size_t sample_index = 0;

static inline
void record_sample(void *buf, int len)
{
	if (len < sizeof(struct payload)) {
		ERROR("Request is too small\n");
		return;
	}
	uint64_t ts = get_ns();
	size_t index = sample_index;
	sample_index += 1;
	struct payload *p = buf;
	sample_t *s = &samples[index];
	s->time_to_tc = p->timestamps[TC_OFF] - p->timestamps[XDP_OFF];
	s->time_to_stream_verdict = p->timestamps[STREAM_VERDICT_OFF] - p->timestamps[XDP_OFF];
	s->time_to_app = ts - p->timestamps[XDP_OFF];
}

void report_samples(void)
{
	INFO("Number of samples: %d\n", sample_index);
	for (size_t i = 0; i < sample_index; i++) {
		sample_t *s = &samples[i];
		INFO("tc: %ld    stream_verdict: %ld    socket: %ld\n",
				s->time_to_tc,
				s->time_to_stream_verdict,
				s->time_to_app);
	}
}

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
	record_sample(buf, len);
	/* Send a drop */
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

int main(int argc, char *argv[])
{
	int ret;
	int udp = 1;
	struct socket_app app = {};

	samples = calloc(SAMPLE_SIZE, sizeof(sample_t));

	/* parse args */
	if (argc < 5) {
		INFO("usage: prog <core> <ip> <port> <mode>\n"
		"  * mode: 0: UDP    1: TCP\n");
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

	app.core_listener = 0;
	app.core_worker = atoi(argv[1]);
	app.ip = argv[2];
	app.port = atoi(argv[3]);
	app.count_workers = 1;
	if (udp) {
		app.sock_handler = handle_client_udp;
		/* app.on_sockready = register_socket; */
		app.on_sockready = NULL;
	} else {
		app.sock_handler = handle_client;
		app.on_sockready = NULL;
	}
	app.on_sockclose = NULL;
	app.on_events = NULL;

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

