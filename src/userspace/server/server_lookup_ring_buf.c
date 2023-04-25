#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#include <sched.h>
#include <pthread.h>

#include <bpf/libbpf.h>
/* use c-hashmap library */
#include <c-hashmap/map.h>

#include "userspace/log.h"
#include "userspace/util.h"

#define MAX_CONN 1024
#define BUFSIZE 2048

static hashmap *tcp_connection_table;
static struct ring_buffer *rbuf;

/* Internal structure */
struct server_conf {
	char *ip;
	short port;
	int core;
};

struct worker_arg {
	pthread_t thread;
	int core;
};
/* -------------- */

/* NOTE: this struct is duplicated in the XDP program */
struct source_addr {
	unsigned int source_ip;
	unsigned short source_port;
} __attribute__((__packed__));
struct req_data {
	unsigned int hash;
	struct source_addr src_addr;
} __attribute__((__packed__));

struct package {
	unsigned int count;
	struct req_data data[5];
} __attribute__((__packed__));

/* Some helpers */
static int set_core_affinity(int core)
{
	cpu_set_t cpuset;
	pthread_t current_thread;

	current_thread = pthread_self();
	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);
	return pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
}

static int set_sock_opts(int fd)
{
	int ret;
	int opt_val;
	opt_val = 1;

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt_val, sizeof(opt_val));
	if (ret)
		return ret;

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val));
	if (ret)
		return ret;

	ret = setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt_val, sizeof(opt_val));
	if (ret)
		return ret;

	return 0;
}

static int set_client_sock_opt(int fd)
{
	int ret;
	int opt_val = 1;

	/* ret = ioctl(fd, FIONBIO, (char *)&opt_val); */
	ret = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (ret)
		return ret;

	ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt_val, sizeof(opt_val));
	if (ret)
		return ret;
	return 0;
}

static inline int prepare_type2_response(char *buf,
		unsigned int *message_length)
{
	int ret;
	int file_fd = open("./file.txt", O_RDONLY);
	if (file_fd < 0) {
		ERROR("Failed to open the file!\n");
		return 1;
	}
	/* Assume read the file in one chunk */
	ret = read(file_fd, buf, BUFSIZE);
	close(file_fd);
	if (ret == BUFSIZE) {
		ERROR("Warning: File is probably larger than buffer!\n");
		ret--;
	}
	buf[ret] = '\0';
	/* Prepare the response (END is need for notifying end of response) */
	strcpy(buf + 8, "Done,END\r\n");
	*message_length = sizeof("Done,END\r\n") - 1 + 8;
	return 0;
}

/*
 * Add the incomming connections to the connection table
 * TODO: I should remove them from connection table when the socket is closed.
 * */
void add_sock_to_table(int sockfd)
{
	struct sockaddr_in _addr;
	socklen_t _addrlen;
	struct source_addr *addr = malloc(sizeof(struct source_addr));

	_addrlen = sizeof(_addr);
	if (getpeername(sockfd, (struct sockaddr *)&_addr, &_addrlen) != 0) {
		ERROR("Failed to get socket peer address\n");
		return;
	}

	/* I expect the address to be in network byte order */
	addr-> source_ip = _addr.sin_addr.s_addr;
	addr->source_port = _addr.sin_port;

	/* NOTE: The keys should not be freed while hashmap is using them! */
	hashmap_set(tcp_connection_table, addr, sizeof(*addr), sockfd);
	/* INFO("Add connection: %x:%d\n", ntohl(addr->source_ip), ntohs(addr->source_port)); */
}

static inline int _tcp_multishot(struct package *pkg, char *buf)
{
	int i, ret;
	unsigned int message_length;
	long long int real_client_fd;
	/* INFO("Receive a package: count: %d\n", pkg.count); */
	int sent = 0;
	for (i = 0; i < pkg->count; i++) {
		/* Hash value */
		/* hash = pkg.data[i].hash; */

		/* Send a reply */
		ret = prepare_type2_response(buf, &message_length);
		if (ret != 0) {
			ERROR("Failed to prepare a response!\n");
			return 1;
		}
		/* Lookup the socket */
		if (!hashmap_get(tcp_connection_table,
					(void *)&pkg->data[i].src_addr,
					sizeof(struct source_addr),
					(uintptr_t *)&real_client_fd)) {
			/* Failed to find the connection */
			ERROR("Connection not found %x:%d\n",
					ntohl(pkg->data[i].src_addr.source_ip),
					ntohs(pkg->data[i].src_addr.source_port));
			continue;
			/* I should not terminate this connection because it is
			 * not the real connection ! */
			/* return 1; */
		}


		if (send(real_client_fd, buf, message_length, 0) < 0) {
			ERROR("Failed to send: %s\n", strerror(errno));
		} else {
			sent++;
			/* INFO("SEND\n"); */
		}
	}
	return 0;
}

static int tcp_multishot_ring_buffer(void *ctx, void *data, size_t size)
{
	char buf[BUFSIZE];

	/* assert size == sizeof(struct package) */
	_tcp_multishot((struct package *)data, buf);
	return 0;
}

static int configure_ring_buffer()
{
	int map_fd;

	rbuf = ring_buffer__new(map_fd, tcp_multishot_ring_buffer, NULL, NULL);
	if (rbuf == NULL)
		return 1;
	return 0;
}

static void *worker_entry(void *_arg)
{
	struct worker_arg *arg = _arg;
	return NULL;
}

static int start_server(struct server_conf *conf)
{
	int ret;
	int sk_fd;
	int client_fd;
	struct sockaddr_in sk_addr;
	struct sockaddr_in peer_addr;
	socklen_t peer_addr_size = sizeof(peer_addr);

	/* Prepare server listening socket */
	sk_addr.sin_family = AF_INET;
	inet_pton(AF_INET, conf->ip, &(sk_addr.sin_addr));
	sk_addr.sin_port = htons(conf->port);

	sk_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sk_fd < 0) {
		ERROR("Failed to create a socket\n");
		return 1;
	}

	set_sock_opts(sk_fd);

	ret = bind(sk_fd, (struct sockaddr *)&sk_addr, sizeof(sk_addr));
	if (ret != 0) {
		ERROR("Failed to bind the socket\n");
		return 1;
	}

	ret = listen(sk_fd, MAX_CONN);
	if (ret != 0) {
		ERROR("Failed to start listening\n");
		return 1;
	}
	INFO("Listening %s:%d\n", conf->ip, conf->port);

	add_sock_to_table(sk_fd);
	while (1) {
		/* The listening server socket is blocking */
		client_fd = accept(sk_fd, (struct sockaddr *)&peer_addr, &peer_addr_size);
		if (client_fd < 0) {
			ERROR("Error: accepting new connection\n");
			return 1;
		}
		set_client_sock_opt(client_fd);

		add_sock_to_table(client_fd);
	}

	return 0;
}

struct worker_arg *launch_worker(int core)
{
	int ret;
	int fd;
	struct worker_arg *arg = malloc(sizeof(struct worker_arg));
	if (!arg)
		return NULL;

	arg->core = core;
	ret = pthread_create(&arg->thread, NULL, worker_entry, arg);
	if (ret) {
		free(arg);
		return NULL;
	}
	return arg;
}

int main(int argc, char *argv[])
{
	int ret;
	const int core_listener = 0;

	int worker_core = 1;
	struct server_conf conf = {
		.ip = "127.0.0.1",
		.port = 8080,
		.core = core_listener
	};

	if (set_core_affinity(core_listener)) {
		ERROR("Failed to set CPU core affinity!\n");
		return 1;
	}
	INFO("Listener running on core %d\n", core_listener);

	/* Prepare connection table */
	tcp_connection_table = hashmap_create();
	/* Prepare the ring buffer channel */
	if (configure_ring_buffer()) {
		ERROR("Failed to configure the ring buffer\n");
		return 1;
	}

	/* Start a worker thread */
	launch_worker(worker_core);

	return start_server(&conf);
}
