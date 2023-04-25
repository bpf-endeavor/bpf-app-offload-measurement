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

#define ADD_SOCKET_TO_POLL_LIST(sd, list, index) {        \
		list[index].fd = sd;                      \
		list[index].events = POLLIN;              \
		index++;                                  \
}

#define TERMINATE(i, list) {                              \
	close(list[i].fd);                                \
	list[i].fd = -1;                                  \
	list[i].events = 0;                               \
	compress_array = 1;                               \
}

#define MAX_CONN 1024
#define BUFSIZE 2048
#define RING_BUFFER_MAP_NAME "ring_map"

pthread_spinlock_t table_lock;
static hashmap *tcp_connection_table;

/* Internal structure */
struct worker_arg {
	int running;
	pthread_t thread;
	struct pollfd *list;
	int count_conn;
	pthread_spinlock_t lock;
	int core;
	struct ring_buffer *rbuf;
};

struct server_conf {
	char *ip;
	short port;
	int core;
	struct worker_arg **workers;
};
/* -------------- */

/* NOTE: this struct is duplicated in the XDP program */
#define BATCH_SIZE 5
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
	struct req_data data[BATCH_SIZE];
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

	/* strcpy(buf, "Done,END\r\n"); */
	/* *message_length = sizeof("Done,END\r\n") - 1; */
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
	struct source_addr *addr = calloc(1, sizeof(struct source_addr));

	_addrlen = sizeof(_addr);
	if (getpeername(sockfd, (struct sockaddr *)&_addr, &_addrlen) != 0) {
		WARN("Failed to get socket peer address\n");
		return;
	}

	/* I expect the address to be in network byte order */
	addr->source_ip = _addr.sin_addr.s_addr;
	addr->source_port = _addr.sin_port;

	pthread_spin_lock(&table_lock);
	/* NOTE: The keys should not be freed while hashmap is using them! */
	hashmap_set(tcp_connection_table, addr, sizeof(struct source_addr), sockfd);
	pthread_spin_unlock(&table_lock);
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
		pthread_spin_lock(&table_lock);
		ret = hashmap_get(tcp_connection_table,
				(void *)&pkg->data[i].src_addr,
				sizeof(struct source_addr),
				(uintptr_t *)&real_client_fd);
		pthread_spin_unlock(&table_lock);
		if (!ret) {
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
	struct package *pkg = data;

	/* assert size == sizeof(struct package) */
	/* assert pkg->count <= BATCH_SIZE */
	/* INFO("recv package: size = %d\n", pkg->count); */

	_tcp_multishot(pkg, buf);
	return 0;
}

static struct ring_buffer *configure_ring_buffer()
{
	int map_fd;
	map_fd = find_map(RING_BUFFER_MAP_NAME);
	if (map_fd < 1)
		return NULL;
	return ring_buffer__new(map_fd, tcp_multishot_ring_buffer, NULL, NULL);
}

static void *worker_entry(void *_arg)
{
	int i, j;
	int num_event, count_conn;
	int compress_array;
	struct worker_arg *arg = _arg;

	if (set_core_affinity(arg->core)) {
		ERROR("Failed to set CPU core affinity!\n");
		return (void *)-1;
	}
	INFO("Worker running on core %d\n", arg->core);

	char buf[1024];
	int ret;
	compress_array = 0;
	while (arg->running) {
		ring_buffer__poll(arg->rbuf, 1000);
		/* Check if there is any socket to close. does not block */
		count_conn = arg->count_conn;
		num_event = poll(arg->list, count_conn, 0);
		if (num_event > 0) {
			for (i = 0; i < count_conn; i++) {
				if (arg->list[i].revents & POLLHUP ||
					arg->list[i].revents & POLLERR ||
					arg->list[i].revents & POLLNVAL) {
						TERMINATE(i, arg->list);
						continue;
				}
				if(arg->list[i].revents & POLLIN) {
					ret = recv(arg->list[i].fd, buf, 1023, 0);
					if (ret == 0) {
						TERMINATE(i, arg->list);
					} else if (ret < 0) {
						if (ret != EWOULDBLOCK)
							TERMINATE(i, arg->list);
					}
				}
			}

			/* update number of connections */
			pthread_spin_lock(&arg->lock);
			count_conn = arg->count_conn;
			if (compress_array)
			{
				compress_array = 0;
				for (i = 0; i < count_conn; i++)
				{
					if (arg->list[i].fd == -1)
					{
						for(j = i; j < count_conn; j++)
						{
							arg->list[j].fd = arg->list[j+1].fd;
							arg->list[j].events = arg->list[j+1].events;
						}
						i--;
						count_conn--;
					}
				}
				/* This function only reduce the size */
				arg->count_conn = count_conn;
			}
			pthread_spin_unlock(&arg->lock);
		}
	}
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
			ERROR("Error: accepting new connection (%s)\n", strerror(errno));
			return 1;
		}
		set_client_sock_opt(client_fd);

		pthread_spin_lock(&conf->workers[0]->lock);
		ADD_SOCKET_TO_POLL_LIST(client_fd, conf->workers[0]->list, conf->workers[0]->count_conn);
		pthread_spin_unlock(&conf->workers[0]->lock);

		add_sock_to_table(client_fd);
	}

	return 0;
}

struct worker_arg *launch_worker(int core)
{
	int ret;
	struct worker_arg *arg = malloc(sizeof(struct worker_arg));
	if (!arg)
		return NULL;

	arg->core = core;
	arg->running = 1;
	arg->rbuf = configure_ring_buffer();
	arg->list = (struct pollfd *)calloc(MAX_CONN + 1, sizeof(struct pollfd));
	pthread_spin_init(&arg->lock, PTHREAD_PROCESS_PRIVATE);
	arg->count_conn = 0;
	/* Prepare the ring buffer channel */
	if (arg->rbuf == NULL) {
		ERROR("Failed to configure the ring buffer\n");
		return NULL;
	}

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
	struct worker_arg *worker;
	const int core_listener = 0;
	const int count_workers = 1;

	int worker_core = 7;
	struct server_conf conf = {
		.ip = "192.168.1.1",
		.port = 8080,
		.core = core_listener,
		.workers = calloc(count_workers, sizeof(struct worker_arg *)),
	};

	if (set_core_affinity(core_listener)) {
		ERROR("Failed to set CPU core affinity!\n");
		return 1;
	}
	INFO("Listener running on core %d\n", core_listener);

	/* Prepare connection table */
	tcp_connection_table = hashmap_create();
	pthread_spin_init(&table_lock, PTHREAD_PROCESS_PRIVATE);

	/* Start a worker thread */
	worker = launch_worker(worker_core);
	if (worker == NULL) {
		return 1;
	}
	conf.workers[0] = worker;

	ret = start_server(&conf);

	pthread_spin_destroy(&table_lock);
	return ret;
}
