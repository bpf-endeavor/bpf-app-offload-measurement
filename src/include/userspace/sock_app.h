/*
 * Boiler plate for creating socket applications
 * @author Farbod Shahinfar
 * @date Feb 2023
 * */
#ifndef _SOCK_APP_H
#define _SOCK_APP_H

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <arpa/inet.h>
#include <linux/in.h>
#include <netinet/tcp.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>

#include <sched.h>
#include <pthread.h>

#include "userspace/log.h"

#define MAX_CONN 1024
#define BUFSIZE 2048

#define ADD_SOCKET_TO_POLL_LIST(sd, list, index) {        \
		list[index].fd = sd;                              \
		list[index].events = POLLIN;                      \
		index++;                                          \
}

#define TERMINATE(i, list) {                          \
	close(list[i].fd);                                \
	list[i].fd = -1;                                  \
	list[i].events = 0;                               \
	compress_array = 1;                               \
	cctx[i] = (struct client_ctx) {};                 \
}

struct client_ctx;
typedef int (*sock_handler_fn)(int fd, struct client_ctx *ctx);

/* Define a socket application
 * */
struct socket_app {
	unsigned int core_listener;
	unsigned int core_worker;
	unsigned short port;
	char *ip;
	unsigned short count_workers;
	sock_handler_fn sock_handler;

	void (* on_sockready)(int fd);
};

/* Argument of a worker thread. The sockets are passed to each worker through
 * the list of file descriptors.
 * */
struct worker_arg {
	int core;
	struct pollfd *list;
	int count_conn;
	pthread_spinlock_t lock;
	pthread_t thread;
	sock_handler_fn sock_handler;
};

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

static void *worker_entry(void *_arg)
{
	int ret, i, j;
	struct worker_arg *arg = _arg;
	int compress_array = 0;
	int num_event;
	int num_conn = arg->count_conn;
	struct client_ctx cctx[MAX_CONN + 1] = {};
	long long int u;
	set_core_affinity(arg->core);
	INFO("Worker started (pid = %d) (core = %d)\n", getpid(), arg->core);
	while (1) {
		num_event = poll(arg->list, num_conn, -1);
		if (num_event < 0) {
			ERROR("Polling failed! (%s)\n", strerror(errno));
			pthread_exit((void *)1);
		}

		for (i = 0; i < num_conn; i++) {
			if(arg->list[i].revents == 0) {
				continue;
			}

			if (i == 0) {
				/* This is a wake up call from the master */
				read(arg->list[0].fd, &u, sizeof(u));
				continue;
			}

			if (arg->list[i].revents & POLLHUP ||
				arg->list[i].revents & POLLERR ||
				arg->list[i].revents & POLLNVAL) {
					TERMINATE(i, arg->list);
					continue;
			}

			/* Data ready, handle the socket data */
			ret = arg->sock_handler(arg->list[i].fd, &cctx[i]);
			if (ret == 1) {
				TERMINATE(i, arg->list);
			}
		}

		/* update number of connections */
		pthread_spin_lock(&arg->lock);
		num_conn = arg->count_conn;
		if (compress_array)
		{
			compress_array = 0;
			for (i = 0; i < num_conn; i++)
			{
				if (arg->list[i].fd == -1)
				{
					for(j = i; j < num_conn; j++)
					{
						arg->list[j].fd = arg->list[j+1].fd;
						arg->list[j].events = arg->list[j+1].events;
					}
					i--;
					num_conn--;
				}
			}
			/* This function only reduce the size */
			arg->count_conn = num_conn;
		}
		pthread_spin_unlock(&arg->lock);
	}
	return NULL;
}

struct worker_arg *launch_workers(sock_handler_fn handler,
		unsigned int core_worker)
{
	int ret;
	int fd;
	struct worker_arg *arg = malloc(sizeof(struct worker_arg));
	if (!arg)
		return NULL;
	arg->list = (struct pollfd *)calloc(MAX_CONN + 1, sizeof(struct pollfd));

	fd = eventfd(0, 0);
	if (fd < 0) {
		free(arg);
		return NULL;
	}
	arg->list[0].fd = fd;
	arg->list[0].events = POLLIN;
	arg->count_conn = 1;
	arg->sock_handler = handler;
	arg->core = core_worker;

	pthread_spin_init(&arg->lock, PTHREAD_PROCESS_PRIVATE);

	ret = pthread_create(&arg->thread, NULL, worker_entry, arg);
	if (ret) {
		free(arg);
		return NULL;
	}
	return arg;
}

int run_server(struct socket_app *app)
{
	int ret;
	int sk_fd;
	int client_fd;
	struct sockaddr_in sk_addr;
	struct sockaddr_in peer_addr;
	socklen_t peer_addr_size = sizeof(peer_addr);
	struct worker_arg *worker_context;
	long long int u = 1;

	if (set_core_affinity(app->core_listener)) {
		ERROR("Failed to set CPU core affinity!\n");
		return 1;
	}
	INFO("Listener running on core %d\n", app->core_listener);

	/* Prepare server listening socket */
	sk_addr.sin_family = AF_INET;
	inet_pton(AF_INET, app->ip, &(sk_addr.sin_addr));
	sk_addr.sin_port = htons(app->port);

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

	/* TODO: may lunch multiple workers */
	if (app->count_workers != 1) {
		ERROR("Multy worker servers have not been implemented yet!\n");
		return 1;
	}

	/* Start a worker thread */
	worker_context = launch_workers(app->sock_handler, app->core_worker);
	if (!worker_context) {
		ERROR("Failed to launch a worker\n");
		return 1;
	}

	ret = listen(sk_fd, MAX_CONN);
	if (ret != 0) {
		ERROR("Failed to start listening\n");
		return 1;
	}
	INFO("Listening %s:%d\n", app->ip, app->port);

	while (1) {
		/* The listening server socket is blocking */
		client_fd = accept(sk_fd, (struct sockaddr *)&peer_addr, &peer_addr_size);
		if (client_fd < 0) {
			ERROR("Error: accepting new connection\n");
			return 1;
		}
		set_client_sock_opt(client_fd);

		/* Add the socket to the worker list of connections */
		pthread_spin_lock(&worker_context->lock);
		ADD_SOCKET_TO_POLL_LIST(client_fd, worker_context->list, worker_context->count_conn);
		pthread_spin_unlock(&worker_context->lock);

		/* Wake up the worker */
		write(worker_context->list[0].fd, &u, sizeof(u));

		/* DEBUG("[%f] new connection %d -> %d\n", get_time(), client_fd, worker_context->count_conn - 1); */
	}
}
#endif
