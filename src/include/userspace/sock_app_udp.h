/*
 * Boiler plate for creatign UDP socket apps
 * @author: Farbod Shahinfar
 * @date: April 2023
 * */
#ifndef _SOCK_APP_UDP_H
#define _SOCK_APP_UDP_H

#define _GNU_SOURCE

/* The UDP server relies on the same interface as TCP (sock_app.h) */
#include "userspace/sock_app.h"

static int set_udp_sock_opts(int fd)
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

	ret = fcntl(fd, F_SETFL, O_NONBLOCK);
	if (ret)
		return ret;

	return 0;
}

#define MAX_UDP_SOCKS 15
int run_udp_server(struct socket_app *app)
{

	int ret;
	int sk_fd;
	struct sockaddr_in sk_addr;

	int i;
	int num_event, num_conn;
	struct client_ctx cctx[MAX_UDP_SOCKS + 1] = {};
	struct worker_arg *arg;

	if (set_core_affinity(app->core_worker)) {
		ERROR("Failed to set CPU core affinity!\n");
		return 1;
	}
	INFO("Worker running on core %d\n", app->core_worker);

	/* Prepare server listening socket */
	sk_addr.sin_family = AF_INET;
	inet_pton(AF_INET, app->ip, &(sk_addr.sin_addr));
	sk_addr.sin_port = htons(app->port);

	sk_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_fd < 0) {
		ERROR("Failed to create a socket\n");
		return 1;
	}

	set_udp_sock_opts(sk_fd);

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

	arg = malloc(sizeof(struct worker_arg));
	if (!arg)
		return 1;
	arg->list = (struct pollfd *)calloc(MAX_UDP_SOCKS + 1, sizeof(struct pollfd));
	arg->list[0].fd = sk_fd;
	arg->list[0].events = POLLIN;
	arg->count_conn = 1;
	arg->sock_handler = app->sock_handler;
	arg->core = app->core_worker;
	num_conn = arg->count_conn;

	/* The main logic would be here */
	while (1) {
		num_event = poll(arg->list, num_conn, -1);
		if (num_event < 0) {
			ERROR("Polling failed! (%s)\n", strerror(errno));
			return 1;
		}

		for (i = 0; i < num_conn; i++) {
			if(arg->list[i].revents == 0) {
				continue;
			}

			if (arg->list[i].revents & POLLHUP ||
				arg->list[i].revents & POLLERR ||
				arg->list[i].revents & POLLNVAL) {
					continue;
			}

			/* Data ready, handle the socket data */
			ret = arg->sock_handler(arg->list[i].fd, &cctx[i]);
			if (ret != 0) {
				/* Probably an error happend on the socket */
				ERROR("Handler encountered an error\n");
				return 1;
			}
		}
	}

	return 0;
}
#endif
