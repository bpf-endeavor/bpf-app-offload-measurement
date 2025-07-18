#define _GNU_SOURCE

#include <stdlib.h>

/* If a value should be shared across multiple message of a socket place it in
 * this struct */
struct client_ctx { };

#include "userspace/log.h"
#include "userspace/sock_app.h"
#include "userspace/sock_app_udp.h"
#include "userspace/util.h"

#define RECV_BUFSIZE 4096

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
	/* ret = send(client_fd, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", 41, 0); */
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

	/* Send a reply */
	ret = sendto(client_fd, buf, len, 0 /*flags*/,
			(struct sockaddr *)&client_addr, addr_len);
	return 0;
}

/* void on_sockready(int fd) */
/* { */
/* 	int ret; */
/* 	int bufsize; */
/* 	bufsize = 1 << 20; */
/* 	ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)); */
/* 	if (ret != 0) printf("failed to set sndbuf\n"); */
/* 	/1* Creating a mismatch between Rx and Tx buffer *1/ */
/* 	bufsize = 1 << 10; */
/* 	ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)); */
/* 	if (ret != 0) printf("failed to set rcvbuf\n"); */
/* 	printf("increase socket buffers\n"); */
/* } */

int main(int argc, char *argv[])
{
	int ret;
	int udp = 1;
	struct socket_app app = {};

	/* parse args */
	if (argc < 5) {
		INFO("usage: prog <core> <ip> <port> <mode>\n"
		"  * mode: 0: UDP    1: TCP\n");
		return 1;
	}

	if (atoi(argv[4]) == 1) {
		udp = 0;
		printf("Running server in TCP mode.\n");
	} else {
		printf("Running server in UDP mode.\n");
	}

	app.core_listener = 0;
	app.core_worker = atoi(argv[1]);
	app.ip = argv[2];
	app.port = atoi(argv[3]);
	app.count_workers = 1;
	if (udp) {
		app.sock_handler = handle_client_udp;
	} else {
		app.sock_handler = handle_client;
	}
	/* app.on_sockready = on_sockready; */
	app.on_sockready = NULL;
	app.on_sockclose = NULL;
	app.on_events = NULL;

	if (!udp) {
		ret = run_server(&app);
	} else {
		ret = run_udp_server(&app);
	}
	if (ret != 0) {
		ERROR("Failed to run server!\n");
		return 1;
	}

	return 0;
}
