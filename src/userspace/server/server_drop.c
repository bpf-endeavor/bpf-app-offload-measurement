#define _GNU_SOURCE

#include <stdlib.h>
#include <stdint.h>

/* If a value should be shared across multiple message of a socket place it in
 * this struct */
struct client_ctx { };

#include "userspace/log.h"
#include "userspace/sock_app.h"
#include "userspace/sock_app_udp.h"
#include "userspace/util.h"

#define RECV_BUFFER_SIZE 2048

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

static uint64_t counter = 0;
static uint64_t last_report = 0;
static inline void report_tput(void) {
	uint64_t ts, delta;
	/* We must run on a single core */
	counter += 1;
	ts = get_ns(); /* from util.h */
	if (last_report == 0) {
		last_report = ts;
		return;
	}

	delta = ts - last_report;
	if (delta >= 1000000000L) {
		printf("throughput: %ld (pps)\n", counter);
		counter = 0;
		last_report = ts;
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
	char buf[RECV_BUFFER_SIZE];

	/* Receive message and check the return value */
	RECV(client_fd, buf, RECV_BUFFER_SIZE, 0);
	len = ret;
	/* if (len == 0) */
	/* 	return 1; */
	/* buf[len] = 0; */
	/* printf("recv: (%d)\n%s", len, buf); */

	report_tput();
	/* Drop */
	return 0;
}

int handle_client_udp(int client_fd, struct client_ctx *ctx)
{
	int ret, len;
	char buf[RECV_BUFFER_SIZE];

	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);

	/* Receive message and check the return value */
	ret = recvfrom(client_fd, buf, RECV_BUFFER_SIZE, 0 /*udp_flags*/,
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
	report_tput();
	/* Drop */
	return 0;
}

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

