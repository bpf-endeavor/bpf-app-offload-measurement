#define _GNU_SOURCE
struct client_ctx { };

#include "userspace/log.h"
#include "userspace/sock_app.h"
#include "userspace/util.h"

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



#define MAXIMUM 100000000
unsigned long long int current_ts;
size_t ts_index;
unsigned long long int parser_ts[MAXIMUM];
unsigned long long int verdict_ts[MAXIMUM];

struct timestamp {
	__u64 parser_ts;
	__u64 verdict_ts;
} __attribute__((__packed__));


/*
 * Update the current timestamp when we receive some events (requests)
 * This is to avoid reading the clock for each request in cases we have
 * received a batch of requests.
 * */
void measure_time(void) {
	struct timespec tp = {};
	clock_gettime(CLOCK_MONOTONIC, &tp);
	current_ts = tp.tv_nsec + (tp.tv_sec * 1000000000L);
}


/* Handle a socket message
 * Return value:
 *     0: Keep connection open for more data.
 *     1: Close the conneection.
 * */
int handle_client(int client_fd, struct client_ctx *ctx)
{
	int ret, len;
	char buf[BUFSIZE];
	struct timestamp *ts;
	RECV(client_fd, buf, BUFSIZE, 0);
	len = ret;

	ts = (void *)&buf;
	parser_ts[ts_index] = current_ts - ts->parser_ts;
	verdict_ts[ts_index] = current_ts - ts->verdict_ts;
	ts_index++;

	/* Prepare the response (END is need for notifying end of response) */
	strcpy(buf, "Done,END\r\n\0");
	/* Send a reply */
	ret = send(client_fd, buf, sizeof("Done,END\r\n"), 0);

	return 0;
}


int main(int argc, char *argv[])
{
	int ret;
	struct socket_app app = {};

	/* parse args */
	if (argc < 3) {
		INFO("usage: prog <core> <ip>\n");
		return 1;
	}
	app.core_listener = 0;
	app.core_worker = atoi(argv[1]);
	app.port = 8080;
	app.ip = argv[2];
	app.count_workers = 1;
	app.sock_handler = handle_client;
	app.on_sockready = NULL;
	app.on_sockclose = NULL;
	app.on_events = measure_time;

	ret = run_server(&app);
	if (ret != 0) {
		ERROR("Failed to run server!\n");
		return 1;
	}

	/* Report the results */
	INFO("Some measurements\n");
	INFO("parser->userspace,verdict->userspace\n");
	for (size_t i = 0; i < ts_index; i++) {
		INFO("%ld,%ld\n", parser_ts[i], verdict_ts[i]);
	}
	INFO("------------------\n");
	return 0;
}
