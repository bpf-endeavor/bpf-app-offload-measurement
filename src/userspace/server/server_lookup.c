#define _GNU_SOURCE

/* #define NO_SUMMARY */

enum {
	FULL_USERSPACE = 0,
	BPF_OFFLOAD = 1,
} mode;

/* If a value should be shared across multiple message of a socket place it in
 * this struct */
struct client_ctx {
	int old;
	int req_type;
	unsigned int remaining_req_length;
	unsigned int hash;
};

struct request {
	int req_type;
	unsigned int payload_length;
} __attribute__((__packed__));

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

#define ASCII_LETTER(val) ((val % 26) + 'a')

/* Handle a socket message
 * Return value:
 *     0: Keep connection open for more data.
 *     1: Close the conneection.
 * */
int handle_client_full(int client_fd, struct client_ctx *ctx)
{
	int ret, len;
	unsigned int hash;
	char buf[BUFSIZE];
	unsigned char *message;
	unsigned int message_length;

	/* Receive message and check the return value */
	RECV(client_fd, buf, BUFSIZE, 0);
	len = ret;

	if (ctx->old) {
		/* Load the previousely calculated value */
		hash = ctx->hash;
		message = (unsigned char *)buf;
		message_length = len;
	} else {
		/* Initialize the value, read 4 bytes of message */
		struct request *req = (struct request *)buf;
		ctx->old = 1;
		ctx->req_type = req->req_type;
		ctx->remaining_req_length = req->payload_length;
		hash = FNV_OFFSET_BASIS_32;
		message = (unsigned char *)(req + 1);
		message_length = len - sizeof(struct request);

		/* INFO("New request: type: %d size: %d\n", ctx->req_type, ctx->remaining_req_length); */
	}

	fnv_hash(message, message_length, &hash);

	ctx->hash = hash;
	ctx->remaining_req_length -= message_length;
	/* INFO("received: %s (remaining: %d)\n", message, ctx->remaining_req_length); */
	/* INFO("received: (remaining: %d)\n", ctx->remaining_req_length); */


	if (ctx->remaining_req_length > 0) {
		/* The request is not received completely yet */
		return 0; /* Returning zero means keep connection open for more
			     data */
	} else if (ctx->remaining_req_length < 0) {
		ERROR("Unexpected request length !!\n");
		return 1;
	}

	/* Request has been received completely */
	/* INFO("END OF REQUEST\n"); */
	ctx->old = 0;
	/* INFO("hash: %d\n", hash); */

	/* TODO: implement this part */
	if (ctx->req_type == 1) {
		/* Prepare the response (END is need for notifying end of response) */
		strcpy(buf, "Done,END\r\n");
		message_length = sizeof("Done,END\r\n") - 1;
	} else if (ctx->req_type == 2) {
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
		}
		buf[ret] = '\0';
		/* Prepare the response (END is need for notifying end of response) */
		strcpy(buf + 8, "Done,END\r\n");
		message_length = sizeof("Done,END\r\n") - 1 + 8;
	} else {
		ERROR("Unknown request type!!\n");
		return 1;
	}

	/* Send a reply */
	ret = send(client_fd, buf, message_length, 0);

	return 0;
}

int handle_client_bpf(int client_fd, struct client_ctx *ctx)
{
	int ret, len;
	unsigned int hash;
	char buf[BUFSIZE];
	unsigned int message_length;

	/* Receive message and check the return value */
	RECV(client_fd, buf, BUFSIZE, 0);
	len = ret;

#ifdef NO_SUMMARY
	if (ctx->old) {
		/* Load the previousely calculated value */
		message_length = len;
	} else {
		/* Initialize the value, read 4 bytes of message */
		struct request *req = (struct request *)buf;
		ctx->old = 1;
		ctx->remaining_req_length = req->payload_length;
		message_length = len - sizeof(struct request);

		/* INFO("New request: type: %d size: %d\n", ctx->req_type, ctx->remaining_req_length); */
	}

	ctx->remaining_req_length -= message_length;
	/* INFO("received: %s (remaining: %d)\n", message, ctx->remaining_req_length); */
	/* INFO("received: (remaining: %d)\n", ctx->remaining_req_length); */


	if (ctx->remaining_req_length > 0) {
		/* The request is not received completely yet */
		return 0; /* Returning zero means keep connection open for more
			     data */
	} else if (ctx->remaining_req_length < 0) {
		ERROR("Unexpected request length !!\n");
		return 1;
	}
	ctx->old = 0;
#endif


	hash = *(unsigned int *)buf;
	/* INFO("hash: %d\n", hash); */

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
	}
	buf[ret] = '\0';
	/* Prepare the response (END is need for notifying end of response) */
	strcpy(buf + 8, "Done,END\r\n");
	message_length = sizeof("Done,END\r\n") - 1 + 8;

	/* Send a reply */
	ret = send(client_fd, buf, message_length, 0);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;
	struct socket_app app;

	/* parse args */
	if (argc < 4) {
		INFO("usage: prog <core> <ip> <mode>\n"
		"* mode: either 0 or 1.\n"
		"  0: full userspace - 1: recieve hash from ebpf\n");

		return 1;
	}
	app.core_listener = 0;
	app.core_worker = atoi(argv[1]);
	app.port = 8080;
	app.ip = argv[2];
	app.count_workers = 1;

	mode = atoi(argv[3]);

	if (mode == FULL_USERSPACE) {
		app.sock_handler = handle_client_full;
	} else {
		app.sock_handler = handle_client_bpf;
	}

	ret = run_server(&app);
	if (ret != 0) {
		ERROR("Failed to run server!\n");
		return 1;
	}

	return 0;
}
