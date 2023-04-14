#define _GNU_SOURCE

/* #define NO_SUMMARY */

/* If a value should be shared across multiple message of a socket place it in
 * this struct */
struct client_ctx {
	int old;
	int req_type;
	unsigned int remaining_req_length;
	unsigned int hash;
};
/* ---------------------- */

#include "userspace/log.h"
#include "userspace/sock_app.h"
#include "userspace/sock_app_udp.h"
#include "userspace/util.h"

#define SOCKMAP_NAME "sock_map"

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

enum {
	FULL_USERSPACE = 0,
	BPF_OFFLOAD = 1,
	FULL_USERSPACE_UDP = 2,
	BPF_MULTI_SHOT_UDP = 3,
} mode;

struct request {
	int req_type;
	unsigned int payload_length;
} __attribute__((__packed__));

/* For multi-shot support */
/* NOTE: this struct is duplicated in the XDP program */
struct req_data {
	unsigned int hash;
	unsigned int source_ip;
	unsigned short source_port;
} __attribute__((__packed__));

struct package {
	unsigned int count;
	struct req_data data[5];
} __attribute__((__packed__));

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

#define WAIT_FOR_MORE_DATE 101
#define SEND_REPLY 200
#define UNEXPECTED 500
static inline int full_request_handle(struct client_ctx *ctx, char *buf,
		unsigned int len, unsigned int *response_size)
{
	unsigned char *message;
	unsigned int message_length;
	unsigned int hash;

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
	/* message[message_length] = '\0'; */
	/* INFO("received: %s (remaining: %d)\n", message, ctx->remaining_req_length); */
	/* INFO("received: (remaining: %d)\n", ctx->remaining_req_length); */


	if (ctx->remaining_req_length > 0) {
		/* The request is not received completely yet */
		return WAIT_FOR_MORE_DATE;
	} else if (ctx->remaining_req_length < 0) {
		ERROR("Unexpected request length !!\n");
		return UNEXPECTED;
	}

	/* Request has been received completely */
	/* INFO("END OF REQUEST\n"); */
	ctx->old = 0;
	/* INFO("hash: %d\n", hash); */

	/* TODO: implement this part */
	if (ctx->req_type == 1) {
		/* Prepare the response (END is need for notifying end of response) */
		strcpy(buf, "Done,END\r\n");
		*response_size = sizeof("Done,END\r\n") - 1;
	} else if (ctx->req_type == 2) {
		if (prepare_type2_response(buf, response_size) != 0)
			return UNEXPECTED;
	} else {
		ERROR("Unknown request type!!\n");
		return UNEXPECTED;
	}
	return SEND_REPLY;
}

/* Handle a socket message
 * Return value:
 *     0: Keep connection open for more data.
 *     1: Close the conneection.
 * */
int handle_client_full(int client_fd, struct client_ctx *ctx)
{
	int ret, len;
	char buf[BUFSIZE];
	unsigned int message_length;

	/* Receive message and check the return value */
	RECV(client_fd, buf, BUFSIZE, 0);
	len = ret;

	switch (full_request_handle(ctx, buf, len, &message_length)) {
		case UNEXPECTED:
			return 1;
			break;
		case WAIT_FOR_MORE_DATE:
			return 0;
			break;
		case SEND_REPLY:
			/* Send a reply */
			ret = send(client_fd, buf, message_length, 0);
			return 0;
			break;
		default:
			ERROR("Unexpected return value from full_request_handle!\n");
			return 1;
			break;
	}

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
	/* INFO("HERE\n"); */

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

	/* Send a reply */
	ret = prepare_type2_response(buf, &message_length);
	if (ret != 0)
		return 1;
	ret = send(client_fd, buf, message_length, 0);
	/* INFO("SEND\n"); */
	return 0;
}

int handle_client_udp(int client_fd, struct client_ctx *ctx)
{
	int ret, len;
	char buf[BUFSIZE];
	unsigned int message_length;

	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);

	/* Receive message and check the return value */
	ret = recvfrom(client_fd, buf, BUFSIZE, 0 /*udp_flags*/,
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

	/* buf[len] = '\0'; */
	/* INFO("received data! (len: %d) %s\n", len, buf); */

	switch (full_request_handle(ctx, buf, len, &message_length)) {
		case UNEXPECTED:
			ERROR("Handling request failed!\n");
			return 1;
			break;
		case WAIT_FOR_MORE_DATE:
			/* INFO("Wait\n"); */
			return 0;
			break;
		case SEND_REPLY:
			/* INFO("Reply\n"); */
			/* Send a reply */
			ret = sendto(client_fd, buf, message_length, 0 /*flags*/,
					(struct sockaddr *)&client_addr, addr_len);
			if (ret < 0) {
				ERROR("Failed to send the message\n");
			}
			return 0;
			break;
		default:
			ERROR("Unexpected return value from full_request_handle!\n");
			return 1;
			break;
	}

	return 0;
}

int handle_client_bpf_multishot(int client_fd, struct client_ctx *ctx)
{
	int ret, len;
	char buf[BUFSIZE];
	unsigned int message_length;

	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);

	struct package pkg;
	int i;

	/* Receive message and check the return value */
	ret = recvfrom(client_fd, buf, BUFSIZE, 0 /*udp_flags*/,
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

	/* buf[ret] = '\0'; */
	/* INFO("recv! len = %d %s\n", len, buf); */

	pkg = *(struct package *)buf;
	/* INFO("Receive a package: count: %d\n", pkg.count); */

	for (i = 0; i < pkg.count; i++) {
		/* Send a reply */
		ret = prepare_type2_response(buf, &message_length);
		if (ret != 0) {
			ERROR("Failed to prepare a response!\n");
			return 1;
		}
		client_addr.sin_family = AF_INET;
		client_addr.sin_addr.s_addr = pkg.data[i].source_ip;
		client_addr.sin_port = pkg.data[i].source_port;
		addr_len = sizeof(struct sockaddr_in);
		/* INFO("ip: %x port: %d\n", ntohl(client_addr.sin_addr.s_addr), ntohs(client_addr.sin_port)); */
		if (sendto(client_fd, buf, message_length, 0 /*flags*/,
				(struct sockaddr *)&client_addr, addr_len) < 0) {
			ERROR("Failed to send: %s\n", strerror(errno));
		} else {
			/* INFO("SEND\n"); */
		}
	}

	return 0;
}

void insert_to_sockmap(int sockfd)
{
	int ret;
	int map_fd = find_map(SOCKMAP_NAME);

	if (map_fd < 1) {
		ERROR("Failed to find the SOCKMAP\n");
		return;
	}

	DEBUG("map_fd: %d sockfd: %d\n", map_fd, sockfd);
	ret = 0;
	ret = bpf_map_update_elem(map_fd, &ret, &sockfd, BPF_NOEXIST);
	if (ret) {
		ERROR("Failed to insert to sockmap %s\n", strerror(errno));
		return;
	}
	INFO("Successfully insert socket fd to SOCKMAP\n");
}

int main(int argc, char *argv[])
{
	int ret;
	struct socket_app app = {};

	/* parse args */
	if (argc < 4) {
		INFO("usage: prog <core> <ip> <mode>\n"
		"* mode: either 0 or 1.\n"
		"  0: full userspace\n"
		"  1: recieve hash from ebpf\n"
		"  2: full userspace (UDP)\n"
		"  3: bpf multi-shot (UDP)\n"
		);

		return 1;
	}
	app.core_listener = 0;
	app.core_worker = atoi(argv[1]);
	app.port = 8080;
	app.ip = argv[2];
	app.count_workers = 1;
	app.on_sockready = NULL;

	mode = atoi(argv[3]);

	int udp = 0;
	switch (mode) {
		case FULL_USERSPACE:
			INFO("Mode: statndalone (TCP)\n");
			app.sock_handler = handle_client_full;
			break;
		case BPF_OFFLOAD:
			INFO("Mode: bpf + userspace (TCP)\n");
			app.sock_handler = handle_client_bpf;
			break;
		case FULL_USERSPACE_UDP:
			INFO("Mode: standalone (UDP)\n");
			udp = 1;
			app.sock_handler = handle_client_udp;
			break;
		case BPF_MULTI_SHOT_UDP:
			INFO("Mode: bpf + batching (UDP)\n");
			udp = 1;
			app.sock_handler = handle_client_bpf_multishot;
			break;
		default:
			ERROR("Unexpected value for application mode!\n");
			return 1;
	}

	if (argc > 4 && !strcmp(argv[4], "--sockmap")) {
		INFO("Trying to insert socket fd into sockmap\n");
		app.on_sockready = insert_to_sockmap;
	}

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
