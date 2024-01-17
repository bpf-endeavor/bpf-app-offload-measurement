#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SERVER_IP   "0.0.0.0"
#define SERVER_PORT 8080

#define READ_BUFFER_SIZE 2048
#define WRITE_BUFFER_SIZE 2048

/* Annotation are only defined when generating BPF code. In order to compile
 * the code normally, I declare them here.
 * */
#ifndef __ANNOTATE_LOOP
#define __ANNOTATE_SKIP
#define __ANNOTATE_EXCLUDE_BEGIN
#define __ANNOTATE_EXCLUDE_END
#define __ANNOTATE_IGNORE_INST
#define __ANNOTATE_LOOP(x)
#define __ANNOTATE_BEGIN_CACHE(x,y,u,w)
#define __ANNOTATE_END_CACHE(x, y)
#define __ANNOTATE_BEGIN_UPDATE_CACHE(x,y,u,w,z)
#define __ANNOTATE_END_UPDATE_CACHE(x, y)
#define __ANNOTATE_DEFINE_CACHE(x,y,u,w,z,t,i)
#else
/* If there is something that needs to be defined only for the BPF program */
#endif

struct context {
	int fd;
	struct sockaddr_in addr;
	socklen_t addr_len;
};

int
main(int argc, char *argv[])
{
	int fd;
	struct sockaddr_in sk_addr;

	sk_addr.sin_family = AF_INET;
	inet_pton(AF_INET, SERVER_IP, &(sk_addr.sin_addr));
	sk_addr.sin_port = htons(SERVER_PORT);

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	bind(fd, (struct sockaddr *)&sk_addr, sizeof(sk_addr));
	while (1) {
		struct context c;
		char rbuf[READ_BUFFER_SIZE];

		/* NOTE: Add this ignore region so the compiler do not generate
		 * map lookup for shared value of fd */
		__ANNOTATE_EXCLUDE_BEGIN
		c.fd = fd;
		c.addr_len = sizeof(struct sockaddr_in);
		__ANNOTATE_EXCLUDE_END

		recvfrom(c.fd, rbuf, READ_BUFFER_SIZE, 0,
				(struct sockaddr *)&c.addr, &c.addr_len);
		/* if (req_size <= 0) { */
		/* 	fprintf(stderr, "Error while reading the socket\n"); */
		/* 	continue; */
		/* } */
		/* printf("here: %s\n", rbuf); */

		sendto(c.fd, "END\r\n", 5, 0, (struct sockaddr *)&c.addr,
				c.addr_len);

	}
	return 0;
}
