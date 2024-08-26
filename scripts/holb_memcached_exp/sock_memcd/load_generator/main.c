#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <linux/in.h>
#include <unistd.h>
#include <signal.h>

#define SERVER_IP "192.168.200.101"
#define SERVER_PORT 8080
#define PAYLOAD "hello world\r\n"
#define PAYLOAD_LEN 13
#define MAX_SAMPLES 1000000


static inline unsigned long int get_ns(void) {
	struct timespec spec = {};
	clock_gettime(CLOCK_MONOTONIC, &spec);
	unsigned long int rprt_ts = spec.tv_sec * 1000000000LL + spec.tv_nsec;
	return rprt_ts;
}

static volatile int running = 0;
static size_t sample_index = 0;
static uint64_t samples[MAX_SAMPLES];


void handle_sig(int s)
{
	running = 0;
}

static inline int do_req(int sock)
{
	int ret;
	struct msghdr m;
	struct iovec io[1];
	const int flags = 0;
	uint64_t begin, duration;
	char rx_buf[512];

	io[0].iov_base = PAYLOAD;
	io[0].iov_len = PAYLOAD_LEN;

	m.msg_name = NULL;
	m.msg_namelen = 0;
	m.msg_iov = io;
	m.msg_iovlen = 1;
	m.msg_control = NULL;
	m.msg_controllen = 0;
	m.msg_flags = 0;

	begin = get_ns();
	ret = sendmsg(sock, &m, flags);
	if (ret != PAYLOAD_LEN)  {
		perror("Failed to send message");
		return 1;
	}
	io[0].iov_base = rx_buf;
	io[0].iov_len = 512;
	ret = recvmsg(sock, &m, flags);
	if (ret <= 0) {
		perror("Failed to recv message");
		return 1;
	}
	duration = get_ns() - begin;

	samples[sample_index] = duration;
	sample_index++;
	if (sample_index >= MAX_SAMPLES) {
		printf("Maximum number of samples reached!\n");
		running = 0;
	}
	return 0;
}

void report_samples(void)
{
	char line[256];
	int line_len;
	FILE *f = fopen("samples.txt", "a+");

	printf("num samples: %ld\n", sample_index);
	printf("writing to samples.txt\n");

	line_len = snprintf(line, 256, "num samples: %ld\n", sample_index);
	fwrite(line, line_len, 1, f);

	for (int i = 0; i < sample_index; i++) {
		line_len = snprintf(line, 256, "%ld\n", samples[i]);
		fwrite(line, line_len, 1, f);
	}
	fclose(f);
}

int main(int argc, char **argv)
{
	int ret = 0;
	int s = 0;
	uint64_t begin, duration;
	struct sockaddr_in addr;
	socklen_t addrlen;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 1) {
		printf("Failed to open a socket\n");
		exit(EXIT_FAILURE);
	}

	addr.sin_family = AF_INET;
	inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);
	addr.sin_port = ntohs(SERVER_PORT);
	addrlen = sizeof(addr);
	ret = connect(s, (struct sockaddr *)&addr, addrlen);
	if (ret != 0) {
		printf("Failed to connect to server\n");
		shutdown(s, SHUT_RDWR);
		close(s);
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, handle_sig);
	signal(SIGHUP, handle_sig);
	printf("Hit Ctrl-C to stop ...\n");
	running = 1;
	begin = get_ns();
	while (running) {
		do_req(s);
		usleep(100);
	}
	duration = get_ns() - begin;
	float sec = (float)duration / 1000000000.0f;
	printf("\nran for %f sec\n", sec);
	printf("avg rate: %.2f\n", sample_index / sec);

	report_samples();
	return 0;
}
