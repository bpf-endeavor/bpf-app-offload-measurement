#ifndef _UTIL_H
#define _UTIL_H
#include <sys/time.h>
#include <string.h>
#include <pthread.h>

#define FNV_OFFSET_BASIS_32	2166136261
#define FNV_PRIME_32		16777619

/* Fowler–Noll–Vo hash function
 * */
unsigned int fnv_hash(const unsigned char *message, unsigned short length,
		unsigned int *hash)
{
	unsigned short off;
	*hash = FNV_OFFSET_BASIS_32;
	for (off = 0; off < length; off++) {
		*hash ^= message[off];
		*hash *= FNV_PRIME_32;
	}
	return 0;
}

__attribute__((__unused__))
static size_t roundup_page(size_t sz)
{
	size_t page_size = sysconf(_SC_PAGE_SIZE);
	return ((sz + page_size - 1) / page_size) * page_size;
}

double get_time(void)
{
	int ret;
	struct timeval t;
	ret = gettimeofday(&t, NULL);
	if (ret)
		return 0;
	return (double)t.tv_usec/1000000.0 + (double)t.tv_sec;
}

int send_http_reply(int fd, char *str)
{
	int ret;
	/* For creating response */
	char response_fmt[] = "HTTP/1.1 200 Okay\r\n"
				"Content-Length: %d\r\n"    // content length
				"\r\n"
				"%s\r\n"                    // text
				"\r\n";
	char response[2048];
	int content_length;
	int len;

	/* Generate response */
	content_length = strlen(str);
	content_length += 4;

	/* Format HTTP response */
	len = sprintf(response, response_fmt, content_length, str);
	/* printf("len: %d\n", len); */

	ret = send(fd, response, len, 0);
	/* printf("sent (fd: %d): %d\n", fd, ret); */
	return ret;
}
#endif
