#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Put state of each socket in this struct (This will be used in sockops.h as
 * part of per socket metadata) */
struct connection_state { };

#include "my_bpf/sockops.h"

#define OFFSET_MASK 0x0fff

/* struct arg { */
/* 	int test; */
/* }; */

/* struct { */
/* 	__uint(type,  BPF_MAP_TYPE_ARRAY); */
/* 	/1* __uint(map_flags, BPF_F_MMAPABLE); *1/ */
/* 	__type(key,   __u32); */
/* 	__type(value, struct arg); */
/* 	__uint(max_entries, 1); */
/* } arg_map SEC(".maps"); */

SEC("sk_skb/stream_parser")
int parser(struct __sk_buff *skb)
{

	void *data;
	void *data_end;
	__u16 len;

	/* Pull message data so that we can access it */
	if (bpf_skb_pull_data(skb, skb->len) != 0) {
		bpf_printk("Parser: Failed to load message data\n");
		return 0;
	}

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	len = skb->len;

	char *ptr = data + ((len - 3) & 0x7fff);
	if ((void *)ptr < data || ((void *)ptr + 3 > data_end)) {
		bpf_printk("Parser: Not enough data!");
		return 0;
	}

	if (ptr[0] == 'E' && ptr[1] == 'N' && ptr[2] == 'D') {
		/* Found the end of request */
		return skb->len;
	}
	bpf_printk("@%d\n%s", (long)ptr - (long)data, ptr);

	return 0;
}

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
