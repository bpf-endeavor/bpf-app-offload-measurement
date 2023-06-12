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

struct timestamp {
	__u64 parser_ts;
	__u64 verdict_ts;
} __attribute__((__packed__));

#define MEASURE_PARSER_TO_USERSPACE 1
/* #define MEASURE_VERDICT_TO_USERSPACE 1 */


SEC("sk_skb/stream_parser")
int parser(struct __sk_buff *skb)
{
#ifdef MEASURE_PARSER_TO_USERSPACE
	void *data, *data_end;
	struct timestamp *ts;
	__u64 now;

	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;
	ts = data;
	now = bpf_ktime_get_ns();

	if ((void *)(ts + 1) > data_end) {
		bpf_printk("Not enough space for timestamp");
		return skb->len;
	}

	/* put the timestamp on the request */
	ts->parser_ts = now;
#endif
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
#ifdef MEASURE_VERDICT_TO_USERSPACE
	void *data, *data_end;
	struct timestamp *ts;
	__u64 now;

	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;
	ts = data;
	now = bpf_ktime_get_ns();

	if ((void *)(ts + 1) > data_end) {
		bpf_printk("Not enough space for timestamp");
		return SKB_DROP;
	}

	/* put the timestamp on the request */
	ts->verdict_ts = now;
#endif
	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
