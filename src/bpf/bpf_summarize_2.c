#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

#include "my_bpf/commons.h"

#define SERVER_PORT 8080
#define HEADER_SIZE (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
#define MAX_BUF_SIZE 5128
#define SUMMARY_RESULT_BYTES 8
#define MAX_NUM_CONN 6

struct stream_buf {
	__u16 head;
	__u8 buffer[MAX_BUF_SIZE];
} __attribute__((packed));

typedef struct stream_buf stream_buf_t;

struct two_tuple {
	__u16 src_port;
	__u32 src_ip;
} __attribute__((packed));

typedef struct two_tuple flow_id_t;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key,   __u32);
	__type(value, stream_buf_t);
	__uint(max_entries, MAX_NUM_CONN);
} stream_buf_map SEC(".maps");

/* Map flow to connection index */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, flow_id_t);
	__type(value, __u32);
	__uint(max_entries, MAX_NUM_CONN);
} flow_index_map SEC(".maps");

/* How many flows we have observed */
static __u32 flow_counter = 0;


/* SK_SKB Test ------------------------------------------------------------- */

/* Put state of each socket in this struct (This will be used in sockops.h as
 * part of per socket metadata)
 * */
struct connection_state { };
#include "my_bpf/sockops.h"
/* SEC("sk_skb/stream_parser") */
/* int parser(struct __sk_buff *skb) */
/* { */
/* 	return skb->len; */
/* } */

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
	/* We are hooked to our server socket so we are dropping the correct
	 * traffic
	 * */
	return SK_DROP;
}

/* XDP Test ---------------------------------------------------------------- */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	int ret;
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr  *ip;
	struct udphdr *udp;
	__u8 *ptr;
	__u16 len, i, tmp_index;
	short delta;

	data = (void *)(__u64)ctx->data;
	data_end = (void *)(__u64)ctx->data_end;
	eth = data;
	ip = (void *)(eth + 1);
	udp = (void *)(ip + 1);
	/* Make sure the packet is for our server */
	if (udp + 1 > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return XDP_PASS;
	/* Find the flow index */
	flow_id_t fid = {
		.src_port = udp->source,
		.src_ip = ip->saddr,
	};
	__u32 flow_index = 0;
	__u32 *tmp = bpf_map_lookup_elem(&flow_index_map, &fid);
	if (tmp == NULL) {
		if (flow_counter >= MAX_NUM_CONN) {
			bpf_printk("Maximum number of connections have reached");
			return XDP_ABORTED;
		}
		flow_index = flow_counter;
		flow_counter += 1;
		ret = bpf_map_update_elem(&flow_index_map, &fid, &flow_index,
				BPF_NOEXIST);
		if (ret != 0) {
			bpf_printk("Failed to update flow_index_map");
		}
	} else {
		flow_index = *tmp;
	}
	/* Fetch the stream buffer for the flow */
	stream_buf_t *buf = bpf_map_lookup_elem(&stream_buf_map, &flow_index);
	if (buf == NULL) {
		/* Must never happen */
		return XDP_ABORTED;
	}
	/* Copy the payload of the packet to the stream buffer */
	ptr = (__u8 *)(udp + 1);
	len = ((__u64)data_end) - ((__u64)data) - HEADER_SIZE;
	if (len < 1) {
		/* Packet with empty payload */
		return XDP_DROP;
	}
	if ((len + buf->head) > MAX_BUF_SIZE) {
		bpf_printk("Stream buffer overflow");
		return XDP_ABORTED;
	}
	for (i = 0; i < MAX_BUF_SIZE && i < len; i++) {
		tmp_index = buf->head + i;
		tmp_index &= 0x7fff;
		if ((void *)(ptr + i + 1) > data_end) {
			bpf_printk("index out of packet's range (copy from packet) @index=%d [len: %d]", i, len);
			return XDP_ABORTED;
		}
		if (tmp_index >= MAX_BUF_SIZE) {
			return XDP_ABORTED;
		}
		buf->buffer[tmp_index] = ptr[i];
	}
	buf->head += len;
	/* Check if more data is needed. Request ends with "Z\n" */
	if (buf->head < 2) {
		/* Wait for more data */
		return XDP_DROP;
	}
	tmp_index = buf->head - 2;
	tmp_index &= 0x7fff;
	if (tmp_index + 1 >= MAX_BUF_SIZE) {
		return XDP_ABORTED;
	}
	if (buf->buffer[tmp_index] != 'Z' || buf->buffer[tmp_index + 1] != '\n') {
		/* wait for more data */
		/* bpf_printk("a: %c b: %c", buf->buffer[tmp_index], buf->buffer[tmp_index + 1]); */
		return XDP_DROP;
	}
	/* bpf_printk("End of request found"); */
	/* Resize the packet to accomodate the summary */
	delta = SUMMARY_RESULT_BYTES - len;
	ret = bpf_xdp_adjust_tail(ctx, delta);
	if (ret < 0) {
		bpf_printk("Failed to resize the packet (delta=%d)", delta);
		return XDP_ABORTED;
	}
	data = (void *)(__u64)ctx->data;
	data_end = (void *)(__u64)ctx->data_end;
	eth = data;
	ip = (void *)(eth + 1);
	udp = (void *)(ip + 1);
	ptr = (__u8 *)(udp + 1);
	/* Copy stream buffer to the packet */
	for (i = 0; i < SUMMARY_RESULT_BYTES; i++) {
		if ((void *)(ptr + i + 1) > data_end) {
			bpf_printk("index out of packet's range (copy to packet) @index=%d", i);
			return XDP_ABORTED;
		}
		ptr[i] = buf->buffer[i];
	}
	/* Clear the stream_buffer */
	buf->head = 0;
	/* Update checksums */
	ret = __prepare_headers_before_pass(ctx);
	if (ret != 0) {
		bpf_printk("Failed to update the headers");
		return XDP_ABORTED;
	}
	/* bpf_printk("send to user-space: %s", ptr); */
	return XDP_PASS;
}

/* TC Test ----------------------------------------------------------------- */
SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
	/* Make sure we are dropping only the traffic related to the our server
	 * */
	void *data, *data_end;
	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	if (udp + 1 > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	if (ip->protocol != IPPROTO_TCP)
		return TC_ACT_OK;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return TC_ACT_OK;
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";

