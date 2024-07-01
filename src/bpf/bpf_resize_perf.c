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

#define SERVER_PORT 3030
#define INCREASE 128
#define TIMESTAMP_FRAME_SZIE 12

/* SK_SKB Test ------------------------------------------------------------- */

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
#if (INCREASE == 0)
	return SK_PASS;
#else
	if (bpf_skb_adjust_room(skb, INCREASE, 0, 0) != 0) {
		bpf_printk("Failed to resize the packet!");
		return SK_DROP;
	}
	__u8 *new_head = (__u8 *)(__u64)skb->data;
	__u8 *data_end = (__u8 *)(__u64)skb->data_end;
	__u8 *head     = new_head + INCREASE;
	if ((head + TIMESTAMP_FRAME_SZIE > data_end)) {
		bpf_printk("Unexpected memory address ?!");
		return SK_DROP;
	}
	__builtin_memmove(new_head, head, TIMESTAMP_FRAME_SZIE);
	return SK_PASS;
#endif
}

/* XDP Test ---------------------------------------------------------------- */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	/* Make sure we are dropping only the traffic related to the our server
	 * */
	void *data, *data_end;
	data = (void *)(__u64)ctx->data;
	data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	if (udp + 1 > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return XDP_PASS;

	return XDP_DROP;
	/* int delta = RESIZE_TO - ((__u64)data_end - (__u64)data); */
	/* if (!bpf_xdp_adjust_tail(ctx, -delta)) { */
	/* 	bpf_printk("Failed to resize"); */
	/* 	return XDP_DROP; */
	/* } */
	/* __prepare_headers_before_pass(ctx); */
	/* return XDP_PASS; */
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
	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return TC_ACT_OK;
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
