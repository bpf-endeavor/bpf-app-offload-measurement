/* The goal is to measure the time taken to reach to different hooks. The
 * origin of time is when the packet is processed by XDP.
 * */
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

#define SERVER_PORT 8080
#define XDP_OFF 0
#define TC_OFF  1
#define STREAM_VERDICT_OFF 2

#define COUNT_HOOKS 3

struct payload {
	unsigned long long timestamps[COUNT_HOOKS];
} __attribute__((packed));


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
	void *data, *data_end;
	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;
	struct payload *p = data;
	if ((void *)(p + 1) > data_end) {
		bpf_printk("verdict: out of range!");
		return SK_DROP;
	}
	__u64 ts = bpf_ktime_get_ns();
	p->timestamps[STREAM_VERDICT_OFF] = ts;
	return SK_PASS;
}

/* XDP Test ---------------------------------------------------------------- */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
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
	struct payload *p = (void *)(udp + 1);
	if ((void *)(p + 1) > data_end) {
		bpf_printk("xdp: out of range!");
		return XDP_DROP;
	}
	__u64 ts = bpf_ktime_get_ns();
	p->timestamps[XDP_OFF] = ts;
	udp->check = 0;
	return XDP_PASS;
}

/* TC Test ----------------------------------------------------------------- */
SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
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
	struct payload *p = (void *)(udp + 1);
	if ((void *)(p + 1) > data_end) {
		bpf_printk("tc: out of range!");
		return TC_ACT_SHOT;
	}
	__u64 ts = bpf_ktime_get_ns();
	p->timestamps[TC_OFF] = ts;
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
