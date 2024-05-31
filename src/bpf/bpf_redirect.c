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

/* TIMESTAMP FRAME MUST REFLECT THE ONE INSIDE THE KERNEL
 * (/include/linux/test_timer.h)
 * */
/* #define TF_MAGIC 0x7591 */
/* #define TF_PORT 3030 */
/* struct timestamp_frame { */
/* 	__u32 magic; */
/* 	__u64 timestamp; */
/* } __attribute__((packed)); */
/* ---------------------------------------------------------------------- */

/* struct { */
/* 	__uint(type, BPF_MAP_TYPE_DEVMAP); */
/* 	__type(key_size, int); */
/* 	__type(value_size, struct bpf_devmap_val); */
/* 	__uint(max_entries, 1); */
/* } devmap SEC(".maps"); */


#include <my_bpf/commons.h>


static inline __attribute__((always_inline))
void swap_src_dst_mac(void *data)
{
	unsigned short *p = data;
	unsigned short dst[3];

	dst[0] = p[0];
	dst[1] = p[1];
	dst[2] = p[2];
	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst[0];
	p[4] = dst[1];
	p[5] = dst[2];
}

static inline __attribute__((always_inline))
void echo(struct ethhdr *eth, struct iphdr *ip, struct udphdr *udp)
{
	__u32 tmp;
	__u64 csum;

	/* Swap MAC addresses */
	swap_src_dst_mac(eth);

	/* Update dest mac */
	/* char tmp_d[] = {0xb8,0xce,0xf6,0xd2,0x12,0xc7}; */
	/* memcpy(&eth->h_dest, tmp_d, sizeof(tmp_d)); */
	/* char tmp_s[] = { 0xe8,0xeb,0xd3,0xa7,0x0c,0xb7 }; */
	/* memcpy(&eth->h_source, tmp_s, sizeof(tmp_s)); */
	/* bpf_printk("here"); */

	tmp = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp;
	ip->ttl = 64;
	ip->check = 0;
	csum = 0;
	ipv4_csum_inline(ip, &csum);
	ip->check = bpf_htons(csum);

	tmp = 0;
	tmp = udp->dest;
	udp->dest = udp->source;
	udp->source = (__u16)tmp;
	udp->check = 0;

}


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
	/* return SK_DROP; */

	/* Pull message data so that we can access it */
	/* if (bpf_skb_pull_data(skb, skb->len) != 0) { */
	/* 	bpf_printk("Parser: Failed to load message data"); */
	/* 	return SK_DROP; */
	/* } */

	int zero  = 0;
	int r = bpf_sk_redirect_map(skb, &sock_map, zero, 0);
	return r;
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
	/* struct timestamp_frame *tf = (void *)(udp+1); */

	if (udp + 1 > data_end) {
		/* Packet is too small */
		return XDP_PASS;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return XDP_PASS;

	echo(eth, ip, udp);

	/* udp->dest = bpf_htons(TF_PORT); */
	/* tf->magic = TF_MAGIC; */
	/* tf->timestamp = bpf_ktime_get_ns(); */
	/* int zero = 0; */
	/* return bpf_redirect_map(&devmap, &zero); */
	/* NOTE: the interface index is hard coded */
	/* ip -json addr show enp1s0 */

	/* int r = bpf_redirect(7, 0); */
	/* if (r != XDP_REDIRECT) { */
	/* 	bpf_printk("failed to redirect"); */
	/* } */
	/* return r; */
	return XDP_TX;
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

	echo(eth, ip, udp);

	/* return TC_ACT_SHOT; */

	/* NOTE: interface index is hard code. Find it using the following
	 * command.
	 *     ip -json addr show  <eth..>
	 * */
	return bpf_redirect(5, 0);
}

char _license[] SEC("license") = "GPL";

