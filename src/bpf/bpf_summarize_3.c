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

/* 0 */
/* #define SUMMARY_RESULT_BYTES 1457 */
/* 10 */
/* #define SUMMARY_RESULT_BYTES 1312 */
/* 20 */
/* #define SUMMARY_RESULT_BYTES 1166 */
/* 30 */
/* #define SUMMARY_RESULT_BYTES 1020 */
/* 40 */
/* #define SUMMARY_RESULT_BYTES 874 */
/* 50 */
/* #define SUMMARY_RESULT_BYTES 729 */
/* 60 */
/* #define SUMMARY_RESULT_BYTES 583 */
/* 70 */
/* #define SUMMARY_RESULT_BYTES 437 */
/* 80 */
/* #define SUMMARY_RESULT_BYTES 291 */
/* 90 */
/* #define SUMMARY_RESULT_BYTES 145 */
/* 99.5 */
/* #define SUMMARY_RESULT_BYTES 8 */

 /* Command for updating the map
  * I=~/auto_kern_offload_bench/scripts/int2hex.py; sudo bpftool map update name size_map key $(echo 0 | $I) value $(echo 12 | $I); sudo bpftool map dump name size_map
  * */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key,  __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} size_map SEC(".maps");

/* SK_SKB Test ------------------------------------------------------------- */

/* Put state of each socket in this struct (This will be used in sockops.h as
 * part of per socket metadata)
 * */
/* struct connection_state { }; */
/* #include "my_bpf/sockops.h" */
/* SEC("sk_skb/stream_parser") */
/* int parser(struct __sk_buff *skb) */
/* { */
/* 	return skb->len; */
/* } */

/* SEC("sk_skb/stream_verdict") */
/* int verdict(struct __sk_buff *skb) */
/* { */
/* 	/1* We are hooked to our server socket so we are procesing the correct */
/* 	 * traffic */
/* 	 * *1/ */
/* 	int ret; */
/* 	char *p = (char *)(__u64)skb->data; */
/* 	void *data_end = (void *)(__u64)skb->data_end; */
/* 	short z_index = skb->len - 2; */
/* 	z_index &= 0x1fff; */
/* 	__u16 length = (__u64)skb->data_end - (__u64)skb->data; */
/* 	if (skb->len != length) { */
/* 		bpf_printk("what is this??? skb.len:%d != delta:%d", skb->len, length); */
/* 	} */
/* 	if (z_index < 0 || z_index >= skb->len || ((void *)p + z_index + 1) > data_end) { */
/* 		bpf_printk("This should never happen! (len: %d index: %d)", skb->len, z_index); */
/* 		return SK_DROP; */
/* 	} */
/* 	if (p[z_index] != 'Z') { */
/* 		bpf_printk("have not received the full message!! Is message in multiple packets? len=%d @ %d", skb->len, z_index); */
/* 		return SK_DROP; */
/* 	} */
/* 	ret = __adjust_skb_size(skb, SUMMARY_RESULT_BYTES); */
/* 	if (ret != 0) { */
/* 		bpf_printk("failed to resize the request!"); */
/* 		return SK_DROP; */
/* 	} */
/* 	return SK_PASS; */
/* } */

/* XDP Test ---------------------------------------------------------------- */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr  *ip;
	struct udphdr *udp;

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

	int ret;
	/* char *p = data; */
	__u16 len = (__u64)ctx->data_end - (__u64)ctx->data;
	/* short z_index = len - 2; */
	/* /1* z_index &= 0x1fff; *1/ */
	/* if (z_index < 0 || z_index >= len || ((void *)p + z_index + 1) > data_end) { */
	/* 	bpf_printk("This should never happen! (len: %d index: %d)", len, z_index); */
	/* 	return XDP_ABORTED; */
	/* } */
	/* if (p[z_index] != 'Z') { */
	/* 	bpf_printk("have not received the full message!! Is message in multiple packets? len=%d @ %d", len, z_index); */
	/* 	return XDP_ABORTED; */
	/* } */

	const int z = 0;
	int *target_sz = bpf_map_lookup_elem(&size_map, &z);
	if (target_sz == NULL)
		return XDP_ABORTED;

	/* short delta = HEADER_SIZE + SUMMARY_RESULT_BYTES - len; */
	const short delta = HEADER_SIZE + (*target_sz) - len;
	/* bpf_printk("delta: %d", delta); */
	ret = bpf_xdp_adjust_tail(ctx, delta);
	if (ret != 0) {
		bpf_printk("failed to resize the request!");
		return XDP_ABORTED;
	}
	__prepare_headers_before_pass(ctx);

	return XDP_PASS;
}

/* TC Test ----------------------------------------------------------------- */
/* SEC("tc") */
/* int tc_prog(struct __sk_buff *skb) */
/* { */
/* 	/1* Make sure we are processing only the traffic related to the our server */
/* 	 * *1/ */
/* 	void *data, *data_end; */
/* 	data = (void *)(__u64)skb->data; */
/* 	data_end = (void *)(__u64)skb->data_end; */
/* 	struct ethhdr *eth = data; */
/* 	struct iphdr  *ip = (void *)(eth + 1); */
/* 	struct udphdr *udp = (void *)(ip + 1); */
/* 	if (udp + 1 > data_end) */
/* 		return TC_ACT_OK; */
/* 	if (eth->h_proto != bpf_htons(ETH_P_IP)) */
/* 		return TC_ACT_OK; */
/* 	if (ip->protocol != IPPROTO_TCP) */
/* 		return TC_ACT_OK; */
/* 	if (udp->dest != bpf_htons(SERVER_PORT)) */
/* 		return TC_ACT_OK; */

/* 	int ret; */
/* 	char *p = data; */
/* 	short z_index = skb->len - 2; */
/* 	z_index &= 0x1fff; */
/* 	__u16 length = (__u64)skb->data_end - (__u64)skb->data; */
/* 	if (skb->len != length) { */
/* 		bpf_printk("what is this??? skb.len:%d != delta:%d", skb->len, length); */
/* 	} */
/* 	if (z_index < 0 || z_index >= skb->len || ((void *)p + z_index + 1) > data_end) { */
/* 		bpf_printk("This should never happen! (len: %d index: %d)", skb->len, z_index); */
/* 		return TC_ACT_SHOT; */
/* 	} */
/* 	if (p[z_index] != 'Z') { */
/* 		bpf_printk("have not received the full message!! Is message in multiple packets? len=%d @ %d", skb->len, z_index); */
/* 		return TC_ACT_SHOT; */
/* 	} */
/* 	ret = __adjust_skb_size(skb, SUMMARY_RESULT_BYTES); */
/* 	if (ret != 0) { */
/* 		bpf_printk("failed to resize the request!"); */
/* 		return TC_ACT_SHOT; */
/* 	} */
/* 	return TC_ACT_OK; */
/* } */

char _license[] SEC("license") = "GPL";
