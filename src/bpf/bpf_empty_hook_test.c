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
#define REPEAT 100000


#define VALUE_SIZE 64
typedef struct {
	char data[VALUE_SIZE];
} __attribute__((packed)) value_t;
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	/* __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); */
	__type(key,  __u32);
	__type(value, value_t);
	__uint(max_entries, 1);
	/* __uint(map_flags, BPF_F_MMAPABLE); */
} a_map SEC(".maps");

/* #define CHECK_EMPTY_HOOK 1 */
#ifdef CHECK_EMPTY_HOOK
/*
 * This is a custom helper functions added just for this test. The patch should
 * be available kernel directory.
 * */
#ifndef bpf_ret_zero
static int (*bpf_ret_zero)() = (void *) 212;
#endif
#endif

struct loop_context {
	void *context;
};

static long do_experiment_xdp(__u32 i, void *_ctx)
{
#ifdef CHECK_EMPTY_HOOK
	bpf_ret_zero();
#else
	int zero = 0;
	value_t *v = bpf_map_lookup_elem(&a_map, &zero);
	if (v == NULL) return 1;
	v->data[0] = 'f';

	/* struct xdp_md *ctx = ((struct loop_context *)_ctx)->context; */
	/* bpf_xdp_adjust_tail(ctx, 1000); */
	/* bpf_xdp_adjust_tail(ctx, -1000); */
#endif
	return 0;
}

static long do_experiment_tc(__u32 i, void *_ctx)
{
	struct __sk_buff *ctx = ((struct loop_context *)_ctx)->context;
	bpf_skb_adjust_room(ctx, 1000, BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_NO_CSUM_RESET);
	bpf_skb_adjust_room(ctx, -1000, BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_NO_CSUM_RESET);
	return 0;
}

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

	/* bpf_printk("Started an experiment:"); */
	__u64 begin, duration;
	begin = bpf_ktime_get_ns();
	struct loop_context llctx = {
		.context = (void *)skb,
	};
	bpf_loop(REPEAT, do_experiment_tc, &llctx, 0);
	duration = bpf_ktime_get_ns() - begin;
	bpf_printk("Helper function avg exec time: %ld", duration / REPEAT);
	return TC_ACT_SHOT;
}

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

	/* bpf_printk("Started an experiment:"); */
	__u64 begin, duration;
	begin = bpf_ktime_get_ns();
	struct loop_context llctx = {
		.context = (void *)ctx,
	};
	bpf_loop(REPEAT, do_experiment_xdp, &llctx, 0);
	duration = bpf_ktime_get_ns() - begin;
	bpf_printk("Helper function avg exec time: %ld", duration / REPEAT);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
