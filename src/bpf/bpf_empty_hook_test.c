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

/*
 * This is a custom helper functions added just for this test. The patch should
 * be available kernel directory.
 * */
#ifndef bpf_ret_zero
static int (*bpf_ret_zero)() = (void *) 212;
#endif

struct loop_context {
	void *context;
};

static long do_experiment(__u32 i, void *_ctx)
{
	/* bpf_ret_zero(); */

	struct xdp_md *ctx = ((struct loop_context *)_ctx)->context;
	bpf_xdp_adjust_tail(ctx, 1000);
	bpf_xdp_adjust_tail(ctx, -1000);
	return 0;
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

	bpf_printk("Started an experiment:");
	__u64 begin, duration;
	begin = bpf_ktime_get_ns();
	struct loop_context llctx = {
		.context = (void *)ctx,
	};
	bpf_loop(REPEAT, do_experiment, &llctx, 0);
	duration = bpf_ktime_get_ns() - begin;
	bpf_printk("Empty hook avg exec time: %ld", duration / REPEAT);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
