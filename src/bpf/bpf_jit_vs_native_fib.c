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

# define __nobuiltin(X) __attribute__((no_builtin(X)))
#define UPPER_BOUND_ON_LIMIT_REQ 10000

char _license[] SEC("license") = "GPL";

#define SERVER_PORT 8080

static __u64 counter = 0;
static __u64 last_report = 0;

static inline __attribute__((always_inline))
void report_tput(void)
{
	__u64 ts, delta;
	/* We must run on a single core */
	counter += 1;
	ts = bpf_ktime_get_coarse_ns();
	if (last_report == 0) {
		last_report = ts;
		return;
	}

	delta = ts - last_report;
	if (delta >= 1000000000L) {
		bpf_printk("throughput: %ld (pps)", counter);
		counter = 0;
		last_report = ts;
	}
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	void *data, *data_end;
	data = (void *)(__u64)ctx->data;
	data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	__u32 *limit = (__u32 *)(udp + 1);
	if ((void *)(limit + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return XDP_PASS;
	if (*limit > UPPER_BOUND_ON_LIMIT_REQ)
		return XDP_ABORTED;
	__u64 a = 1, b = 1 , c = 0;
	for (__u32 i = 2; i < *limit; i++) {
		c = a + b;
		a = b;
		b = c;
	}
	if (c == 4)  /* to avoid optimizing the loop */
		bpf_printk("calculated fib %u to be %llu", *limit, c);
	report_tput();
	return XDP_DROP;
}
