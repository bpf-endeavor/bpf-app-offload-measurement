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

static __u64 counter = 0;
static __u64 last_report = 0;

static inline __attribute__((always_inline))
void report_tput(void)
{
	__u64 ts, delta;
	/* We must run on a single core */
	/* counter += 1; */
	__atomic_fetch_add(&counter, 1, __ATOMIC_RELAXED);
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

static inline __u16 csum_fold_helper(__u64 csum)
{
	int i;
#pragma clang loop unroll(full)
	for (i = 0; i < 4; i++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}

static inline
void ipv4_csum_inline(void *iph, __u64 *csum)
{
	__u32 i;
	__u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
	for (i = 0; i < sizeof(struct iphdr) >> 1; i++) {
		*csum += bpf_ntohs(*next_iph_u16);
		next_iph_u16++;
	}
	*csum = csum_fold_helper(*csum);
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	bpf_printk("THIS MUST NOT PRINT (in mlx5 driver mode)");
	void *data, *data_end;
	data = (void *)(__u64)ctx->data;
	data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	__u64 csum;
	__u64 tmp = 0;
	if (udp + 1 > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return XDP_PASS;
	report_tput();
#pragma clang loop unroll(disable)
	for (int  i = 0; i < 256; i++) {
		csum = 0;
		ip->check = 0;
		ipv4_csum_inline(ip, &csum);
		tmp += bpf_htons(csum);
	}
	ip->check = csum;
	if (tmp == 0) {
		bpf_printk("this must not have happend");
		return XDP_ABORTED;
	}
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
