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

/*
 * Use `bpftool` to control the number of iterations in the XDP prog:
 *  sudo bpftool map update name map_csum_repeat key 0x00 0x00 0x00 0x00 value 0x01 0x00 0x00 0x00
 *  sudo bpftool map dump name map_csum_repeat
 * */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key,  __u32);
	__type(value, int);
	__uint(max_entries, 1);
} map_csum_repeat SEC(".maps");

static inline __attribute__((always_inline))
void report_tput(void)
{
	__u64 ts, delta;
	/* We must run on a single core */
	/* counter += 1; */
	__sync_fetch_and_add(&counter, 1);
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
	/* bpf_printk("THIS MUST NOT PRINT (in mlx5 driver mode)"); */
	void *data, *data_end;
	data = (void *)(__u64)ctx->data;
	data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	__u64 csum;
	__u64 tmp = 0;
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return XDP_PASS;
	report_tput();

	int z = 0;
	int *v = bpf_map_lookup_elem(&map_csum_repeat, &z);
	if (v == NULL)
		return XDP_ABORTED;
	int _checksum_repeat = *v;

#pragma clang loop unroll(disable)
	for (int  i = 0; i < _checksum_repeat && i < 1024; i++) {
		csum = 0;
		ip->check = 0;
		ipv4_csum_inline(ip, &csum);
		tmp += bpf_htons(csum);
	}
	ip->check = csum;
	if (tmp == 123) {
		bpf_printk("this must not have happend");
		return XDP_ABORTED;
	}
	return XDP_DROP;
}

#define WORKING_PKT_SIZE 64
SEC("xdp")
int xdp_prog_2(struct xdp_md *ctx)
{
	/* bpf_printk("THIS MUST NOT PRINT (in mlx5 driver mode)"); */
	void *data, *data_end;
	data = (void *)(__u64)ctx->data;
	data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	__u64 tmp = 0;

	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return XDP_PASS;
	report_tput();

	int z = 0;
	int *v = bpf_map_lookup_elem(&map_csum_repeat, &z);
	if (v == NULL)
		return XDP_ABORTED;
	int _checksum_repeat = *v;

	__u8 *val = data;
	if ((void *)(val + WORKING_PKT_SIZE) > data_end) {
		bpf_printk("small packet size. expect 256 B packets!");
		return XDP_ABORTED;
	}

/* #pragma clang loop unroll(disable) */
	for (int  i = 0; i < _checksum_repeat && i < 1024; i++) {
		/* Max iteration is 1024 times */
		for (int j = 0; j < WORKING_PKT_SIZE; j++) {
			tmp += val[j];
		}
	}

	if (tmp == 123) {
		bpf_printk("this must not have happend");
		return XDP_ABORTED;
	}

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
