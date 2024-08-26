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

#define SERVER_PORT_1 8080
#define SERVER_PORT_2 11211

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 4);
} map_progs_demux SEC(".maps");

SEC("xdp")
int xdp_demux(struct xdp_md *ctx)
{
	void *data, *data_end;
	data = (void *)(__u64)ctx->data;
	data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);

	if ((void *)(udp + 1) > data_end) {
		/* Packet is too small */
		return XDP_PASS;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	__u16 port = bpf_ntohs(udp->dest);
	switch (port) {
		case SERVER_PORT_1:
			bpf_tail_call(ctx, &map_progs_demux, 0);
			break;
		case SERVER_PORT_2:
			bpf_tail_call(ctx, &map_progs_demux, 1);
			break;
		default:
			return XDP_PASS;
	}
	return XDP_PASS;
}
