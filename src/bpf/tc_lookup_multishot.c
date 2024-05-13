#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <linux/pkt_cls.h>

#include "my_bpf/commons.h"
#include "my_bpf/hash_fn.h"
#include "my_bpf/csum_helpers.h"

#define OFFSET_MASK 0x7fff

#define PORT 8080
/* #define MAX_CONN 10240 */

#define BATCH_SIZE 15

struct reqhdr {
	int req_type;
	unsigned int payload_length;
} __attribute__((__packed__));

/* NOTE: this struct is duplicated in the userspace program */
struct source_addr {
	unsigned int source_ip;
	unsigned short source_port;
} __attribute__((__packed__));
struct req_data {
	unsigned int hash;
	struct source_addr src_addr;
} __attribute__((__packed__));
struct package {
	unsigned int count;
	struct req_data data[15];
} __attribute__((__packed__));
#define need_lock 1
struct protected_area {
	struct package package;
#ifdef need_lock
	struct bpf_spin_lock lock;
#endif
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key,   __u32);
	__type(value, struct protected_area);
	__uint(max_entries, 2);
} batching_map SEC(".maps");
/* ---------------- */

SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
	void *data, *data_end;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct reqhdr *req;

	__u8 *base;
	__u16 len;
	short new_size, packet_size;
	short size_delta;
	struct udphdr *old_udp;
	__u16 tmp_off;

	__u32 hash;
	struct package *pkg;
	const int zero = 0;
	struct package *state;
	__u8 index;
	unsigned long long int cksum;

	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;
	eth = data;
	ip = (struct iphdr *)(eth + 1);

	if ((void *)(ip + 1) > data_end ||
			eth->h_proto != bpf_htons(ETH_P_IP) ||
			ip->protocol != IPPROTO_UDP) {
		return TC_ACT_OK;
	}

	udp = (void *)ip + (ip->ihl * 4);
	if ((void *)(udp + 1) > data_end || udp->dest != bpf_htons(PORT)) {
		return TC_ACT_OK;
	}

	req = (struct reqhdr *)(udp + 1);
	if ((void *)(req + 1) > data_end) {
		return TC_ACT_OK;
	}

	/* bpf_printk("TC"); */
	if (req->req_type == 1) {
		bpf_printk("Currently type 1 request is not supported\n");
		return TC_ACT_SHOT;
	} else if (req->req_type != 2) {
		bpf_printk("Unexpected request type");
		return TC_ACT_SHOT;
	}

	base = (__u8 *)(req + 1);
	len  = (__u64)data_end - (__u64)base;
	/* assert len == req->payload_length */
	hash = FNV_OFFSET_BASIS_32;
	if (fnv_hash_impl2(base, len, data_end, &hash) != 0) {
		bpf_printk("Failed to perform the hashing!");
		return TC_ACT_SHOT;
	}
	struct protected_area *parea = bpf_map_lookup_elem(&batching_map, &zero);
	if (parea == NULL) {
		bpf_printk("Failed to get the proteced area");
		return TC_ACT_SHOT;
	}
#ifdef need_lock
	bpf_spin_lock(&parea->lock);
#endif
	pkg = &parea->package;
	index = pkg->count;
	if (index >= BATCH_SIZE) {
#ifdef need_lock
		bpf_spin_unlock(&parea->lock);
#endif
		bpf_printk("Batch size grow larger than expected!");
		return TC_ACT_SHOT;
	}
	pkg->count++;
	pkg->data[index].hash = hash;
	pkg->data[index].src_addr.source_ip = ip->saddr;
	pkg->data[index].src_addr.source_port = udp->source;

	if (pkg->count != BATCH_SIZE) {
		/* Waiting for more request */
#ifdef need_lock
		bpf_spin_unlock(&parea->lock);
#endif
		/* bpf_printk("waiting!"); */
		return TC_ACT_SHOT;
	}

	/* I just want to place a package as UDP payload.  `` has the curent
	 * length of UDP payload. I use it to calculate the amount of memory
	 * adjustment needed.  */
	packet_size = (__u64)data_end - (__u64)data;
	new_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + \
			sizeof(struct udphdr) + sizeof(struct package);
	size_delta = new_size - packet_size;
	/* bpf_printk("resize delta: %d", size_delta); */
	if (bpf_skb_adjust_room(skb, size_delta, BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_NO_CSUM_RESET) != 0) {
#ifdef need_lock
		bpf_spin_unlock(&parea->lock);
#endif
		bpf_printk("Failed to resize the packet");
		return TC_ACT_SHOT;
	}
	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;
	eth = data;
	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
#ifdef need_lock
		bpf_spin_unlock(&parea->lock);
#endif
		bpf_printk("Failed: IP header out of range!!");
		return TC_ACT_SHOT;
	}

	udp = (void *)ip + (ip->ihl * 4);

	/* if (size_delta > 0 && size_delta < 256) { */
		/* If we have grown the packet, then the space
		 * is added between IP header and UDP header
		 * (notice BPF_ADJ_ROOM_NET). Move UDP up to
		 * fill the gap and create space for data.
		 * */

		/* The if condition is wiered because of the
		 * BPF verifier. I am not sure why I need to
		 * check the upper value of size_delta.
		 * */

		/* tmp_off is unsigned short and is used only
		 * to get pass the BPF verifier
		 * */
		tmp_off = size_delta;
		tmp_off = (tmp_off & OFFSET_MASK);
		old_udp = ((void *)udp) + tmp_off;
		if ((void *)(udp+1) > data_end || (void *)(old_udp + 1) > data_end) {
#ifdef need_lock
			bpf_spin_unlock(&parea->lock);
#endif
			bpf_printk("Accessing out of packet when moving UDP header (size_delta: %d tmp_off: %d)", size_delta, tmp_off);
			return TC_ACT_SHOT;
		}
		memmove(udp, old_udp, sizeof(*old_udp));
	/* } */

	if ((void *)(udp + 1) > data_end) {
#ifdef need_lock
		bpf_spin_unlock(&parea->lock);
#endif
		return TC_ACT_SHOT;
	}
	state = (struct package *)(udp + 1);
	if ((void *)(state + 1) > data_end) {
#ifdef need_lock
		bpf_spin_unlock(&parea->lock);
#endif
		bpf_printk("not enough space for the state");
		return TC_ACT_SHOT;
	}
	memcpy(state, pkg, sizeof(struct package));

	/* Clear the package */
	pkg->count = 0;
#ifdef need_lock
	bpf_spin_unlock(&parea->lock);
#endif

	/* Fix value of some fields */
	len = (__u64)data_end - (__u64)ip;
	ip->tot_len = bpf_htons(len);
	/* bpf_printk("len: %d (%d, %d, %d)", len, sizeof(*ip), sizeof(*udp), sizeof(*state)); */

	udp->len = bpf_htons(sizeof(struct udphdr) + sizeof(struct package));

	cksum = 0;
	ip->check = 0;
	ipv4_csum_inline(ip, &cksum);
	ip->check = bpf_htons(cksum);

	cksum = 0;
	udp->check = 0;
	/* ipv4_l4_csum_inline(data_end, udp, ip, &cksum); */
	/* udp->check = bpf_htons(cksum); */

	/* bpf_printk("To userspace %x:%d", bpf_ntohl(pkg->data[0].source_ip), bpf_ntohs(pkg->data[0].source_port)); */
	/* Send it to the userspace app */
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
