#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <linux/pkt_cls.h>

/* Put state of each socket in this struct */
struct connection_state {};

#include "my_bpf/commons.h"
#include "my_bpf/hash_fn.h"
#include "my_bpf/csum_helpers.h"

#define OFFSET_MASK 0x7fff

#define PORT 8080

/* NOTE: I am using a __u8 as index, if changing the value to larger than 255
 * update the code */
#define BATCH_SIZE 5


/*
 * This is the request header. The client sends its requets in this format.
 * */
struct reqhdr {
	int req_type;
	unsigned int payload_length;
} __attribute__((__packed__));

/* NOTE: this struct is duplicated in the userspace program */
struct source_addr {
	unsigned int source_ip;
	unsigned short source_port;
} __attribute__((__packed__));

/*
 * Each request is reduced to this structure. The userspace program receives a
 * batch of request in the form of this struct.
 * */
struct req_data {
	unsigned int hash;
	struct source_addr src_addr;
} __attribute__((__packed__));

struct package {
	__u32 count;
	struct req_data data[BATCH_SIZE];
} __attribute__((__packed__));

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key,   __u32);
	__type(value, struct package);
	__uint(max_entries, 2);
} batching_map SEC(".maps");
/* ---------------- */

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
	/* bpf_printk("Here at verdict program!"); */
	void *data, *data_end;
	struct source_addr *src_addr_hdr;
	struct reqhdr *req;

	__u8 *base;
	__u16 len;

	__u32 hash;
	struct package *pkg;
	const int zero = 0;
	struct package *state;
	__u8 index;

	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;

	/* I expect the TC program to encapsulate the payload with source_addr
	 * header.
	 * */
	src_addr_hdr = data;
	req = (struct reqhdr *)(src_addr_hdr + 1);
	if ((void *)(req + 1) > data_end) {
		bpf_printk("Request is too small");
		return SK_PASS;
	}

	if (req->req_type == 1) {
		bpf_printk("Currently type 1 request is not supported\n");
		return SK_DROP;
	} else if (req->req_type == 2) {
		base = (__u8 *)(req + 1);
		len = (__u64)data_end - (__u64)base;
		/* assert len == req->payload_length */
		hash = FNV_OFFSET_BASIS_32;
		if (fnv_hash(base, len, data_end, &hash) != 0) {
			bpf_printk("Failed to perform the hashing!");
			return SK_DROP;
		}

		pkg = bpf_map_lookup_elem(&batching_map, &zero);
		if (!pkg) {
			bpf_printk("Failed to get the package (batch)!");
			return SK_DROP;
		}
		index = pkg->count;
		if (index >= BATCH_SIZE) {
			bpf_printk("Batch size grow larger than expected!");
			return SK_DROP;
		}
		pkg->count++;
		pkg->data[index].hash = hash;

		/* For some reason these values are zero in case of UDP? */
		/* pkg->data[index].source_ip = skb->remote_ip4; */
		/* pkg->data[index].source_port = bpf_ntohs((__u16)bpf_ntohl(skb->remote_port)); */

		/* Copy source IP and port to the package data */
		pkg->data[index].src_addr = *src_addr_hdr;

		/* bpf_printk("recv request from: %x:%d", */
		/* 		pkg->data[index].src_addr.source_ip, */
		/* 		pkg->data[index].src_addr.source_port); */

		if (pkg->count == BATCH_SIZE) {
			if (__adjust_skb_size(skb, sizeof(struct package)) != 0) {
				bpf_printk("Failed to resize the packet");
				return SK_DROP;
			}
			data = (void *)(__u64)skb->data;
			data_end = (void *)(__u64)skb->data_end;

			state = (struct package *)(data);
			if ((void *)(state + 1) > data_end) {
				bpf_printk("not enough space for the state");
				return SK_DROP;
			}
			memcpy(state, pkg, sizeof(struct package));

			/* Clear the package */
			pkg->count = 0;

			/* Send it to the userspace app */
			return SK_PASS;
		} else {
			/* Waiting for more request */
			return SK_DROP;
		}
	}

	/* Other request types are not handled in BPF */
	return SK_PASS;
}

/*
 * This TC program adds the source IP and port of the request to the payload
 * of the UDP packet. This information is used for batching
 * */
SEC("tc")
int tc_encap_with_source(struct __sk_buff *skb)
{
	/* bpf_printk("It is TC"); */
	void *data, *data_end;

	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp, *old_udp;
	struct source_addr *src_addr_hdr;

	short len;
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

	/* This is a UDP request for our service. Encapsulate with the source
	 * address.
	 * */
	if (bpf_skb_adjust_room(skb, sizeof(struct source_addr),
				BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_NO_CSUM_RESET) != 0) {
		bpf_printk("Failed to add space for source address header!");
		return TC_ACT_SHOT;
	}

	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;
	eth = data;
	ip = (struct iphdr *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		bpf_printk("Failed: IP header out of range!!");
		return TC_ACT_SHOT;
	}

	/* The space is added between IP and UDP header.
	 * Move UDP up and place the source header at the beging of the
	 * payload.
	 * */
	udp = (void *)ip + (ip->ihl * 4);
	old_udp = ((void *)udp) + sizeof(struct source_addr);
	if ((void *)(udp+1) > data_end ||
			(void *)(old_udp + 1) > data_end) {
		bpf_printk("Accessing out of packet when moving UDP header");
		return TC_ACT_SHOT;
	}
	memmove(udp, old_udp, sizeof(struct udphdr));

	src_addr_hdr = (struct source_addr *)(udp + 1);
	if ((void *)(src_addr_hdr + 1) > data_end) {
		bpf_printk("Error: source address header pointer is out or packet range!");
		return TC_ACT_SHOT;
	}
	src_addr_hdr->source_ip = ip->saddr;
	src_addr_hdr->source_port = udp->source;

	/* Now I have changed the payload, I should update the some fields in 
	 * IP and UDP headers
	 * */
	len = (__u64)data_end - (__u64)ip;
	ip->tot_len = bpf_htons(len);
	udp->len = bpf_htons(bpf_ntohs(udp->len) + sizeof(struct source_addr));

	cksum = 0;
	ip->check = 0;
	ipv4_csum_inline(ip, &cksum);
	ip->check = bpf_htons(cksum);
	udp->check = 0;

	/* Send packet to the SK_SKB */
	/* bpf_printk("Send to verdict program"); */
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
