#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Put state of each socket in this struct */
struct connection_state {};

#include "my_bpf/commons.h"
#include "my_bpf/hash_fn.h"
#include "my_bpf/csum_helpers.h"

#define OFFSET_MASK 0x7fff

#define PORT 8080
#define MAX_CONN 10240

/* NOTE: I am using a __u8 as index, if changing the value to larger than 255
 * update the code */
#define BATCH_SIZE 5

struct reqhdr {
	int req_type;
	unsigned int payload_length;
} __attribute__((__packed__));

/* NOTE: this struct is duplicated in the userspace program */
struct req_data {
	unsigned int hash;
	__u32 source_ip;
	__u16 source_port;
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

/* SEC("sk_skb/stream_parser") */
/* int parser(struct __sk_buff *skb) */
/* { */
/* 	bpf_printk("parser: %d", skb->len); */
/* 	return skb->len; */
/* } */

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
	/* bpf_printk("here it is!"); */
	void *data, *data_end;
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

	req = (struct reqhdr *)(data);
	if ((void *)(req + 1) > data_end) {
		/* bpf_printk("Not request too small"); */
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
		pkg->data[index].source_ip = skb->remote_ip4;
		pkg->data[index].source_port = bpf_ntohs((__u16)bpf_ntohl(skb->remote_port));

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

	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
