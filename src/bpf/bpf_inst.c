#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Put state of each socket in this struct */
struct connection_state {};

#include "my_bpf/sockops.h"

#define MAX_INST_COUNT 1000

/* TODO: this struct is duplicated in the loader. If you are changing this also
 * update that! */
struct arg {
	int inst_count;
};

struct {
	__uint(type,  BPF_MAP_TYPE_ARRAY);
	/* __uint(map_flags, BPF_F_MMAPABLE); */
	__type(key,   __u32);
	__type(value, struct arg);
	__uint(max_entries, 1);
} arg_map SEC(".maps");


SEC("sk_skb/stream_parser")
int parser(struct __sk_buff *skb)
{
	return skb->len;
}


SEC("sk_skb/stream_verdict")
int verdict_inst_bench(struct __sk_buff *skb)
{
	bpf_printk("hello from verdict!");

	void *data, *data_end;
	char *ptr;
	__u16 len;
	__u16 i, index;
	int value;
	struct arg *arg;

	/* Pull message data so that we can access it */
	if (bpf_skb_pull_data(skb, skb->len) != 0) {
		bpf_printk("Failed to load message data\n");
		return SK_DROP;
	}

	data = (void *)(long)skb->data;
	ptr = data;
	data_end = (void *)(long)skb->data_end;
	len = (long)data_end - (long)data;

	/* Load benchmark arguments */
	value = 0;
	arg = bpf_map_lookup_elem(&arg_map, &value);
	if (!arg) {
		return SK_DROP;
	}
	if (arg->inst_count > MAX_INST_COUNT) {
		/* The preconditions have been violated */
		bpf_printk("The argument is asking more instructions than hard coded upper bound! change the hard coded value!");
		return SK_DROP;
	}

	/* Benchmark logic */
	if ((void *)(ptr + sizeof(int)) > data_end) {
		bpf_printk("Packet is smaller than 4 bytes (len: %d)", len);
		return SK_DROP;
	}
	value = *(int *)ptr;
	for (i = 0; i < MAX_INST_COUNT; i++) {
		if (i > arg->inst_count) {
			break;
		}

		/* index = (i % len) & 0x0fff; */
		index = i;
		if (((void *)ptr + index + 1) > data_end) {
			bpf_printk("Trying to access out of packet");
			return SK_DROP;
		}
		value += ptr[index];
	}
	if ((void *)ptr + sizeof(int) > data_end) {
		bpf_printk("Packet is smaller than 4 bytes (2)");
		return SK_DROP;
	}
	*(int *)ptr = value;

	if (value == 13) {
		/* This if is for asking the compiler to not optimize the for
		 * loop by removing it */
		bpf_printk("i: %d  val: %d", i, value);
	}

	bpf_printk("goodbye");
	return SK_DROP;
}

char _license[] SEC("license") = "GPL";
