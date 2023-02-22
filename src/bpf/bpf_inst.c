#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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
	char *data, *data_end;
	__u16 len;
	__u16 i, index;
	int value;
	struct arg *arg;

	value = 0;
	arg = bpf_map_lookup_elem(&arg_map, &value);

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	len = (long)data_end - (long)data;

	if (data + 4 > data_end) {
		bpf_printk("Packet is smaller than 4 bytes");
		return SK_DROP;
	}

	value = *(int *)data;
	for (i = 0; i < arg->inst_count; i++) {
		index = i % len;
		if ((data + index + 1) > data_end) {
			bpf_printk("Trying to access out of packet");
			return SK_DROP;
		}
		value += data[i % len];
	}
	*(int *)data = value;

	if (value == 13) {
		/* This if is for asking the compiler to not optimize the for
		 * loop by removing it */
		bpf_printk("i: %d  val: %d", i, value);
	}

	return SK_DROP;
}
