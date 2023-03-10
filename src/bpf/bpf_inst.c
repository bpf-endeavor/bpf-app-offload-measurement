#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Put state of each socket in this struct */
struct connection_state {};

#include "my_bpf/sockops.h"

#define OFFSET_MASK 0x0fff

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


struct loop_context {
	unsigned int value;
	void *data_end;
	char *ptr;
	__u16 len;
	__u32 index;
};

/* NOTE: Farbod: I like this type of defining loops :). It does solve some
 * issues!
 * */
/*
 * Return: 0 -> continue the loop
 *         1 -> break from the loop
 * */
static long inst_loop(__u32 i, void *_ctx)
{
	struct loop_context *ctx = _ctx;
	/* __u32 index = i % ctx->len; */

	if (((void *)ctx->ptr + ctx->index + 1) > ctx->data_end) {
		bpf_printk("Trying to access out of packet");
		return SK_DROP;
	} else {
		ctx->value += ctx->ptr[ctx->index];
	}

	/* TODO: I want to use (i % index) but it seems clang generates a code
	 * which kernel can not verify. So I emulate the effect.
	 * */
	ctx->index = ctx->index == ctx->len - 1 ? 0 : ctx->index + 1;

	return 0;
}

#define ASCII_LETTER(val) ((val % 26) + 'a')

SEC("sk_skb/stream_verdict")
int verdict_inst_bench(struct __sk_buff *skb)
{
	void *data, *data_end;
	char *ptr;
	__u32 len;
	int value;
	struct arg *arg;
	struct sock_context *sock_ctx;

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

	/* NOTE: The userspace receives arguments as a variable and does not need to
	 * perform the look for each packet. Is this a fair comparison? 
	 *
	 * One solution could be to inject the argument values to the BPF
	 * binary when the loader program is loading it to the kernel.
	 * */

	/* Benchmark logic */
	if ((void *)(ptr + sizeof(int)) > data_end) {
		bpf_printk("Packet is smaller than 4 bytes (len: %d)", len);
		return SK_DROP;
	}
	struct loop_context loop_ctx = {
		.value = *(int *)ptr,
		.data_end = data_end,
		.ptr = ptr,
		.len = len,
		.index = 0,
	};
	bpf_loop(arg->inst_count, inst_loop, &loop_ctx, 0);
	*ptr = ASCII_LETTER(loop_ctx.value);

	/* Mark end of request */
	ptr = data + ((len - 5) & OFFSET_MASK);
	if ((void *)ptr < data || (void *)ptr + 5 > data_end) {
		bpf_printk("Packet is less than 5 bytes ??\n");
		return SK_DROP;
	}
	ptr[0] = 'E';
	ptr[1] = 'N';
	ptr[2] = 'D';
	ptr[3] = '\r';
	ptr[4] = '\n';

	/* NOTE: can I improve the eBPF environment by introducing a helper
	 * that does not need passing the index of socket map when redirecting
	 * on the same socket ? */
	/* Send a reply: I need to know the index of this socket on the socket map! */
	if (skb->sk == NULL) {
		bpf_printk("The socket reference is NULL");
		return SK_DROP;
	}
	sock_ctx = bpf_sk_storage_get(&sock_ctx_map, skb->sk, NULL, 0);
	if (!sock_ctx) {
		bpf_printk("Failed to get socket context!");
		return SK_DROP;
	}
	return bpf_sk_redirect_map(skb, &sock_map, sock_ctx->sock_map_index, 0);
}

char _license[] SEC("license") = "GPL";
