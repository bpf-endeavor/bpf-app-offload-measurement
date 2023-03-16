#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Put state of each socket in this struct (This will be used in sockops.h as
 * part of per socket metadata) */
struct connection_state {
	__u16 parser_seeker;
};

#include "my_bpf/sockops.h"

#define OFFSET_MASK 0x0fff

/* TODO: this struct is duplicated in the loader. If you are changing this also
 * update that! */
struct arg {
	int summary_size;
	int inst_count;
};

struct {
	__uint(type,  BPF_MAP_TYPE_ARRAY);
	/* __uint(map_flags, BPF_F_MMAPABLE); */
	__type(key,   __u32);
	__type(value, struct arg);
	__uint(max_entries, 1);
} arg_map SEC(".maps");

struct parser_loop_ctx {
	char *ptr;
	void *data_end;
	int found;
	int err;
};

static long parse_until_end_of_req(__u32 i, void *_ctx)
{
	struct parser_loop_ctx *ctx = _ctx;
	char *ptr = ctx->ptr;
	if ((void *)ptr + 3 > ctx->data_end) {
		bpf_printk("Parser: index is out of range of packet");
		ctx->err = 1;
		// break;
		return 1;
	}
	if (ptr[0] == 'E'
	 && ptr[1] == 'N'
	 && ptr[2] == 'D') {
		ctx->found = 1;
		// break;
		return 1;
	}
	ctx->ptr = ctx->ptr + 1;
	return 0;
}

/* This parser looks for the end of a request wich can span over multiple TCP
 * packets segments.
 *
 * It is for testing if summarizing multiple packets into a single context
 * switch would have any benfits.
 * */
SEC("sk_skb/stream_parser")
int parser(struct __sk_buff *skb)
{

	void *data;
	void *data_end;
	struct parser_loop_ctx loop_ctx;
	struct sock_context *sock_ctx;
	__u16 head, len;

	/* Pull message data so that we can access it */
	if (bpf_skb_pull_data(skb, skb->len) != 0) {
		bpf_printk("Parser: Failed to load message data\n");
		return SK_DROP;
	}

	/* Load the socket context */
	if (skb->sk == NULL) {
		bpf_printk("Parser: The socket reference is NULL");
		return SK_DROP;
	}
	sock_ctx = bpf_sk_storage_get(&sock_ctx_map, skb->sk, NULL, 0);
	if (!sock_ctx) {
		bpf_printk("Parser: Failed to get socket context!");
		return SK_DROP;
	}

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	head = sock_ctx->state.parser_seeker;
	len = skb->len - head;

	if (len  < 3) {
		// Not enough data wait
		return 0;
	}

	loop_ctx = (struct parser_loop_ctx) {
		.ptr = data + (head & OFFSET_MASK),
		.data_end = data_end,
		.found = 0,
		.err = 0,
	};
	/* bpf_printk("packet size: %d | head: %d", skb->len, head); */
	bpf_loop(len - 2, parse_until_end_of_req, &loop_ctx, 0);
	/* bpf_printk("found: %d | err: %d", loop_ctx.found, loop_ctx.err); */

	if (loop_ctx.err) {
		return SK_DROP;
	}

	if (loop_ctx.found) {
		// clear the offset for the new request
		sock_ctx->state.parser_seeker = 0;
		/* bpf_printk("done", loop_ctx.found, loop_ctx.err); */
		return skb->len;
	} else {
		// remember the offset for the next iteration
		sock_ctx->state.parser_seeker = ((long)loop_ctx.ptr - (long)data) + 2;
	}

	/* Wait for the rest of the request */
	/* bpf_printk("wait for more!", loop_ctx.found, loop_ctx.err); */
	return 0;
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
		/* TODO: set error flag in the context and return from the main
		 * function */
		bpf_printk("Trying to access out of packet");
		return 1;
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
int verdict(struct __sk_buff *skb)
{
	void *data, *data_end;
	char *ptr;
	__u32 len;
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

	/* Summarize the request */
	if (arg->summary_size > len) {
		bpf_printk("Error: Summary size is larger than request size");
		return SK_DROP;
	}

	int len_delta = -(arg->summary_size - len);
	int to_shrink = len_delta > 0xfff ? 0xfff : len_delta;
	len_delta -= to_shrink;
	if (bpf_skb_adjust_room(skb, -to_shrink, 0, BPF_ADJ_ROOM_NET) < 0) {
		bpf_printk("Failed to resize the packet (delta: %d)", to_shrink);
		return SK_DROP;
	}
	if (len_delta > 0) {
		// Farbod: Assuming it would be done in two attempts at most!
		if (bpf_skb_adjust_room(skb, -len_delta, 0, BPF_ADJ_ROOM_NET) < 0) {
			bpf_printk("Failed to resize the packet at second attempt (delta: %d)", len_delta);
			return SK_DROP;
		}
	}

	return SK_PASS;
}

char _license[] SEC("license") = "GPL";
