#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "my_bpf/hash_fn.h"
#include "my_bpf/commons.h"

/* Put state of each socket in this struct (This will be used in sockops.h as
 * part of per socket metadata) */
struct connection_state {
	int old;
	int ready;
	int req_type;
	int rem_bytes;
	unsigned int hash;
};

#include "my_bpf/sockops.h"

#define OFFSET_MASK 0x7fff

struct request {
	int req_type;
	unsigned int payload_length;
} __attribute__((__packed__));

SEC("sk_skb/stream_parser")
int parser(struct __sk_buff *skb)
{

	void *data;
	void *data_end;
	struct sock_context *sock_ctx;
	__u32 hash;
	__u8 *ptr;
	__u32 len;

	/* Pull message data so that we can access it */
	if (bpf_skb_pull_data(skb, skb->len) != 0) {
		bpf_printk("Parser: Failed to load message data");
		return 0;
	}

	if (skb->sk == NULL) {
		bpf_printk("The socket reference is NULL");
		return SK_DROP;
	}
	sock_ctx = bpf_sk_storage_get(&sock_ctx_map, skb->sk, NULL, 0);
	if (!sock_ctx) {
		bpf_printk("Failed to get socket context!");
		return SK_DROP;
	}

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	if (sock_ctx->state.old) {
		hash = sock_ctx->state.hash;
		ptr = data;
		len = skb->len;
	} else {
		/* A new request */
		struct request *req = data;
		sock_ctx->state.old = 1;
		sock_ctx->state.ready = 0;

		/* Bound checking */
		if ((void *)(req+1) > data_end) {
			bpf_printk("Failed to read request header");
			return 0;
		}

		sock_ctx->state.req_type = req->req_type;
		sock_ctx->state.rem_bytes = req->payload_length;
		hash = FNV_OFFSET_BASIS_32;
		ptr = (__u8 *)(req + 1);
		len = skb->len - sizeof(struct request);
	}

	if (fnv_hash(ptr, len, data_end, &hash) != 0) {
		bpf_printk("Failed to perform the hashing!");
		return 0;
	}

	sock_ctx->state.hash = hash;
	sock_ctx->state.rem_bytes -= len;

	if (sock_ctx->state.rem_bytes > 0) {
		/* Discard the current bytes */
		return skb->len;
	} else if (sock_ctx->state.rem_bytes < 0) {
		bpf_printk("Unexpected request length !!");
		return skb->len;
	}

	sock_ctx->state.old = 0;
	sock_ctx->state.ready = 1;

	return skb->len;
}

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
	void *data;
	void *data_end;
	struct sock_context *sock_ctx;

	if (skb->sk == NULL) {
		bpf_printk("The socket reference is NULL");
		return SK_DROP;
	}
	sock_ctx = bpf_sk_storage_get(&sock_ctx_map, skb->sk, NULL, 0);
	if (!sock_ctx) {
		bpf_printk("Failed to get socket context!");
		return SK_DROP;
	}

	if (!sock_ctx->state.ready)
		return SK_DROP;

	/* Pull message data so that we can access it */
	if (bpf_skb_pull_data(skb, skb->len) != 0) {
		bpf_printk("Parser: Failed to load message data");
		return 0;
	}

	if (sock_ctx->state.req_type == 1) {
		__adjust_skb_size(skb, sizeof("Done,END\r\n") - 1);
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;

		/* Reply */
		if (data + sizeof("done,END\r\n") - 1 > data_end) {
			bpf_printk("Not enough space for writing reply");
			return SK_DROP;
		}
		memcpy(data, "Done,END\r\n", sizeof("Done,END\r\n") - 1);
		return bpf_sk_redirect_map(skb, &sock_map,
				sock_ctx->sock_map_index, 0);
	} else if (sock_ctx->state.req_type == 2) {
		__adjust_skb_size(skb, sizeof(sock_ctx->state.hash));
		data = (void *)(long)skb->data;
		data_end = (void *)(long)skb->data_end;

		if ((void *)data + sizeof(sock_ctx->state.hash) > data_end) {
			bpf_printk("Failed to copy hash value to the packet!");
			return SK_DROP;
		}
		memcpy(data, &sock_ctx->state.hash, sizeof(sock_ctx->state.hash));
		return SK_PASS;
	}

	bpf_printk("Unknown request type");
	return SK_DROP;
}

char _license[] SEC("license") = "GPL";
