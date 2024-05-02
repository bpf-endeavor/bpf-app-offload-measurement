// #include <sys/types.h>
// #include <sys/socket.h>
// #include <linux/tcp.h>
// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
// #include <bpf/bpf_endian.h>
// 
// #include "my_bpf/hash_fn.h"
// #include "my_bpf/commons.h"
// 
// /* Put state of each socket in this struct (This will be used in sockops.h as
//  * part of per socket metadata) */
// struct connection_state {
// 	int old;
// 	int ready;
// 	int req_type;
// 	int rem_bytes;
// 	unsigned int hash;
// };
// 
// #include "my_bpf/sockops.h"
// 
// #define OFFSET_MASK 0x7fff
// /* NOTE: I am using a __u8 as index, if changing the value to larger than 255
//  * update the code */
// #define BATCH_SIZE 5
// #define BATCH_TIME_OUT_NS 2000
// 
// struct request {
// 	int req_type;
// 	unsigned int payload_length;
// } __attribute__((__packed__));
// 
// /* NOTE: this struct is duplicated in the userspace program */
// struct source_addr {
// 	unsigned int source_ip;
// 	unsigned short source_port;
// } __attribute__((__packed__));
// struct req_data {
// 	unsigned int hash;
// 	struct source_addr src_addr;
// } __attribute__((__packed__));
// 
// struct package {
// 	__u32 count;
// 	struct req_data data[BATCH_SIZE];
// } __attribute__((__packed__));
// 
// struct batch_entry {
// 	struct package pkg;
// 	struct bpf_timer timer;
// };
// 
// /* Maps ------------ */
// struct {
// 	/* Key and Value size MUST be zero */
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	/* max_entries MUST be a power of two */
// 	__uint(max_entries, 4 * 1024 * 1024);
// } ring_map SEC(".maps");
// 
// struct {
// 	/* NOTE: per cpu array is not supported for bpf_timer */
// 	/* __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); */
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__type(key,   __u32);
// 	__type(value, struct batch_entry);
// 	__uint(max_entries, 2);
// } batching_map SEC(".maps");
// /* ---------------- */
// 
// /* This is a helper function for sending batch to userspace */
// static inline int submit_batch_to_userspace(struct package *pkg)
// {
// 	struct bpf_dynptr ptr;
// 	bpf_ringbuf_reserve_dynptr(&ring_map, sizeof(struct package), 0, &ptr);
// 	bpf_dynptr_write(&ptr, 0, pkg, sizeof(struct package), 0);
// 	bpf_ringbuf_submit_dynptr(&ptr, 0);
// 	return 0;
// }
// 
// /* This the callback triggered when batch timer out occurs */
// static int submit_batch_cb(void *map, __u32 *key, struct batch_entry *val)
// {
// 	submit_batch_to_userspace(&val->pkg);
// 	/* Clear the package */
// 	val->pkg.count = 0;
// 	return 0;
// }
// 
// 
// SEC("sk_skb/stream_parser")
// int parser(struct __sk_buff *skb)
// {
// 	void *data;
// 	void *data_end;
// 	struct sock_context *sock_ctx;
// 	__u32 hash;
// 	__u8 *ptr;
// 	int len, proc_len;
// 
// 	/* Pull message data so that we can access it */
// 	if (bpf_skb_pull_data(skb, skb->len) != 0) {
// 		bpf_printk("Parser: Failed to load message data");
// 		return 0;
// 	}
// 
// 	if (skb->sk == NULL) {
// 		bpf_printk("The socket reference is NULL");
// 		return SK_DROP;
// 	}
// 	sock_ctx = bpf_sk_storage_get(&sock_ctx_map, skb->sk, NULL, 0);
// 	if (!sock_ctx) {
// 		bpf_printk("Failed to get socket context!");
// 		return SK_DROP;
// 	}
// 
// 	data = (void *)(long)skb->data;
// 	data_end = (void *)(long)skb->data_end;
// 
// 	if (sock_ctx->state.old) {
// 		hash = sock_ctx->state.hash;
// 		ptr = data;
// 		len = skb->len;
// 		proc_len = 0;
// 	} else {
// 		/* A new request */
// 		struct request *req = data;
// 		sock_ctx->state.old = 1;
// 		sock_ctx->state.ready = 0;
// 
// 		/* Bound checking */
// 		if ((void *)(req+1) > data_end) {
// 			bpf_printk("Failed to read request header");
// 			return 0;
// 		}
// 
// 		sock_ctx->state.req_type = req->req_type;
// 		sock_ctx->state.rem_bytes = req->payload_length;
// 		hash = FNV_OFFSET_BASIS_32;
// 		ptr = (__u8 *)(req + 1);
// 		len = skb->len - sizeof(struct request);
// 		proc_len = sizeof(struct request);
// 	}
// 	len = len > sock_ctx->state.rem_bytes ? sock_ctx->state.rem_bytes : len;
// 
// 	if (fnv_hash(ptr, len, data_end, &hash) != 0) {
// 		bpf_printk("Failed to perform the hashing!");
// 		return 0;
// 	}
// 
// 	sock_ctx->state.hash = hash;
// 	sock_ctx->state.rem_bytes -= len;
// 
// 	if (sock_ctx->state.rem_bytes > 0) {
// 		/* Discard the current bytes */
// 		return proc_len + len;
// 	} else if (sock_ctx->state.rem_bytes < 0) {
// 		bpf_printk("Unexpected request length !! rem_bytes: %d, cur len: %d skb_len: %d",
// 				sock_ctx->state.rem_bytes, len, skb->len);
// 		return proc_len + len;
// 	}
// 
// 	sock_ctx->state.old = 0;
// 	sock_ctx->state.ready = 1;
// 
// 	return proc_len + len;
// }
// 
// SEC("sk_skb/stream_verdict")
// int verdict(struct __sk_buff *skb)
// {
// 	void *data;
// 	void *data_end;
// 	struct sock_context *sock_ctx;
// 
// 	const int zero = 0;
// 	struct batch_entry *entry;
// 	__u8 index;
// 
// 	if (skb->sk == NULL) {
// 		bpf_printk("The socket reference is NULL");
// 		return SK_DROP;
// 	}
// 	sock_ctx = bpf_sk_storage_get(&sock_ctx_map, skb->sk, NULL, 0);
// 	if (!sock_ctx) {
// 		bpf_printk("Failed to get socket context!");
// 		return SK_DROP;
// 	}
// 
// 	if (!sock_ctx->state.ready) {
// 		return SK_DROP;
// 	}
// 
// 	/* Pull message data so that we can access it */
// 	if (bpf_skb_pull_data(skb, skb->len) != 0) {
// 		bpf_printk("Parser: Failed to load message data");
// 		return 0;
// 	}
// 
// 	if (sock_ctx->state.req_type == 1) {
// 		__adjust_skb_size(skb, sizeof("Done,END\r\n") - 1);
// 		data = (void *)(long)skb->data;
// 		data_end = (void *)(long)skb->data_end;
// 
// 		/* Reply */
// 		if (data + sizeof("done,END\r\n") - 1 > data_end) {
// 			bpf_printk("Not enough space for writing reply");
// 			return SK_DROP;
// 		}
// 		memcpy(data, "Done,END\r\n", sizeof("Done,END\r\n") - 1);
// 		return bpf_sk_redirect_map(skb, &sock_map,
// 				sock_ctx->sock_map_index, 0);
// 	} else if (sock_ctx->state.req_type == 2) {
// 		/* Batch request */
// 		entry = bpf_map_lookup_elem(&batching_map, &zero);
// 		if (!entry) {
// 			bpf_printk("Failed to get the batch object!");
// 			return SK_DROP;
// 		}
// 		index = entry->pkg.count & 0x1f;
// 		if (index >= BATCH_SIZE) {
// 			bpf_printk("Batch size grow larger than expected!");
// 			return SK_DROP;
// 		}
// 
// 		/* Extract the packet source address */
// 		entry->pkg.data[index].src_addr.source_ip = skb->remote_ip4;
// 		/* This is ridiculous! I should think about it a bit. Why such
// 		 * a juggling is needed?
// 		 * */
// 		entry->pkg.data[index].src_addr.source_port =
// 			bpf_ntohs((__u16)bpf_ntohl(skb->remote_port));
// 		/* bpf_printk("receive: %x:%d", bpf_ntohl(pkg->data[index].source_ip), */
// 		/* 		bpf_ntohs(pkg->data[index].source_port)); */
// 
// 		/* Mark this index as used */
// 		entry->pkg.count++;
// 		entry->pkg.data[index].hash = sock_ctx->state.hash;
// 
// 		if (entry->pkg.count == BATCH_SIZE) {
// #if SEND_ON_PKT
// 			__adjust_skb_size(skb, sizeof(struct package));
// 			data = (void *)(long)skb->data;
// 			data_end = (void *)(long)skb->data_end;
// 
// 			if ((void *)data + sizeof(struct package) > data_end) {
// 				bpf_printk("Failed to copy hash value to the packet!");
// 				return SK_DROP;
// 			}
// 			memcpy(data, &entry->pkg, sizeof(struct package));
// 			entry->pkg.count = 0;
// 			return SK_PASS;
// #else
// 			submit_batch_to_userspace(&entry->pkg);
// 			/* Clear the package */
// 			entry->pkg.count = 0;
// 			bpf_timer_cancel(&entry->timer);
// 			return SK_DROP;
// #endif
// 		} else {
// #ifndef SEND_ON_PKT
// 			if (entry->pkg.count == 1) {
// 				/* Arm the timer */
// 				bpf_timer_init(&entry->timer, &batching_map, 0);
// 				bpf_timer_set_callback(&entry->timer, submit_batch_cb);
// 				bpf_timer_start(&entry->timer, BATCH_TIME_OUT_NS, 0);
// 			}
// #endif
// 			/* Batching: waiting for more request */
// 			return SK_DROP;
// 		}
// 	}
// 
// 	bpf_printk("Unknown request type");
// 	return SK_DROP;
// }
// 
// char _license[] SEC("license") = "GPL";
