#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct connection_state {};
#include "my_bpf/sockops.h"

/* /1* NOTE: expect ``str'' to be a STRING_LITERAL *1/ */
/* #define STRING_TO_PACKET(skb, str, FAIL_RET) {         \ */
/*   const unsigned int __size = sizeof(str) - 1;         \ */
/*   /1* __adjust_skb_size(skb, __size);                      \ *1/ \ */
/*   bpf_skb_adjust_room(skb, __size - skb->len, 0, 0);   \ */
/*   if (((void *)(__u64)skb->data + __size)  > (void *)(__u64)skb->data_end) { \ */
/*     FAIL_RET;                                          \ */
/*   }                                                    \ */
/*   memcpy((void *)(__u64)skb->data, str, __size);       \ */
/* } */

SEC("sk_skb/stream_parser")
int parser(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
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
	return bpf_sk_redirect_map(skb, &sock_map, sock_ctx->sock_map_index, 0);
}

char _license[] SEC("license") = "GPL";
