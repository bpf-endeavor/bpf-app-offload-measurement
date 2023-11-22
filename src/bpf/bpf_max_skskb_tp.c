/* Paramaters Configuring the Experiment */

/* Do not perform map lookup to fine the index of the socket.
 * It is a very small optimization.
 * */
/* #define USE_SELF_REDIRECT 1 */

/* Modify and resize the packet and reply with some constant string.
 * */
#define CONSTANT_REPLY    1

/* Only use stream_verdict program (remove stream_parser)
 * */
/* #define SK_SKB_VERDICT */

/* #define STREAM_PARSER_TOUCH_SKB */

/* ------------------------------------ */

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct connection_state {};
#include "my_bpf/sockops.h"

#ifndef BPF_F_REDIRECT_SELF
#define BPF_F_REDIRECT_SELF (1ULL << 1)
#endif



#ifdef CONSTANT_REPLY
/* Set request content to the STRING given.
 * NOTE: expect ``str'' to be a STRING_LITERAL
 * */
#define STRING_TO_PACKET(skb, str, FAIL_RET) {         \
  const unsigned int __size = sizeof(str) - 1;         \
  /* __adjust_skb_size(skb, __size);                      \ */ \
  bpf_skb_adjust_room(skb, __size - skb->len, 0, 0);   \
  if (((void *)(__u64)skb->data + __size)  > (void *)(__u64)skb->data_end) { \
    FAIL_RET;                                          \
  }                                                    \
  memcpy((void *)(__u64)skb->data, str, __size);       \
}
#else
#define STRING_TO_PACKET(skb, str, FAIL_RET) ;;
#endif


#ifndef SK_SKB_VERDICT
SEC("sk_skb/stream_parser")
int parser(struct __sk_buff *skb)
{
#ifdef STREAM_PARSER_TOUCH_SKB
	/* Pull message data so that we can access it */
	if (bpf_skb_pull_data(skb, skb->len) != 0) {
		bpf_printk("Parser: Failed to load message data");
		return 0;
	}
#endif
	return skb->len;
}
#endif

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
#ifdef USE_SELF_REDIRECT
	/* Does this flag help with performance of responding to the request
	 * for the same socket ?
	 * */
	STRING_TO_PACKET(skb, "HELLO WORLD END\r\n", return SK_DROP);
	return bpf_sk_redirect_map(skb, &sock_map, 0, BPF_F_REDIRECT_SELF);
#else
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
	STRING_TO_PACKET(skb, "HELLO WORLD END\r\n", return SK_DROP);
	return bpf_sk_redirect_map(skb, &sock_map, sock_ctx->sock_map_index, 0);
#endif
}

char _license[] SEC("license") = "GPL";
