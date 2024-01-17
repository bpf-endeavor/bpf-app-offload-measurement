#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/tcp.h>

#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif
#ifndef memmove
#define memmove(d, s, len) __builtin_memmove(d, s, len)
#endif
#ifndef memset
#define memset(d, c, len) __builtin_memset(d, c, len)
#endif
typedef char bool;
#define PKT_OFFSET_MASK 0xfff
struct context {
  int fd;
  struct sockaddr_in addr;
  socklen_t addr_len;
};

/* Put state of each socket in this struct (This will be used in sockops.h as
 * part of per socket metadata) */
struct connection_state { };
#include "my_bpf/sockops.h"

SEC("sk_skb/stream_parser")
int parser(struct __sk_buff *skb)
{
  return skb->len;
}

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
  if (bpf_skb_pull_data(skb, skb->len) != 0) {
    bpf_printk("Parser: Failed to load message data");
    return SK_DROP;
  }
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
  struct context c;
  char * rbuf;
  rbuf = (void *)((unsigned long long)(skb->data));
  __adjust_skb_size(skb, 5);
  if ((void *)((unsigned long long)(skb->data)) + 5 > (void *)((unsigned long long)(skb->data_end))) {
    return (SK_DROP);
  }
  memcpy((void *)((unsigned long long)(skb->data)), "END\r\n", 5);
  return (return bpf_sk_redirect_map(skb, &sock_map, sock_ctx->sock_map_index, 0););
}

char _license[] SEC("license") = "GPL";
