#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "xdp_helper.h"

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
#define MAX_PACKET_SIZE 1472
#define DATA_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
struct context {
  int fd;
  struct sockaddr_in addr;
  socklen_t addr_len;
};

SEC("xdp")
int xdp_prog(struct xdp_md *xdp)
{
  {
    void *data = (void *)(unsigned long long)xdp->data;
    void *data_end = (void *)(unsigned long long)xdp->data_end;
    struct ethhdr *eth = data;
    struct iphdr  *ip  = (void *)(eth + 1);
    struct udphdr *udp = (void *)(ip  + 1);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;
    if (udp->dest != bpf_htons(8080)) return XDP_PASS;
  }
  struct context c;
  char * rbuf;
  rbuf = (void *)((unsigned long long)(xdp->data) + DATA_OFFSET);
  int _tmp_100;
  _tmp_100 = 5 - (unsigned short)((void *)((unsigned long long)(xdp->data_end)) - (void *)((unsigned long long)(xdp->data) + DATA_OFFSET));
  bpf_xdp_adjust_tail(xdp, _tmp_100);
  if ((void *)((unsigned long long)(xdp->data) + DATA_OFFSET) + 5 > (void *)((unsigned long long)(xdp->data_end))) {
    return (XDP_DROP);
  }
  memcpy((void *)((unsigned long long)(xdp->data) + DATA_OFFSET), "END\r\n", 5);
  __prepare_headers_before_send(xdp);
  return (XDP_TX);
}

char _license[] SEC("license") = "GPL";
