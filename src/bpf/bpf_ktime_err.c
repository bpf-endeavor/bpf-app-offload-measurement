#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>

static inline __attribute__((always_inline))
void test_timer()
{
	__u64 t1, t2, delta;
	t1 = bpf_ktime_get_boot_ns();
	t2 = bpf_ktime_get_boot_ns();
	delta = t2 - t1;
	bpf_printk("%ld", delta);
}

/* SK_SKB Test ------------------------------------------------------------- */

/* Put state of each socket in this struct (This will be used in sockops.h as
 * part of per socket metadata)
 * */
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
	test_timer();
	return SK_PASS;
}

/* XDP Test ---------------------------------------------------------------- */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	test_timer();
	return XDP_PASS;
}

/* TC Test ----------------------------------------------------------------- */
SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
	test_timer();
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

