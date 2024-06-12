/*
 * How much benefit we gain if we drop at eBPF HOOK
 * This experiment will show what is the upper-bound of benefits we can gain.
 * We avoid doing every instruction needed after the eBPF HOOk
 * */
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

#define SERVER_PORT 8080

static __u64 counter = 0;
static __u64 last_report = 0;

static inline __attribute__((always_inline))
void report_tput(void)
{
	__u64 ts, delta;
	/* We must run on a single core */
	counter += 1;
	ts = bpf_ktime_get_coarse_ns();
	if (last_report == 0) {
		last_report = ts;
		return;
	}

	delta = ts - last_report;
	if (delta >= 1000000000L) {
		bpf_printk("throughput: %ld (pps)", counter);
		counter = 0;
		last_report = ts;
	}
}

/* SK_SKB Test ------------------------------------------------------------- */

/* Put state of each socket in this struct (This will be used in sockops.h as
 * part of per socket metadata)
 * */
struct connection_state { };
#include "my_bpf/sockops.h"
/* SEC("sk_skb/stream_parser") */
/* int parser(struct __sk_buff *skb) */
/* { */
/* 	return skb->len; */
/* } */

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
	/* We are hooked to our server socket so we are dropping the correct
	 * traffic
	 * */
	report_tput();
	return SK_PASS;
}

/* XDP Test ---------------------------------------------------------------- */
SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	report_tput();
	return XDP_PASS;
}

/* TC Test ----------------------------------------------------------------- */
SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
	report_tput();
	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
