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

/* static __u64 counter = 0; */
/* static __u64 last_report = 0; */

/* static inline __attribute__((always_inline)) */
/* void report_tput(void) */
/* { */
/* 	__u64 ts, delta; */
/* 	/1* We must run on a single core *1/ */
/* 	counter += 1; */
/* 	ts = bpf_ktime_get_coarse_ns(); */
/* 	if (last_report == 0) { */
/* 		last_report = ts; */
/* 		return; */
/* 	} */

/* 	delta = ts - last_report; */
/* 	if (delta >= 1000000000L) { */
/* 		bpf_printk("throughput: %ld (pps)", counter); */
/* 		counter = 0; */
/* 		last_report = ts; */
/* 	} */
/* } */

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
	/* report_tput(); */

	__u64 cookie = bpf_get_socket_cookie(skb);
	struct sock_context *ctx = bpf_map_lookup_elem(&sock_ctx_map, &cookie);
	if (ctx == NULL) {
		bpf_printk("failed to get socket context");
		return SK_DROP;
	}
	__adjust_skb_size(skb, 41);
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if (data + 41 > data_end) {
		bpf_printk("Not enough space for writing reply");
		return SK_DROP;
	}
	memcpy(data, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nide", 41);
	return bpf_sk_redirect_map(skb, &sock_map, ctx->sock_map_index, 0);
}

char _license[] SEC("license") = "GPL";
