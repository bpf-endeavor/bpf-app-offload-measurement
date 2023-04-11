/* This file has some helper functions for calculating IP and TCP/UDP checksums
 * */
#ifndef _CSUM_HELPERS_H
#define _CSUM_HELPERS_H

#include <linux/ip.h>

struct csum_loop_ctx {
	__u16 *next_iph_u16;
	void *data_end;
	__u64 *csum;
};

static inline __u16 csum_fold_helper(__u64 csum)
{
	int i;
#pragma unroll
	for (i = 0; i < 4; i++) {
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16); }
	return ~csum;
}

static inline
void ipv4_csum_inline(void *iph, __u64 *csum)
{
	__u32 i;
	__u16 *next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
	for (i = 0; i < sizeof(struct iphdr) >> 1; i++) {
		*csum += bpf_ntohs(*next_iph_u16);
		next_iph_u16++;
	}
	*csum = csum_fold_helper(*csum);
}

static long csum_loop(__u32 i, void *_ctx)
{
	struct csum_loop_ctx *ctx = _ctx;
	if ((void *)(ctx->next_iph_u16 + 1) > ctx->data_end) {
		return 1;
	}
	*ctx->csum += bpf_ntohs(*ctx->next_iph_u16);
	ctx->next_iph_u16++;
	return 0;
}

/* TODO: this value is too low! I need to increase it */
#define MAX_PACKET_SIZE 1470
static inline
void ipv4_l4_csum_inline(void *data_end, void *l4_hdr,
		struct iphdr *iph, __u64 *csum)
{
	/* __u32 i; */
	__u32 ip_addr;
	__u16 *next_iph_u16;
	__u8 *last_byte;

	// Psuedo header
	ip_addr = bpf_ntohl(iph->saddr);
	*csum += (ip_addr >> 16) + (ip_addr & 0xffff);
	ip_addr = bpf_ntohl(iph->daddr);
	*csum += (ip_addr >> 16) + (ip_addr & 0xffff);
	*csum += (__u16)iph->protocol;
	*csum += (__u16)((long)data_end - (long)l4_hdr);

	next_iph_u16 = (__u16 *)l4_hdr;
	// Use an upper bound to avoid variable size loops
/* #pragma clang loop unroll(disable) */
/* 	for (i = 0; i < MAX_PACKET_SIZE >> 1; i++) { */
/* 		if ((void *)(next_iph_u16 + 1) > data_end) { */
/* 			break; */
/* 		} */
/* 		*csum += bpf_ntohs(*next_iph_u16); */
/* 		next_iph_u16++; */
/* 	} */
	const __u16 length = (__u64)data_end - (__u64)next_iph_u16;
	const __u16 nr = length / 2;
	struct csum_loop_ctx loop_ctx = {
		.next_iph_u16 = next_iph_u16,
		.data_end = data_end,
		.csum = csum,
	};
	bpf_loop(nr, csum_loop, &loop_ctx, 0);
	if (loop_ctx.next_iph_u16 != data_end) {
		last_byte = (__u8 *)next_iph_u16;
		if ((void *)(last_byte + 1) <= data_end) {
			*csum += (__u16)(*last_byte) << 8;
		}
	}
	*csum = csum_fold_helper(*csum);
}
#endif
