/* date: 09-Oct-2024
 * author: farbod shahinfar
 * inspired from:
 * https://en.wikipedia.org/wiki/Sieve_of_Atkin
 * https://www.geeksforgeeks.org/sieve-of-atkin/
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

# define __nobuiltin(X) __attribute__((no_builtin(X)))
#define UPPER_BOUND_ON_LIMIT_REQ 100

char _license[] SEC("license") = "GPL";

typedef struct {
	__u32 vals[UPPER_BOUND_ON_LIMIT_REQ];
} sieve_t;

struct {
	/* __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); */
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key,  __u32);
	__type(value, sieve_t);
	__uint(max_entries, 1);
} sieve_map SEC(".maps");

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

static inline __attribute__((always_inline)) __nobuiltin("memset")
void __calc_prime(int limit)
{
	__u32 index, n;
	const __u32 zero = 0;
	sieve_t *s;

	s = bpf_map_lookup_elem(&sieve_map, &zero);
	if (s == NULL)
		return;

	/* 1. We know 2, 3, 5 are prime.
	 * 2. We know even numbers are not prime.
	 * 3. Each index i of `s->vals' is the number 2*i+7
	 * */

	/* Mark all the numbers as composite (not prime) */
	/* __builtin_memset(s->vals, 0, UPPER_BOUND_ON_LIMIT_REQ); */
	/* NOTE: I do not know why but memset does not compile. I use a loop */
	for (__u32 i = 0; i < UPPER_BOUND_ON_LIMIT_REQ; i++) {
		s->vals[i] = 0;
	}

	for (__u32 x = 1; x * x <= limit; x++) {
		for (__u32 y = 1; y * y <= limit; y++) {
			// Condition 1
			n = (4 * x * x) + (y * y);
			if (n >= 7 && n <= limit && (n % 12 == 1 || n % 12 == 5)) {
				index = (n - 7) / 2;
				if (index < UPPER_BOUND_ON_LIMIT_REQ)
					s->vals[index] ^= 1;
			}

			// Condition 2
			n = (3 * x * x) + (y * y);
			if (n >= 7 && n <= limit && n % 12 == 7) {
				index = (n - 7) / 2;
				if (index < UPPER_BOUND_ON_LIMIT_REQ)
					s->vals[index] ^= 1;
			}

			// Condition 3
			n = (3 * x * x) - (y * y);
			if (n >= 7 && x > y && n <= limit && n % 12 == 11) {
				index = (n - 7) / 2;
				if (index < UPPER_BOUND_ON_LIMIT_REQ)
					s->vals[index] ^= 1;
			}
		}
	}

	// Mark all multiples
	// of squares as non-prime
	for (int r = 0; r * r <= limit; r++) {
		if (s->vals[r] == 1) {
			n = (2 * r) + 7;
			n = n * n; /* n2 */
			for (__u32 i = n; i <= limit; i += n) {
				index = (i - 7) / 2;
				s->vals[index] = 0;
			}
		}
	}
}

SEC("xdp")
__nobuiltin("memset") /* the __calc_prime is inlined here so disable
			 builtin_memcpy to avoid compiler error */
int xdp_prog(struct xdp_md *ctx)
{
	/* Make sure we are dropping only the traffic related to the our server
	 * */
	void *data, *data_end;
	data = (void *)(__u64)ctx->data;
	data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	int *limit = (int *)(udp + 1);
	if ((void *)(limit + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return XDP_PASS;
	if (*limit > UPPER_BOUND_ON_LIMIT_REQ)
		return XDP_ABORTED;
	__calc_prime(*limit);
	bpf_printk("calculated prims up to %d", *limit);
	report_tput();
	return XDP_DROP;
}
