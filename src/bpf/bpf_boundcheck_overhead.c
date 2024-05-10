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
#define MESSAGE "HELLO THIS IS AN IMPORTANT MESSAGE I AM TESTING SOMETHING"
#define MESSAGE_SIZE sizeof(MESSAGE)

static __u64 counter = 0;
static __u64 last_report = 0;

/* TODO: this struct is duplicated in the loader. If you are changing this also
 * update that! */
struct arg {
	int inst_count;
};

struct {
	__uint(type,  BPF_MAP_TYPE_ARRAY);
	/* __uint(map_flags, BPF_F_MMAPABLE); */
	__type(key,   __u32);
	__type(value, struct arg);
	__uint(max_entries, 1);
} arg_map SEC(".maps");

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

SEC("xdp")
int xdp_bound_check(struct xdp_md *ctx)
{
	struct arg *arg;
	int ret = 0;
	char arr[MESSAGE_SIZE];
	void *data = (void *)(__u64)ctx->data;
	void *data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	__u16 i, index;
	__u32 value;
	/* Make sure we are processing the traffic related to the our server
	 * */
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return XDP_PASS;

	/* Load benchmark arguments */
	arg = bpf_map_lookup_elem(&arg_map, &ret);
	if (!arg) {
		/* Must never happen */
		return XDP_DROP;
	}

	__builtin_memcpy(arr, MESSAGE, MESSAGE_SIZE);
	value = 0;
	index = 0;
	for (i = 0; i < 8000 && i < arg->inst_count; i++) {
		/* Perform a bound check */
		if (index >= MESSAGE_SIZE) {
			bpf_printk("access out of range");
			return XDP_DROP;
		}
		value += arr[index];
		index = index == 56 ? 0 : index + 1;
	}

	if (value == 0) {
		bpf_printk("This should not be printed!");
	}

	report_tput();
	return XDP_DROP;
}

SEC("xdp")
int xdp_no_check(struct xdp_md *ctx)
{
	struct arg *arg;
	int ret = 0;
	char arr[MESSAGE_SIZE];
	void *data = (void *)(__u64)ctx->data;
	void *data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	__u16 i, index;
	__u32 value;
	/* Make sure we are processing the traffic related to the our server
	 * */
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return XDP_PASS;

	/* Load benchmark arguments */
	arg = bpf_map_lookup_elem(&arg_map, &ret);
	if (!arg) {
		/* Must never happen */
		return XDP_DROP;
	}
	__builtin_memcpy(arr, MESSAGE, MESSAGE_SIZE);
	value = 0;
	index = 0;
	for (i = 0; i < 4000 && i < arg->inst_count; i++) {
		/* index = i % MESSAGE_SIZE; */
		/* DO not perform a bound check */
		value += arr[index];
		index = index == 56 ? 0 : index + 1;
	}

	if (value == 2345) {
		bpf_printk("This should not be printed!");
	}

	report_tput();
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
