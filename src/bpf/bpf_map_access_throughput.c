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
#define ENTRIES (100000 * 1111 / 1000)

/* #define MAP_ARRAY 1 */
/* #define MAP_HASH 1 */
#define MAP_LRU_HASH 1

/* #define PERCPU 1 */
/* #define MMAPED 1 */

typedef struct {
	__u32 mapped_ip;
	__u64 x;
	int verdict;
} value_t;

typedef struct {
	unsigned int src_ip;
	unsigned short src_port;
	unsigned int dst_ip;
	unsigned short dst_port;
	unsigned char  protocol;
} __attribute__((packed)) flow_key_t;

// Define the map
#ifdef MAP_ARRAY
struct {
#ifdef PERCPU
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
#else
	__uint(type, BPF_MAP_TYPE_ARRAY);
#endif
	__type(key,  __u32);
	__type(value, value_t);
	__uint(max_entries, ENTRIES);
#ifdef MMAPED
	__uint(map_flags, BPF_F_MMAPABLE);
#endif
} state_map SEC(".maps");

#else
#ifdef MAP_HASH

struct {
#ifdef PERCPU
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__type(key,  flow_key_t);
	__type(value, value_t);
	__uint(max_entries, ENTRIES);
} state_map SEC(".maps");

#else
#ifdef MAP_LRU_HASH

struct {
#ifdef PERCPU
	__uint(type, BPF_MAP_TYPE_PERCPU_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#endif
	__type(key,  flow_key_t);
	__type(value, value_t);
	__uint(max_entries, ENTRIES);
} state_map SEC(".maps");

#endif
#endif
#endif

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

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	/* Make sure we are dropping only the traffic related to the our server
	 * */
	void *data, *data_end;
	value_t *val;
	data = (void *)(__u64)ctx->data;
	data_end = (void *)(__u64)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	if (udp + 1 > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;
#ifdef MAP_ARRAY
	__u32 index = (bpf_ntohs(udp->source) * 65000) + bpf_ntohs(udp->dest);
	if (index > ENTRIES) {
		bpf_printk("trying to lookup an index out of range! this should not happen! (%d)", index);
		return XDP_DROP;
	}
	val = bpf_map_lookup_elem(&state_map, &index);
	if (val == NULL) {
		/* This will never happen */
		return XDP_ABORTED;
	}
	val->x += 1;
#elif defined(MAP_HASH) || defined(MAP_LRU_HASH)
	flow_key_t flow;
	flow.src_ip = ip->saddr;
	flow.src_port = udp->source;
	flow.dst_ip = ip->daddr;
	flow.dst_port = udp->dest;
	flow.protocol = ip->protocol;
	val = bpf_map_lookup_elem(&state_map, &flow);
	if (val == NULL) {
		value_t new_val;
		new_val.x = 1;
		bpf_map_update_elem(&state_map, &flow, &new_val, BPF_NOEXIST);
	} else {
		val->x += 1;
	}
#endif
	report_tput();
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
