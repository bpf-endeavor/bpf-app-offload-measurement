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

#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif

#define SERVER_PORT 8080

#define VALUE_SIZE 64
typedef struct {
	char data[VALUE_SIZE];
} __attribute__((packed)) value_t;


/* #define MAP_ARRAY 1 */
#define MAP_HASH 1

#ifdef MAP_ARRAY
struct {
	/* __uint(type, BPF_MAP_TYPE_ARRAY); */
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key,  __u32);
	__type(value, value_t);
	__uint(max_entries, 1);
	/* __uint(map_flags, BPF_F_MMAPABLE); */
} comm_channel_map SEC(".maps");
#endif

#ifdef MAP_HASH
#define THE_KEY "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
typedef struct {
	char data[32];
} __attribute__((packed)) my_key_t;

struct {
	/* __uint(type, BPF_MAP_TYPE_HASH); */
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key,  my_key_t);
	__type(value, value_t);
	__uint(max_entries, 1);
} comm_channel_map SEC(".maps");
#endif

SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
	/* Make sure we are dropping only the traffic related to the our server
	 * */
	void *data, *data_end;
	data = (void *)(__u64)skb->data;
	data_end = (void *)(__u64)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *ip = (void *)(eth + 1);
	struct udphdr *udp = (void *)(ip + 1);
	if ((void *)(udp + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;
	if (udp->dest != bpf_htons(SERVER_PORT))
		return TC_ACT_OK;
	bpf_printk("here in tc_prog (bpf_comm_map)");
#ifdef MAP_HASH
	my_key_t key;
	value_t v;
	__builtin_memcpy(&key.data, THE_KEY, 32);
	__builtin_memset(&v.data, 0xAB, VALUE_SIZE);
	bpf_map_update_elem(&comm_channel_map, &key, &v, BPF_ANY);
#endif
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
