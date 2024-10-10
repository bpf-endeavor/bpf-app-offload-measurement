/*  This benchmark test the throughput of reading data throuhg maps
 *
 * This code declares the maps (will be created by libbpf when it is loaded)
 * also there is a TC program for preparing some of the maps (i.e. inserting
 * some values).
 *
 * To trigger the program just send a packet.
 *
 * Look at `server_comm_map.c` for the other half of this benchmark.
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

#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif

#define SERVER_PORT 8080

#define VALUE_SIZE 64
typedef struct {
	char data[VALUE_SIZE];
} __attribute__((packed)) value_t;

#define KEY_SIZE 4
#define THE_KEY "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
typedef struct {
	char data[KEY_SIZE];
} __attribute__((packed)) my_key_t;

/* #define MAP_ARRAY 1 */
/* #define MAP_HASH 1 */
#define MAP_RING 1

/* #define PERCPU 1 */
/* #define MMAPED 1 */


#ifdef MAP_ARRAY
struct {
#ifdef PERCPU
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
#else
	__uint(type, BPF_MAP_TYPE_ARRAY);
#endif
	__type(key,  __u32);
	__type(value, value_t);
	__uint(max_entries, 1);
#ifdef MMAPED
	__uint(map_flags, BPF_F_MMAPABLE);
#endif
} comm_channel_map SEC(".maps");
#endif

#ifdef MAP_HASH
struct {
#ifdef PERCPU
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__type(key,  my_key_t);
	__type(value, value_t);
	__uint(max_entries, 1);
} comm_channel_map SEC(".maps");
#endif

#ifdef MAP_RING
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2048 * 4096);
} comm_channel_map SEC(".maps");

/* Used in RINGBUF benchmark and must match the one defined in userspace
 * program
 * */
#define REPEAT 100000
static __u64 counter = 0;

#endif

SEC("tc")
int tc_prog(struct __sk_buff *skb)
{
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

#ifdef MAP_HASH
	/* Triggering this function once would be enough
	 * command:
	 *   nc -u 192.168.200.101 8080
	 *   <send something>
	 * */
	bpf_printk("here in tc_prog (bpf_comm_map)");
	/* Add a value to hash map for user space to read */
	my_key_t key;
	value_t v;
	__builtin_memcpy(&key.data, THE_KEY, KEY_SIZE);
	__builtin_memset(&v.data, 0xAB, VALUE_SIZE);
	bpf_map_update_elem(&comm_channel_map, &key, &v, BPF_ANY);
#endif

#ifdef MAP_RING
	value_t *val;
	/* Load 100K Values to the RING  so the userspace can read them one
	 * after the other.  Do not notify the userspace until last data is
	 * inserted.
	 *
	 * Command for triggering this about function 100K
	 * sudo ./build/app -a 17:00.0 -l 1 -- --client --ip-local
	 * 192.168.200.102 --ip-dest 192.168.200.101 --port-dest 8080
	 * --duration 2 --rate 51000 --payload 22 --batch 8
	 * */
	val = bpf_ringbuf_reserve(&comm_channel_map, sizeof(*val), 0);
	if (!val) {
		bpf_printk("Failed to reserve memory on the ring buffer!");
		return TC_ACT_SHOT;
	}
	__builtin_memset(&(val->data), 0xAB, VALUE_SIZE);
	counter++;
	if (counter < REPEAT) {
		bpf_ringbuf_submit(val, BPF_RB_NO_WAKEUP);
	} else {
		counter = 0;
		bpf_ringbuf_submit(val, BPF_RB_FORCE_WAKEUP);
		bpf_printk("Notify!");
	}
#endif
	return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
