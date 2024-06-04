#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "userspace/log.h"
#include "userspace/util.h"

#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE (1U << 10)
#endif

#define THE_KEY "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
#define COMM_MAP "comm_channel_ma"
#define REPEAT 100000
#define VALUE_SIZE 64

/* These types should match the ones defined in bpf program */
typedef struct {
	char data[VALUE_SIZE];
} __attribute__((packed)) value_t;

typedef struct {
	char data[32];
} __attribute__((packed)) my_key_t;

int measure_array(int map_fd, struct bpf_map_info *map_info, int64_t *d)
{
	uint64_t begin;
	begin = get_ns();
	int key = 0;
	value_t val;
	for (int i = 0; i < REPEAT; i++) {
		bpf_map_lookup_elem(map_fd, &key, &val);
		if (val.data[0] == 123) {
			INFO("this!\n");
		}
	}
	*d = (get_ns() - begin) / REPEAT;
	return 0;
}

int measure_mmapped_array(int map_fd, struct bpf_map_info *map_info, int64_t *d)
{
	const size_t map_sz = roundup_page((size_t)map_info->value_size * map_info->max_entries);
	void *m = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
	if (m == MAP_FAILED) {
		ERROR("Failed to memory map. size: %ld\n", map_sz);
		return 1;
	}
	const int index = 0;
	const int value_size = sizeof(value_t);
	volatile value_t *val = (value_t *)((uint8_t *)m + (index * value_size));

	uint64_t begin;
	begin = get_ns();
	for (int i = 0; i < REPEAT; i++) {
		if (val->data[0] == 123) {
			INFO("this!\n");
		}
	}
	*d = (get_ns() - begin) / REPEAT;
	return 0;
}

int measure_percpu_array(int map_fd, struct bpf_map_info *map_info, int64_t *d)
{
	uint64_t begin;
	begin = get_ns();
	int key = 0;
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 1) {
		ERROR("Something is wrong\n");
		return 1;
	}
	value_t val[128];
	for (int i = 0; i < REPEAT; i++) {
		bpf_map_lookup_elem(map_fd, &key, &val);
		if (val[0].data[0] == 123) {
			INFO("this!\n");
		}
	}
	*d = (get_ns() - begin) / REPEAT;
	return 0;
}

int measure_hash(int map_fd, struct bpf_map_info *map_info, int64_t *d)
{
	uint64_t begin;
	begin = get_ns();
	my_key_t key;
	memcpy(&key.data, THE_KEY, 32);
	value_t val;
	for (int i = 0; i < REPEAT; i++) {
		bpf_map_lookup_elem(map_fd, &key, &val);
		if (val.data[0] == 123) {
			INFO("this!\n");
		}
	}
	*d = (get_ns() - begin) / REPEAT;
	return 0;
}

int measure_percpu_hash(int map_fd, struct bpf_map_info *map_info, int64_t *d)
{
	uint64_t begin;
	begin = get_ns();
	my_key_t key;
	memcpy(&key.data, THE_KEY, 32);
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 1) {
		ERROR("Something is wrong\n");
		return 1;
	}
	value_t val[128];
	for (int i = 0; i < REPEAT; i++) {
		bpf_map_lookup_elem(map_fd, &key, &val);
		if (val[0].data[0] == 123) {
			INFO("this!\n");
		}
	}
	*d = (get_ns() - begin) / REPEAT;
	return 0;
}

int measure_accessing_map(void)
{
	printf("Expect to find an BPF MAP named %s\n", COMM_MAP);
	int map_fd = find_map(COMM_MAP);
	if (map_fd <= 0) {
		ERROR("Did not found the %s map\n", COMM_MAP);
		return 1;
	}

	struct bpf_map_info map_info = {};
	uint32_t info_size = sizeof(map_info);
	bpf_obj_get_info_by_fd(map_fd, &map_info, &info_size);

	if (map_info.value_size != sizeof(value_t)) {
		ERROR("Map value size does not match value_t!\n");
		return 1;
	}

	char *map_type = "[NOT SET]";
	int64_t duration = 0;
	switch (map_info.type) {
		case BPF_MAP_TYPE_ARRAY:
			if ((map_info.map_flags & BPF_F_MMAPABLE) != 0) {
				map_type = "MMAPABLE ARRAY";
				measure_mmapped_array(map_fd, &map_info, &duration);
			} else {
				map_type = "ARRAY";
				measure_array(map_fd, &map_info, &duration);
			}
			break;
		case BPF_MAP_TYPE_PERCPU_ARRAY:
			map_type = "PERCPU ARRAY";
			measure_percpu_array(map_fd, &map_info, &duration);
			break;
		case BPF_MAP_TYPE_HASH:
			map_type = "HASH";
			measure_hash(map_fd, &map_info, &duration);
			break;
		case BPF_MAP_TYPE_PERCPU_HASH:
			map_type = "PERCPU HASH";
			measure_percpu_hash(map_fd, &map_info, &duration);
			break;
		default:
			ERROR("Unexpected map type: %d\n", map_info.type);
			return 1;
	}
	INFO("Map type: %s\n", map_type);
	INFO("Access time: %ld\n", duration);
	return 0;
}

int main(int argc, char *argv[])
{
	return measure_accessing_map();
}
