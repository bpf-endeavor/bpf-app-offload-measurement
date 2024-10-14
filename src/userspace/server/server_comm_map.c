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
#define KEY_SIZE 4

/* These types should match the ones defined in bpf program */
typedef struct {
	char data[VALUE_SIZE];
} __attribute__((packed)) value_t;

typedef struct {
	char data[KEY_SIZE];
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
	if (nr_cpus < 1 || nr_cpus > 128) {
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
	memcpy(&key.data, THE_KEY, KEY_SIZE);
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
	memcpy(&key.data, THE_KEY, KEY_SIZE);
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 1 || nr_cpus > 128) {
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

static int64_t _rb_dur = 0;
static int _rb_flag = 0;
int handle_ringbuf_event(void *ctx, void *data, size_t data_sz)
{
	static uint64_t counter = 0;
	static uint64_t begin = 0;
	if (counter == 0) {
		begin = get_ns();
	}
	const value_t *val = data;
	if (val->data[0] == 123) {
		INFO("this!\n");
	}
	counter++;
	if (counter >= REPEAT) {
		int64_t dur = (get_ns() - begin) / REPEAT;
		_rb_dur = dur;
		_rb_flag = 1;
		counter = 0;
	}
	return 0;
}

int measure_ringbuf(int map_fd, struct bpf_map_info *map_info, int64_t *d)
{
	struct ring_buffer *rb = NULL;
	rb = ring_buffer__new(map_fd, handle_ringbuf_event, NULL, NULL);
	if (!rb) {
		ERROR("Failed to create ring buffer\n");
		return 1;
	}

	while (1) {
		int err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			ERROR("Interrupted!\n");
			return 1;
		}
		if (err < 0) {
			ERROR("Error polling ring buffer: %d\n", err);
			break;
		}
		if (_rb_flag == 1) {
			_rb_flag = 0;
			*d = _rb_dur;
			return 0;
		}
	}
	return 0;
}

int measure_accessing_map(void)
{
	printf("Expect to find an BPF MAP named %s\n", COMM_MAP);
	int map_fd = find_map(COMM_MAP);
	if (map_fd <= 0) {
		ERROR("Did not found the `%s` map\n", COMM_MAP);
		return 1;
	}

	struct bpf_map_info map_info = {};
	uint32_t info_size = sizeof(map_info);
	bpf_obj_get_info_by_fd(map_fd, &map_info, &info_size);

	if (map_info.type != BPF_MAP_TYPE_RINGBUF) {
		/* Do not check the value size for the ring buffer. */
		if (map_info.value_size != sizeof(value_t)) {
			ERROR("Map value size does not match value_t! (%d != %d)\n", map_info.value_size, sizeof(value_t));
			return 1;
		}
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
		case BPF_MAP_TYPE_RINGBUF:
			map_type = "RINGBUF";
			measure_ringbuf(map_fd, &map_info, &duration);
			break;
		case BPF_MAP_TYPE_LRU_HASH:
			map_type = "LRU HASH";
			measure_hash(map_fd, &map_info, &duration);
			break;
		case BPF_MAP_TYPE_LRU_PERCPU_HASH:
			map_type = "LRU PERCPU HASH";
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
