#ifndef _SHARED_CHANNEL_H
#define _SHARED_CHANNEL_H
#include <bpf/libbpf.h> // bpf_get_link_xdp_id
#include <bpf/bpf.h> // bpf_prog_get_fd_by_id, bpf_obj_get_info_by_fd, ...
#include <sys/mman.h> // mmap
#include "util.h" /* roundup_page */
#include "bpf_userspace_shared_header.h" /* struct parsing_ctx */
/* static unsigned int index_ring = 0; */
int ring_map_fd;
void *ring_map_area;
size_t ring_map_value_size;
int get_shared_map(void)
{
	struct bpf_map_info map_info = {};
	uint32_t info_size = sizeof(map_info);
	unsigned int id = 0;
	int ret = 0;
	int map_fd;
	int flag = 0;
	while (!ret) {
		ret = bpf_map_get_next_id(id, &id);
		if (ret) {
			if (errno == ENOENT)
				break;
			printf("can't get next map: %s%s", strerror(errno),
				errno == EINVAL ? " -- kernel too old?" : "");
			break;
		}
		map_fd = bpf_map_get_fd_by_id(id);
		bpf_obj_get_info_by_fd(map_fd, &map_info, &info_size);
		/* Compare the found map's name with our list of names */
		if (!strcmp(map_info.name, "shared_map")) {
			ring_map_fd = map_fd;
			ring_map_value_size = map_info.value_size;

			/* Memory map */
			if (map_info.map_flags & BPF_F_MMAPABLE) {
				const size_t map_sz = roundup_page((size_t)map_info.value_size * map_info.max_entries);
				void *m = mmap(NULL, map_sz, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
				if (m == MAP_FAILED) {
					printf("Failed to memory map 'ebpf MAP' size: %ld\n", map_sz);
					return 1;
				} else {
					ring_map_area = m;
				}
			} else {
				printf("%s %x\n", map_info.name, map_info.map_flags);
				printf("error: ring map is not mmapable\n");
				return 1;
			}

			flag = 1;
			break;
		}
	}

	if (flag) {
		printf("found ring map!\n");
		/* printf("value size: %ld\n", ring_map_value_size); */
		/* for (int i = 0; i < 5 * ring_map_value_size; i++) { */
		/* 	printf("%02x ", ((unsigned char *)ring_map_area)[i]); */
		/* 	if (i % 16 == 15) */
		/* 		printf("\n"); */
		/* } */
		/* printf("\n"); */
		return 0;
	} else {
		printf("warning: did not found the ring map!\n");
		return 1;
	}
}

struct shared_metadata *get_shared_context(unsigned int mark)
{
	struct shared_metadata *elem;

	/* Make sure we are not accessing out of array's range */
	if (mark > RING_SIZE) {
		printf("out of range acess to shared map\n");
		return NULL;
	}

	elem = &ring_map_area[ring_map_value_size * mark];
	if (elem->valid) {
		return elem;
	}
	printf("is not valid (%d)!\n", mark);
	return NULL;
}
#endif
