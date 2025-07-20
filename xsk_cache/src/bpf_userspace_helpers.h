#pragma once
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/*
 * Find a map by name. Search the global list of BPF maps.
 * */
static int find_map_by_name(char *name)
{
	struct bpf_map_info map_info = {};
	uint32_t info_size = sizeof(map_info);
	unsigned int id = 0;
	int ret = 0;

	while (!ret) {
		ret = bpf_map_get_next_id(id, &id);
		if (ret) {
			if (errno == ENOENT)
				break;
			printf("can't get next map: %s%s\n", strerror(errno),
				errno == EINVAL ? " -- kernel too old?" : "");
			break;
		}
		int map_fd = bpf_map_get_fd_by_id(id);
		bpf_obj_get_info_by_fd(map_fd, &map_info, &info_size);
		/* Compare the found map's name with our list of names */
		if (!strcmp(map_info.name, name)) {
			return map_fd;
		}
		/* This is not our map */
		close(map_fd);
	}
	return -1;
}
