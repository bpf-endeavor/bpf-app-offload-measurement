#ifndef ARGS_H
#define ARGS_H

#include <stdint.h>
#include <net/if.h> // if_nametoindex

#define DEFAULT_HEADROOM_SIZE 256
#define DEFAULT_FRAME_SIZE 4096
#define DEFAULT_CHUNK_MASK 0xfffffffffffff000 // (~(DEFAULT_FRAME_SIZE - 1))
#define DEFAULT_RING_SIZE 512
#define DEFAULT_BATCH_SIZE 32
#define DEFAULT_BUSYPOLL_DURATION 20
#define MAX_NUM_PROGS 8
#define MAX_NUM_MAPS 10

#define MAX_THREADS 16

struct config {
	int terminate;
	// Ring Configuration
	uint32_t num_frames;
	uint32_t frame_size;
	uint32_t frame_shift;
	uint32_t headroom;
	uint32_t rx_size;
	uint32_t tx_size;
	// Interface Identifier
	uint32_t ifindex;
	char *ifname;
	uint32_t qid;
	// CPU Core
	int core;
	// AF_XDP Configuration
	int busy_poll;
	uint32_t busy_poll_duration;
	uint32_t batch_size;
	int copy_mode;
	// XDP Configuration
	int xdp_mode;
	// uBPF Engine Config
	char *ebpf_program_path;
	uint32_t jitted;
	// Custom Kernel
	int custom_kern_prog;
	char *custom_kern_path;
	// App configs
	int worker_threads;
	int bmc_enabled;
	// Userspace Tx Hook
	int has_uth;
	char *uth_prog_path;
	// Userspace packet injection (Interpose link)
	int use_packet_injection;
	// Map system
	char **maps;
	uint32_t count_maps;
	// Dummy
	int args[1]; // it is weired
	uint32_t tmp;
};

extern struct config config;

void usage(char *prog_name);
void parse_args(int argc, char *argv[]);

#endif
