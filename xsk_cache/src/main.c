#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>
#include <sys/eventfd.h>

#include <linux/if_link.h> // some XDP flags

#include "log.h"
#include "config.h"
#include "sockets.h"
#include "worker.h"
#include "dispatcher.h"
#include "bmc_tx_path.h"

static void int_exit(int s) {
	config.terminate = 1;
}

static void set_rlimit(void)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		ERROR("setrlimit(RLIMIT_MEMLOCK) \"%s\"\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static void listen_to_signals(void)
{
	// Add interrupt handler
	signal(SIGINT,  int_exit);
	signal(SIGTERM, int_exit);
}

static int set_core_affinity(void)
{
	/* Set program core affinity */
	if (config.core >= 0)  {
		cpu_set_t cpuset;
		CPU_ZERO(&cpuset);
		CPU_SET(config.core, &cpuset);
		int ret = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
				&cpuset);
		if (ret) {
			ERROR("Failed to set cpu affinity\n");
			return -1;
		}
		INFO("Core affinity set to %d\n", config.core);
	}
	return 0;
}

static int launch_workers(struct worker_handle *workers)
{
	assert(config.worker_threads < MAX_THREADS);
	for (int i = 0; i < config.worker_threads; i++) {
		struct worker_handle *w = &workers[i];
		w->wakeup_fd = eventfd(0, 0);
		if (w->wakeup_fd == -1) {
			ERROR ("failed to create a eventfd: %s", strerror(errno));
			return -1;
		}
		w->status_ = IDLE;
		int ret = pthread_create(&w->thread_, NULL, worker_main, w);
		if (ret != 0) {
			ERROR("Failed to launch a thread\n");
			return -1;
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	parse_args(argc, argv);
	set_rlimit();
	if (set_core_affinity() != 0)
		return EXIT_FAILURE;

	// If needed load custom XDP prog
	if (config.custom_kern_prog && config.custom_kern_path[0] != '-') {
		load_xdp_program(config.custom_kern_path, config.ifindex);
	}
	struct xsk_socket_info *xsk = setup_socket(config.ifname, config.qid);
	if (!xsk) {
		ERROR("Failed to create AF_XDP socket\n");
		goto teardown;
	}

	if (config.custom_kern_prog) {
		// enter XSK to the map for receiving traffic
		int ret = enter_xsks_into_map(xsk, config.qid);
		if (ret) {
			goto teardown;
		}
	}

	if (config.bmc_enabled) {
		if (bmc_initilize() != 0) {
			ERROR("failed to initialize bmc\n");
			goto teardown;
		}
	}

	//
	struct worker_handle workers[MAX_THREADS];
	memset(workers, 0, sizeof(workers));
	if (launch_workers(workers) != 0) {
		goto teardown;
	}

	listen_to_signals();
	poll_socket_and_dispatch(xsk, workers);

teardown:
	config.terminate = 1; // stop workers
	if (config.custom_kern_prog && config.custom_kern_path[0] != '-') {
		// Remove XDP program
		int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | config.xdp_mode;

#ifdef __LIBXDP
		bpf_xdp_attach(config.ifindex, -1, xdp_flags, NULL);
#else
		bpf_set_link_xdp_fd(config.ifindex, -1, xdp_flags);
#endif
		INFO("Unlinked XDP program\n");
	}
	tear_down_socket(xsk);
	INFO("Done!\n");
	return 0;
}
