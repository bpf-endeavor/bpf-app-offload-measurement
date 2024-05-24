#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h> // XDP_FLAGS_*
#include <net/if.h> /* if_nametoindex */

#include "userspace/log.h"
#include "params.h"

#include "sockops_shared.h"

#define SOCK_MAP_NAME "sock_map"
#define CONNECTION_MONITOR_CONF_MAP_NAME  "conn_monitor_config_map"
#define SOCKOPS_NAME "monitor_connections"
#define SK_SKB_PARSER_NAME "parser"
#define BENCHMARK_ARG_MAP_NAME "arg_map"
#define XDP_PROG_NAME "xdp_prog"

static int running = 1;

static void handle_int(int sig)
{
	running = 0;
}

static int configure_connection_monitor(int map_fd)
{
	const int zero = 0;
	struct conn_monitor_config conf;
	conf.listen_ip = 0x00;
	conf.port = htons(context.port);
	return bpf_map_update_elem(map_fd, &zero, &conf, BPF_ANY);
}

static int configure_bpf_benchmark(int map_fd)
{
	const int zero = 0;
	char *file_name = basename(context.bpf_bin);
	INFO("benchmark bpf file: %s\n", file_name);
	/* TODO: how am I going to support different benchmark arguments ? */
	if (strcmp(file_name, "bpf_inst.o") == 0) {
		/* TODO: this struct should be same as the one in the BPF source code  */
		struct arg {
			int inst_count;
		} arg;

		/* Get arguments from user */
		INFO("Arguments for bpf_inst benchmakr:\n");
		INFO("insts (uint32): ");
		fflush(stdout);
		scanf("%d", &arg.inst_count);
		INFO("--------------------------\n");
		INFO("Summary:\n");
		INFO("insts: %d\n", arg.inst_count);
		INFO("\n");
		return bpf_map_update_elem(map_fd, &zero, &arg, BPF_ANY);
	} else if (strcmp(file_name, "bpf_summarize.o") == 0) {
		/* TODO: this struct should be same as the one in the BPF source code  */
		struct arg {
			int summary_size;
			int inst_count;
		} arg;

		/* Get arguments from user */
		INFO("Arguments for bpf_inst benchmakr:\n");
		INFO("insts (uint32): ");
		fflush(stdout);
		scanf("%d", &arg.inst_count);
		INFO("summary size (uint32): ");
		fflush(stdout);
		scanf("%d", &arg.summary_size);
		INFO("--------------------------\n");
		INFO("Summary:\n");
		INFO("insts: %d\n", arg.inst_count);
		INFO("summary size: %d\n", arg.summary_size);
		INFO("\n");
		return bpf_map_update_elem(map_fd, &zero, &arg, BPF_ANY);
	} else if (strcmp(file_name, "bpf_boundcheck_overhead.o") == 0) {
		/* TODO: this struct should be same as the one in the BPF source code  */
		struct arg {
			int inst_count;
		} arg;

		/* Get arguments from user */
		INFO("Arguments for bpf_boundcheck_overhead benchmakr:\n");
		INFO("insts (int): ");
		fflush(stdout);
		scanf("%d", &arg.inst_count);
		INFO("--------------------------\n");
		INFO("Summary:\n");
		INFO("insts: %d\n", arg.inst_count);
		INFO("\n");
		return bpf_map_update_elem(map_fd, &zero, &arg, BPF_ANY);
	}
	/* Nothing to configure */
	INFO("No benchmark argument configuration\n");
	return 0;
}

struct sk_skb_progs {
	struct bpf_program *parser;
	struct bpf_program *verdict;
	struct bpf_program *sockops;

	struct bpf_program *bind4;
	struct bpf_program *sock_release;
};

static struct {
	struct sk_skb_progs progs;
	int sockmap_fd;
} sk_skb_ctx;

static struct {
	struct bpf_tc_hook tc_hook;
} tc_ctx;

/* static unsigned int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE; */

int load_sk_skb(struct bpf_object *bpfobj, struct attach_request *bpf_req)
{
	int ret;
	int map_fd;
	struct bpf_map *map_obj;
	struct sk_skb_progs progs;

	progs.parser = bpf_object__find_program_by_name(bpfobj, SK_SKB_PARSER_NAME);
	if (!progs.parser) {
		WARN("Failed to find sk_skb parser program\n");
		/* goto unload; */
	}

	progs.verdict = bpf_object__find_program_by_name(bpfobj, bpf_req->prog_name);
	if (!progs.verdict) {
		ERROR("Failed to find verdict (%s)\n", bpf_req->prog_name);
		goto unload;
	}

	progs.sockops = bpf_object__find_program_by_name(bpfobj, SOCKOPS_NAME);
	if (!progs.sockops) {
		WARN("Failed to find sockops program\n");
		goto no_sockops;
	}

	/* Configure the connection monitor */
	map_obj = bpf_object__find_map_by_name(bpfobj,
			CONNECTION_MONITOR_CONF_MAP_NAME);
	if (!map_obj) {
		ERROR("Failed to find the connection monitor config map\n");
		goto unload;
	}
	map_fd = bpf_map__fd(map_obj);
	ret = configure_connection_monitor(map_fd);
	if (ret) {
		ERROR("Failed to update the connection monitor config\n");
		goto unload;
	}

no_sockops:

	/* Get sock_map for attaching programs */
	map_obj = bpf_object__find_map_by_name(bpfobj, SOCK_MAP_NAME);
	if (!map_obj) {
		WARN("Failed to find the sock_map!\n");
		INFO("Creating a SOCKMAP for attaching programs.\n");
		map_fd = bpf_map_create(BPF_MAP_TYPE_SOCKMAP, "sock_map",
				4, 8, 10240, NULL);
		if (map_fd < 1) {
			ERROR("Failed to create a SOCKMAP!\n");
			goto unload;
		}
	} else {
		map_fd = bpf_map__fd(map_obj);
	}


	/* Pin sockmap */
	if (bpf_obj_pin(map_fd, SOCKMAP_PINNED_PATH) != 0) {
		ERROR("Failed to pin sockmap (%s)\n", strerror(errno));
		goto unload2;
	}

	/* Attach loaded programs */
	if (progs.parser != NULL) {
		ret = bpf_prog_attach(bpf_program__fd(progs.parser), map_fd,
				BPF_SK_SKB_STREAM_PARSER, 0);
		if (ret) {
			ERROR("Failed to attach parser\n");
			goto unload2;
		}
	}

	ret = bpf_prog_attach(bpf_program__fd(progs.verdict), map_fd,
			BPF_SK_SKB_STREAM_VERDICT, 0);
	if (ret) {
		ERROR("Failed to attach verdict\n");
		goto unload2;
	}

	if (progs.sockops) {
		/* Sockops could be optional */
		ret = bpf_prog_attach(bpf_program__fd(progs.sockops),
				context.cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
		if (ret) {
			ERROR("Failed to attach sockops\n");
			goto unload2;
		}
	}

	sk_skb_ctx.progs = progs;
	sk_skb_ctx.sockmap_fd = map_fd;

	return 0;
unload2:
	unlink(SOCKMAP_PINNED_PATH);
unload:
	/* Should unload the eBPF objects */
	bpf_object__close(bpfobj);
	return 1;
}

void detach_sk_skb(void)
{
	struct sk_skb_progs progs = sk_skb_ctx.progs;
	int map_fd = sk_skb_ctx.sockmap_fd;
	unlink(SOCKMAP_PINNED_PATH);
	bpf_prog_detach2(bpf_program__fd(progs.sockops), context.cgroup_fd, BPF_CGROUP_SOCK_OPS);
	bpf_prog_detach2(bpf_program__fd(progs.parser), map_fd, BPF_SK_SKB_STREAM_PARSER);
	bpf_prog_detach2(bpf_program__fd(progs.verdict), map_fd, BPF_SK_SKB_STREAM_VERDICT);
}

int load_xdp(struct bpf_object *bpfobj, struct attach_request *bpf_req,
		uint32_t xdp_flags)
{
	/* Attach XDP program */
	struct bpf_program *prog = bpf_object__find_program_by_name(bpfobj,
			bpf_req->prog_name);
	if (!prog) {
		ERROR("Failed to find xdp program (%s)\n", bpf_req->prog_name);
		return 1;
	}

	int prog_fd = bpf_program__fd(prog);
	if (bpf_xdp_attach(bpf_req->ifindex, prog_fd, xdp_flags, NULL) != 0) {
		DEBUG("if: %d prog fd: %d\n", bpf_req->ifindex, prog_fd);
		ERROR("Failed to attach XDP program! %s\n", strerror(errno));
		return 1;
	}
	return 0;
}

void detach_xdp(struct attach_request *bpf_req, uint32_t xdp_flags)
{
	bpf_xdp_detach(bpf_req->ifindex, xdp_flags, NULL);
}

int load_tc(struct bpf_object *bpfobj, struct attach_request *bpf_req)
{
	int ret;
	int prog_fd;
	struct bpf_program *prog;

	/* Create the TC hook */
	tc_ctx.tc_hook = (struct bpf_tc_hook) {
		.sz = sizeof(struct bpf_tc_hook),
		.ifindex = bpf_req->ifindex,
		.attach_point = BPF_TC_INGRESS,
		.parent = 0,
	};
	if (bpf_tc_hook_create(&tc_ctx.tc_hook) != 0) {
		/* Maybe the hook already exists. Let's try to delete it and
		 * recreate it
		 * */
		tc_ctx.tc_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		ret = bpf_tc_hook_destroy(&tc_ctx.tc_hook);

		tc_ctx.tc_hook.attach_point = BPF_TC_INGRESS;
		ret = bpf_tc_hook_create(&tc_ctx.tc_hook);
		if (ret != 0) {
			/* Really failed */
			ERROR("Failed to create the TC hook\n");
			return 1;
		}
	}

	/* Attach TC program */
	prog = bpf_object__find_program_by_name(bpfobj, bpf_req->prog_name);
	if (!prog) {
		ERROR("Failed to find the program %s\n", bpf_req->prog_name);
		return 1;
	}
	prog_fd = bpf_program__fd(prog);
	struct bpf_tc_opts tc_opts;
	memset(&tc_opts, 0, sizeof(tc_opts));
	tc_opts = (struct bpf_tc_opts) {
		.sz = sizeof(struct bpf_tc_opts),
		.prog_fd = prog_fd,
		.flags = 0,
		.prog_id = 0,
		.handle = 1,
		.priority = 1,
	};
	if (bpf_tc_attach(&tc_ctx.tc_hook, &tc_opts) != 0) {
		ERROR("Failed to attach TC program!\n");
		goto err;
	}

	return 0;
err:
	/* Destroy TC hook */
	tc_ctx.tc_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
	bpf_tc_hook_destroy(&tc_ctx.tc_hook);
	return 1;
}

void detach_tc(void)
{
	struct bpf_tc_opts tc_opts = {
		.sz = sizeof(struct bpf_tc_opts),
		.prog_fd = 0,
		.flags = 0,
		.prog_id = 0,
		.handle = 1,
		.priority = 1,
	};
	if (bpf_tc_detach(&tc_ctx.tc_hook, &tc_opts)!= 0)
		ERROR("Failed to detach TC program\n");

	tc_ctx.tc_hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
	bpf_tc_hook_destroy(&tc_ctx.tc_hook);
}

int main(int argc, char *argv[])
{
	int ret;
	int i;
	struct bpf_object *bpfobj;
	struct attach_request *bpf_req;
	uint32_t xdp_flags = 0;

	if (parse_args(argc, argv) != 0) {
		return EXIT_FAILURE;
	}

	/* The goal is to load a SK_SKB eBPF program.  The program has a
	 * `monitor_connections` function (sockops program), a `parser`
	 * function and a SK_SKB_VERDICT function which name is given in the
	 * arguments (--bpf_prog). There should exist a `sock_map` to which
	 * SK_SKB programs are attached. The `sockops` will be attached to the
	 * default cgroup.
	 */

	/* Open eBPF binary file */
	bpfobj = bpf_object__open_file(context.bpf_bin, NULL);
	if (!bpfobj) {
		ERROR("Failed to open the BPF binary!\n    %s\n",
				context.bpf_bin);
		return EXIT_FAILURE;
	}

	/* Load all the BPF object to the kernel */
	ret = bpf_object__load(bpfobj);
	if (ret) {
		ERROR("Failed to load the BPF binary to the kernel\n");
		return EXIT_FAILURE;
	}

	/* Configure the benchmark */
	struct bpf_map *map_obj;
	int map_fd;
	map_obj = bpf_object__find_map_by_name(bpfobj, BENCHMARK_ARG_MAP_NAME);
	if (!map_obj) {
		WARN("Failed to find the benchmark specific argument map\n");
		goto ignore_arg_map;
	}
	map_fd = bpf_map__fd(map_obj);
	ret = configure_bpf_benchmark(map_fd);
	if (ret) {
		ERROR("Failed to configure the benchmark\n");
		goto unload_in_main_func;
	}

ignore_arg_map:
	/* /1* Configure devmap *1/ */
	/* /1* TODO: this is hardcoded for a specific experiment make it general if */
	/*  * really needed *1/ */
	/* map_obj = bpf_object__find_map_by_name(bpfobj, "devmap"); */
	/* if (!map_obj) { */
	/* 	WARN("Failed to find the device map for redirecting\n"); */
	/* 	goto ignore_devmap_map; */
	/* } */
	/* map_fd = bpf_map__fd(map_obj); */
	/* const int zero = 0; */
	/* int other_ifindex = if_nametoindex("enp1s0"); */
	/* if (other_ifindex <= 0) { */
	/* 	ERROR("Error finding the other interface\n"); */
	/* 	goto ignore_devmap_map; */
	/* } */
	/* bpf_map_update_elem(map_fd, &zero, &other_ifindex, BPF_NOEXIST); */
	/* INFO("Add enp1s0 to the devmap!\n"); */

/* ignore_devmap_map: */
	for (i = 0; i < context.count_prog; i++) {
		bpf_req = &context.bpf_prog[i];
		switch(bpf_req->bpf_hook) {
			case SK_SKB:
				if (load_sk_skb(bpfobj, bpf_req) != 0)
					return EXIT_FAILURE;
				break;
			case XDP:
				xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
				if (load_xdp(bpfobj, bpf_req, xdp_flags) != 0)
					return EXIT_FAILURE;
				break;
			case GXDP:
				xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
				if (load_xdp(bpfobj, bpf_req, xdp_flags) != 0)
					return EXIT_FAILURE;
				break;
			case TC:
				if (load_tc(bpfobj, bpf_req) != 0)
					return EXIT_FAILURE;
				break;
			default:
				ERROR("Unexpected value!");
				return EXIT_FAILURE;
		}
	}

	/* Wait for the user to SIGNAL the program */
	signal(SIGINT, handle_int);
	signal(SIGHUP, handle_int);
	INFO("Ready!\n");
	INFO("Hit Ctrl+C to \n");
	while (running) {
		sleep(3);
	}

	/* Deattach programs */
	for (i = 0; i < context.count_prog; i++) {
		bpf_req = &context.bpf_prog[i];
		switch(bpf_req->bpf_hook) {
			case SK_SKB:
				detach_sk_skb();
				break;
			case XDP:
				xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
				detach_xdp(bpf_req, xdp_flags);
				break;
			case GXDP:
				xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
				detach_xdp(bpf_req, xdp_flags);
				break;
			case TC:
				detach_tc();
				break;
			default:
				ERROR("Unexpected value!");
				return EXIT_FAILURE;
		}
	}

unload_in_main_func:
	bpf_object__close(bpfobj);

	INFO("Done!\n");
	return 0;
}
