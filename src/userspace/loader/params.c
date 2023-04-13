#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h> /* if_nametoindex */
#include "userspace/log.h"
#include "params.h"

struct context context;

void usage(void)
{
	INFO("Usage: loader [options]\n");
	INFO("Options:\n");
	INFO("  --help     -h:  path to bpf binary file\n");
	INFO("  --bpf_bin  -b:  path to bpf binary file\n");
	INFO("  --bpf_prog -p:  name of bpf program to load (can suply multiple)\n"); 
	INFO("  --port     -P:  the destination port (for connection monitor)\n");
	INFO("  --xdp:          load XDP program on given interface\n");
	INFO("  --tc:           load TC program on ingress of given interface\n");
}

static int get_default_cgroup_fd(void)
{
	/* TODO: Get the CGROUP name from the user */
	int fd;
	fd = open("/sys/fs/cgroup/user.slice", O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		fd = open("/sys/fs/cgroup/unified/", O_DIRECTORY | O_RDONLY);
	}
	return fd;
}

int parse_args(int argc, char *argv[])
{
	int ret;
	int count_prog = 0;
	enum opts {
		HELP = 500,
		BPF_BIN,
		BPF_PROG,
		DEST_PORT,
		XDP_FLAG,
		TC_FLAG,
	};

	struct option long_opts[] = {
		{"help",     no_argument,       NULL, HELP},        /* h */
		{"bpf_bin",  required_argument, NULL, BPF_BIN},     /* b */
		{"bpf_prog", required_argument, NULL, BPF_PROG},    /* p */
		{"port",     required_argument, NULL, DEST_PORT},   /* P */
		{"xdp",      required_argument, NULL, XDP_FLAG},
		{"tc",       required_argument, NULL, TC_FLAG},
		/* End of option list ------------------- */
		{NULL, 0, NULL, 0},
	};


	/* Default values */
	context.port = 8080;
	context.bpf_bin = NULL;
	context.cgroup_fd = get_default_cgroup_fd();
	context.bpf_hook = SK_SKB;

	while(1) {
		ret = getopt_long(argc, argv, "hb:p:P:", long_opts, NULL);
		if (ret == -1)
			break;
		switch (ret) {
			case BPF_BIN:
			case 'b':
				context.bpf_bin = optarg;
				break;
			case BPF_PROG:
			case 'p':
				context.bpf_prog[count_prog] = optarg;
				count_prog++;
				break;
			case DEST_PORT:
			case 'P':
				context.port = atoi(optarg);
				break;
			case XDP_FLAG:
				context.bpf_hook = XDP;
				context.ifindex = if_nametoindex(optarg);
				if (context.ifindex == 0) {
					ERROR("Failed to get interface index!\n");
					return 1;
				}
				break;
			case TC_FLAG:
				context.bpf_hook = TC;
				context.ifindex = if_nametoindex(optarg);
				if (context.ifindex == 0) {
					ERROR("Failed to get interface index!\n");
					return 1;
				}
				break;
			case HELP:
			case 'h':
				usage();
				return 1;
			default:
				usage();
				ERROR("Unknown argument '%s'!\n", argv[optind-1]);
				return 1;
		}
	}
	context.count_prog = count_prog;

	if (context.bpf_bin == NULL) {
		ERROR("Should define the path to the BPF binary (--bpf_bin)\n");
		return 1;
	}

	if (count_prog < 1) {
		ERROR("Should provided at least one program (--bpf_prog)\n");
		return 1;
	}
	return 0;
}
