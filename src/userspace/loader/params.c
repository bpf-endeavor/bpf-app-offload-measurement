#include <stdlib.h>
#include <getopt.h>
#include "userspace/log.h"
#include "params.h"

struct context context;

void usage(void)
{
	INFO("Usage: loader [options]\n");
	INFO("Options:\n");
	INFO("  --bpf_bin:  path to bpf binary file\n");
	INFO("  --bpf_prog: name of bpf program to load (can suply multiple)\n"); 
	INFO("  --port:     the destination port (for connection monitor)\n");
}

int parse_args(int argc, char *argv[])
{
	int ret;
	int count_prog = 0;
	enum opts {
		HELP = 100,
		BPF_BIN,
		BPF_PROG,
		DEST_PORT,
	};

	struct option long_opts[] = {
		{"help", no_argument, NULL, HELP},
		{"bpf_bin", required_argument, NULL, BPF_BIN},
		{"bpf_prog", required_argument, NULL, BPF_PROG},
		{"port", required_argument, NULL, DEST_PORT},
		/* End of option list ------------------- */
		{NULL, 0, NULL, 0},
	};


	/* Default values */
	context.port = 8080;
	context.bpf_bin = NULL;

	while(1) {
		ret = getopt_long(argc, argv, "", long_opts, NULL);
		if (ret == -1)
			break;
		switch (ret) {
			case BPF_BIN:
				context.bpf_bin = optarg;
				break;
			case BPF_PROG:
				context.bpf_prog[count_prog] = optarg;
				count_prog++;
				break;
			case DEST_PORT:
				context.port = atoi(optarg);
				break;
			case HELP:
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
