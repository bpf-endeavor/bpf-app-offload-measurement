#ifndef _PARAMS_H
#define _PARAMS_H

#define MAX_BPF_PROG 8

struct context {
	char *bpf_bin;
	char *bpf_prog[MAX_BPF_PROG];
	unsigned short count_prog;
	unsigned short port;
	int cgroup_fd;
	int is_xdp;
	int ifindex;
};

extern struct context context;

int parse_args(int argc, char *argv[]);
void usage(void);
#endif
