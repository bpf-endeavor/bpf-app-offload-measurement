#ifndef _PARAMS_H
#define _PARAMS_H

#define MAX_BPF_PROG 8

enum attach_type {
	SK_SKB,
	XDP,
	TC,
	GXDP,
};

/* Load a program of the given type and attach it to the interface */
struct attach_request {
	char *prog_name;
	enum attach_type bpf_hook;
	int ifindex;
};

struct context {
	char *bpf_bin;
	struct attach_request bpf_prog[MAX_BPF_PROG];
	unsigned short count_prog;
	unsigned short port;
	int cgroup_fd;
};

extern struct context context;

int parse_args(int argc, char *argv[]);
void usage(void);
#endif
