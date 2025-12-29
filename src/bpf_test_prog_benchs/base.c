#include "./commons.h"
SEC("xdp")
int prog(struct xdp_md *xdp)
{
	return XDP_DROP;
}
