#ifndef PACKET_H
#define PACKET_H
#include <stdint.h>
#include "sockets.h"

struct sized_object {
	void *buffer;
	unsigned size;
};

typedef struct {
	const uint8_t *buffer;
	uint16_t size;
	struct xdp_desc desc;
} request_t;

#endif
