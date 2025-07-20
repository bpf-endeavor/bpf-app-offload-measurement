#ifndef DISPATCHER_H
#define DISPATCHER_H
#include "worker.h"
void poll_socket_and_dispatch(struct xsk_socket_info *xsk, struct worker_handle *w);
#endif
