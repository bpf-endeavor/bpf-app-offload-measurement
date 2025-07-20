#ifndef WORKER_H
#define WORKER_H
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include "packet.h"

enum worker_status {
	IDLE = 0,
	BUSY,
	TRANSMIT,
	DROP,
};

struct worker_handle {
	int wakeup_fd;
	enum worker_status status_;
	request_t req; /* in */
	struct sized_object resp; /* out */
	pthread_t thread_;
};
typedef struct worker_handle worker_t;

void *worker_main(void *);

static inline int submit_work(struct worker_handle *w,
		const request_t *r)
{
	assert(w->status_ == IDLE);
	w->req = *r; // copy descriptor
	w->status_ = BUSY;
	uint64_t poke = 1;
	int ret = write(w->wakeup_fd, &poke, sizeof(uint64_t));
	return ret; // on err -1 , on success number of bytes (8)
}

static inline int worker_is_idle(struct worker_handle *w)
{
	return w->status_ == IDLE;
}

static inline int worker_wants_transmit(worker_t *w)
{
	return w->status_ == TRANSMIT;
}

static inline int worker_wants_drop(worker_t *w)
{
	return w->status_ == DROP;
}

static inline void worker_serviced(worker_t *w)
{
	w->status_ = IDLE;
}
#endif
