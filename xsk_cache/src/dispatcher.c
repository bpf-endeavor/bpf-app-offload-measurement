#include <stdint.h>
#include "dispatcher.h"
#include "config.h"
#include "worker.h"
#include "sockets.h"
#include "xsk_actions.h"
#include "bmc_tx_path.h"

#define MAX_BATCH_SIZE 128

static int check_worker_has_transmit(struct xsk_socket_info *xsk, worker_t *w)
{
	if (worker_wants_transmit(w)) {
		/* struct xdp_desc desc = get_free_descp(); */
		struct xdp_desc desc = w->req.desc;
		void *buf = xsk_umem__get_data(xsk->umem->buffer, desc.addr);

		// Attach BMC TC path here
		if (config.bmc_enabled) {
			if (bmc_tx_filter_main(w->resp.buffer, w->resp.size)) {
				ERROR("failed in bmc tx path\n");
			}
		}

		/* DEBUG("send reply: size=%d\n", w->resp.size); */

		memcpy(buf, w->resp.buffer, w->resp.size);
		desc.len = w->resp.size;
		do_tx(xsk, &desc);
		worker_serviced(w);
		return 1;
	}
	if (worker_wants_drop(w)) {
		do_drop(xsk, &w->req.desc);
		worker_serviced(w);
		return 1;
	}
	return 0;
}

void poll_socket_and_dispatch(struct xsk_socket_info *xsk,
		struct worker_handle *workers)
{
	const uint32_t count_worker = config.worker_threads;
	const uint32_t cnt = config.batch_size;
	struct xdp_desc batch[MAX_BATCH_SIZE];
	memset(batch, 0, sizeof(batch));

	while(!config.terminate) {
		for (uint32_t k = 0; k < count_worker; k++)
			check_worker_has_transmit(xsk, &workers[k]);

		if (xsk->outstanding_tx > 0) {
			__builtin_prefetch(xsk->umem);
			complete_tx(xsk);
		}

		__builtin_prefetch(xsk);
		const uint32_t rx = poll_rx_queue(xsk, batch, cnt);
		if (!rx) {
			continue;
		}
		/* DEBUG("received %d requests\n", rx); */

#ifdef DBG_CHECK_INCOMING_PKTS
		for (uint32_t i = 0; i < rx; i++) {
			const uint64_t addr = batch[i].addr;
			const size_t ctx_len = batch[i].len;
			/* DEBUG("addr: %ld (%ld)- %ld\n", addr, xsk_umem__add_offset_to_addr(addr), ctx_len); */
			void *const ctx = xsk_umem__get_data(xsk->umem->buffer, addr);
			if (check_is_for_this_server(ctx) != 0) {
				pkt_batch.rets[i] = DROP;
				/* terminated before the first stage */
				yield_state[i] = 0; // Ignore processing of this program
			}
		}
#endif

		uint32_t dispatched = 0;
		while (dispatched < rx) {
			// busy check to find an idle worker
			for (uint32_t k = 0; k < count_worker; k++) {
				/* DEBUG("checking worker %d\n", k); */
				worker_t *w = &workers[k];
				if (!worker_is_idle(w)) {
					if (!check_worker_has_transmit(xsk, w)) {
						continue;
					}
				}

				/* DEBUG("found an idle worker ...\n"); */
				request_t req;
				req.desc = batch[dispatched];
				req.size = req.desc.len;
				req.buffer = xsk_umem__get_data(xsk->umem->buffer, req.desc.addr);
				if (submit_work(w, &req) < 0) {
					ERROR("Failed to submit work!");
				}
				dispatched++;
				if (!(dispatched < rx))
					goto out;
			}
		}

out:
		release_rx_queue(xsk, rx);
	}
}
