/* Native forwarding engine (lwIP user-space TCP/UDP termination + socket relay)
 * with the capture tap at the TUN boundary, and the session wrapper that
 * orders start/stop of forwarder and writer. */
#ifndef MPC_ENGINE_H
#define MPC_ENGINE_H

#include "mpc/capture.h"

typedef struct mpc_session mpc_session;

/* Takes ownership of tun_fd (closed on stop). Starts writer + forwarding threads.
 * Returns NULL on failure with *err set (tun_fd is closed on failure too). */
mpc_session *mpc_session_start(int tun_fd, const mpc_capture_config *cfg, int *err);

/* Ordered, idempotent stop: quiesce capture tap -> tear down forwarding and close
 * TUN -> drain writer, flush, fsync, close file. Returns 0 if the capture file is
 * complete, -1 if a storage error occurred. */
int mpc_session_stop(mpc_session *s);

void mpc_session_destroy(mpc_session *s);

mpc_capture *mpc_session_capture(mpc_session *s);

#endif
