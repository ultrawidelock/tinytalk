/**
 * @file spakefake.h — arming the recorded SPAKE2+ exchange. See spakefake.c.
 */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Record one responder-side exchange for the curve calls to replay.
 *
 * Every argument is an expectation as much as a value: a later call that does
 * not match is refused and recorded by spakefake_replay_fault().
 *
 * @param y_ws the 40 bytes of entropy the responder was initialised with. The
 *        expected scalar is its reduction, computed here, so the test never has
 *        to know the reduced value and the state machine cannot pass the raw
 *        entropy through by mistake.
 */
void spakefake_replay_arm(const uint8_t w0[32], const uint8_t l[65], const uint8_t y_ws[40],
			  const uint8_t pa[65], const uint8_t pb[65], const uint8_t z[65],
			  const uint8_t v[65]);

/** Forget the recording; every curve call fails until armed again. */
void spakefake_replay_clear(void);

/** @return NULL if no call has been refused, else why the first one was. */
const char *spakefake_replay_fault(void);

/** How many times each primitive has been called since the last arm/clear. */
unsigned spakefake_replay_key_share_calls(void);
unsigned spakefake_replay_zv_calls(void);

#ifdef __cplusplus
}
#endif
