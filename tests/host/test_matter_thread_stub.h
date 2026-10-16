/**
 * @file test_matter_thread_stub.h — a Thread stack the suite can steer.
 *
 * There is no radio here, so the two matter_thread.h seams are answered by a
 * double whose verdict a test chooses. What that buys is the case hardware
 * makes expensive to reach: a stack that ACCEPTS the dataset and then never
 * attaches. On a bench that means standing next to a border router and turning
 * it off at the right moment; here it is one assignment.
 */
#ifndef TINYTALK_TEST_MATTER_THREAD_STUB_H
#define TINYTALK_TEST_MATTER_THREAD_STUB_H

#include <stddef.h>
#include <stdint.h>

#include <tinytalk/matter_thread.h>

/** The dataset the last matter_thread_start() was handed. */
extern uint8_t g_thread_last_dataset[512];
extern size_t g_thread_last_len;
extern int g_thread_start_calls;
extern int g_thread_clear_calls;
extern int g_thread_wait_calls;
/** The last timeout matter_thread_wait_attached() was asked to honour. */
extern uint32_t g_thread_last_timeout_ms;

/** Make the next matter_thread_start() refuse the dataset. */
extern int g_thread_start_fail;
extern int g_thread_clear_fail;
/** Make the next matter_thread_wait_attached() report an attach. */
extern int g_thread_attached;

/** Make matter_thread_attached_to() answer "already on that network". The
 *  Extended PAN ID it is asked about is recorded, so a test can prove the
 *  cluster asked about the network it was HANDED and not some stored one. */
extern int g_thread_attached_to;
extern uint8_t g_thread_attached_to_xpanid[8];
extern int g_thread_attached_to_calls;

/** The instance name the last matter_thread_advertise() was asked to publish. */
extern char g_thread_last_instance[64];
extern uint16_t g_thread_last_port;
extern int g_thread_advertise_calls;
/** matter_thread_unadvertise() calls, and the last name withdrawn. */
extern int g_thread_unadvertise_calls;
extern char g_thread_last_unadvertised[64];
/** What matter_thread_interface() reports; zeroed by the reset. */
extern struct matter_thread_iface g_thread_iface;

void test_matter_thread_stub_reset(void);

#endif /* TINYTALK_TEST_MATTER_THREAD_STUB_H */
