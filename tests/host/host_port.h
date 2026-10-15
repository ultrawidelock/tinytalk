/* SPDX-License-Identifier: ISC */

/* What tests/host/host_port.c records for a test to read back. */
#ifndef TINYTALK_HOST_PORT_H
#define TINYTALK_HOST_PORT_H

#include <stdint.h>

/* The last value tm_door_lock_actuate() was given, and how often. */
extern uint8_t g_host_lock_state;
extern int g_host_lock_state_calls;

#endif /* TINYTALK_HOST_PORT_H */
