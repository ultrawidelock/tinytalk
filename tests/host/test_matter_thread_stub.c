/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * See test_matter_thread_stub.h.
 */
#include "test_matter_thread_stub.h"

#include <string.h>

#include <tinytalk/matter_thread.h>

uint8_t g_thread_last_dataset[512];
size_t g_thread_last_len;
int g_thread_start_calls;
int g_thread_clear_calls;
int g_thread_wait_calls;
uint32_t g_thread_last_timeout_ms;
int g_thread_start_fail;
int g_thread_clear_fail;
int g_thread_attached;
int g_thread_attached_to;
uint8_t g_thread_attached_to_xpanid[8];
int g_thread_attached_to_calls;
char g_thread_last_instance[64];
uint16_t g_thread_last_port;
int g_thread_advertise_calls;
int g_thread_unadvertise_calls;
char g_thread_last_unadvertised[64];
struct matter_thread_iface g_thread_iface;
struct matter_thread_scan_result g_thread_scan[MATTER_THREAD_SCAN_MAX];
uint8_t g_thread_scan_n;
int g_thread_scan_rc;

void test_matter_thread_stub_reset(void)
{
	memset(g_thread_last_dataset, 0, sizeof(g_thread_last_dataset));
	g_thread_last_len = 0u;
	g_thread_start_calls = 0;
	g_thread_clear_calls = 0;
	g_thread_wait_calls = 0;
	g_thread_last_timeout_ms = 0u;
	g_thread_start_fail = 0;
	g_thread_clear_fail = 0;
	g_thread_attached = 0;
	g_thread_attached_to = 0;
	memset(g_thread_attached_to_xpanid, 0, sizeof(g_thread_attached_to_xpanid));
	g_thread_attached_to_calls = 0;
	memset(g_thread_last_instance, 0, sizeof(g_thread_last_instance));
	g_thread_last_port = 0u;
	g_thread_advertise_calls = 0;
	g_thread_unadvertise_calls = 0;
	memset(g_thread_last_unadvertised, 0, sizeof(g_thread_last_unadvertised));
	memset(&g_thread_iface, 0, sizeof(g_thread_iface));
	memset(g_thread_scan, 0, sizeof(g_thread_scan));
	g_thread_scan_n = 0u;
	g_thread_scan_rc = MATTER_OK;
}

int matter_thread_scan(struct matter_thread_scan_result *out, uint8_t cap, uint8_t *n)
{
	uint8_t k = g_thread_scan_n < cap ? g_thread_scan_n : cap;

	memcpy(out, g_thread_scan, (size_t)k * sizeof(out[0]));
	*n = g_thread_scan_rc == MATTER_OK ? k : 0u;
	return g_thread_scan_rc;
}

int matter_thread_interface(struct matter_thread_iface *out)
{
	*out = g_thread_iface;
	return MATTER_OK;
}

int matter_thread_clear(void)
{
	g_thread_clear_calls++;
	return g_thread_clear_fail ? MATTER_E_STATE : MATTER_OK;
}

int matter_thread_start(const uint8_t *dataset, size_t len)
{
	g_thread_start_calls++;
	if (dataset == NULL || len == 0u || len > sizeof(g_thread_last_dataset)) {
		return MATTER_E_INVAL;
	}
	/* Recorded even when the call is made to fail: what the cluster HANDED
	 * the stack is the thing worth asserting on either way. */
	memcpy(g_thread_last_dataset, dataset, len);
	g_thread_last_len = len;

	return g_thread_start_fail ? MATTER_E_STATE : MATTER_OK;
}

bool matter_thread_attached_to(const uint8_t *xpanid)
{
	g_thread_attached_to_calls++;
	if (xpanid != NULL) {
		memcpy(g_thread_attached_to_xpanid, xpanid, sizeof(g_thread_attached_to_xpanid));
	}

	return g_thread_attached_to != 0;
}

int matter_thread_wait_attached(uint32_t timeout_ms)
{
	g_thread_wait_calls++;
	g_thread_last_timeout_ms = timeout_ms;

	return g_thread_attached ? MATTER_OK : MATTER_E_TIMEOUT;
}

int matter_thread_unadvertise(const char *instance_name)
{
	g_thread_unadvertise_calls++;
	if (instance_name == NULL || strlen(instance_name) >= sizeof(g_thread_last_unadvertised)) {
		return MATTER_E_INVAL;
	}
	strcpy(g_thread_last_unadvertised, instance_name);

	return MATTER_OK;
}

int matter_thread_advertise(const char *instance_name, uint16_t port)
{
	g_thread_advertise_calls++;
	if (instance_name == NULL || strlen(instance_name) >= sizeof(g_thread_last_instance)) {
		return MATTER_E_INVAL;
	}
	strcpy(g_thread_last_instance, instance_name);
	g_thread_last_port = port;

	return MATTER_OK;
}
