/* SPDX-License-Identifier: ISC */

/*
 * The six Thread seams the core calls, and the five more matter_commission.c
 * calls, for an image built without Thread (CONFIG_TINYMATTER_THREAD=n).
 *
 * Same functions and return codes as tests/host/test_matter_thread_stub.c, with
 * the answers matter_thread.h gives for a node that has no network to join: the
 * stack cannot be started, the node is never attached, there is nothing to
 * clear and nothing to withdraw. A commissioner that sends a Thread dataset is
 * told the network could not be brought up rather than left waiting.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <tinymatter/matter_status.h>
#include <tinymatter/matter_thread.h>

int matter_thread_start(const uint8_t *dataset, size_t len)
{
	(void)dataset;
	(void)len;
	return MATTER_E_STATE;
}

int matter_thread_clear(void)
{
	return MATTER_OK;
}

bool matter_thread_attached_to(const uint8_t *xpanid)
{
	(void)xpanid;
	return false;
}

int matter_thread_wait_attached(uint32_t timeout_ms)
{
	(void)timeout_ms;
	return MATTER_E_TIMEOUT;
}

int matter_thread_advertise(const char *instance_name, uint16_t port)
{
	(void)instance_name;
	(void)port;
	return MATTER_E_STATE;
}

int matter_thread_unadvertise(const char *instance_name)
{
	(void)instance_name;
	return MATTER_OK;
}

int matter_thread_advertise_commissionable(uint16_t discriminator, uint16_t port)
{
	(void)discriminator;
	(void)port;
	return MATTER_E_STATE;
}

int matter_thread_unadvertise_commissionable(void)
{
	return MATTER_OK;
}

int matter_thread_dump_active_dataset(void)
{
	return MATTER_OK;
}

void matter_thread_peer_current(struct matter_thread_peer *out)
{
	if (out != NULL) {
		memset(out, 0, sizeof(*out));
	}
}

int matter_thread_send_to(const struct matter_thread_peer *peer, const uint8_t *msg, size_t len)
{
	(void)peer;
	(void)msg;
	(void)len;
	return MATTER_E_STATE;
}
