/* SPDX-License-Identifier: ISC */

/*
 * The Aliro half of the Door Lock cluster, called from tm_door_lock.c for the
 * attributes and commands it does not serve itself. Lock held, as there.
 */
#pragma once

#include <tinytalk/tm_door_lock.h>

void tm_dl_aliro_init(void);
void tm_dl_aliro_read(uint32_t attr, struct matter_tlv_writer *w, matter_tlv_tag_t tag);
uint8_t tm_dl_aliro_invoke(const struct tm_req *req, uint32_t cmd, const uint8_t *fields,
			   size_t len, uint32_t *response);
void tm_dl_aliro_response(const struct tm_req *req, uint32_t response,
			  struct matter_tlv_writer *w, matter_tlv_tag_t tag);
