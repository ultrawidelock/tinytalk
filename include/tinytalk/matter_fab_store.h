/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * matter_fab_store: the operational identity, across a reboot, over the
 * tm_kv.h store a port provides.
 *
 * Without it every reset silently un-commissions the node: the fabric table is plain RAM, the node comes back
 * advertising commissionable, Thread never starts because nothing replays the
 * dataset, and the Home app shows an accessory that is simply gone.
 */
#ifndef MATTER_FAB_STORE_H
#define MATTER_FAB_STORE_H

#include <tinytalk/matter_clusters.h>

/**
 * Write the operational identity to the persistent key-value store.
 *
 * Call after anything that changes the fabric table or the Thread dataset.
 * Cheap enough to call on every such event and far cheaper than being wrong:
 * the alternative is a node that looks commissioned until it reboots.
 *
 * @return 0; `-EINVAL` for an invalid request; or a negative
 *         tm_kv_result from the storage backend.
 */
int matter_fab_commit(const struct matter_device_info *info,
		      enum matter_fabric_store_operation operation, uint8_t slot,
		      const uint8_t *value, size_t value_len);

/**
 * Read it back into @p info.
 *
 * @return 1 when nothing was stored (never commissioned), 0 when a fabric was
 *         restored, `-EINVAL` when @p info is NULL, or a negative
 *         tm_kv_result on a backend error. A stored record written
 *         by a different firmware layout is DISCARDED rather than trusted --
 *         see the note on the size check in the .c file.
 */
int matter_fab_load(struct matter_device_info *info);

/**
 * Forget it, so the next boot comes up commissionable.
 *
 * @return 0, or a negative tm_kv_result from the backend.
 */
int matter_fab_erase(void);

#endif /* MATTER_FAB_STORE_H */
