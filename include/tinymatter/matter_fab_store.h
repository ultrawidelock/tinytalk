/* SPDX-License-Identifier: ISC */

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

#include <tinymatter/matter_clusters.h>

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

/**
 * Write the Door Lock attribute a controller sets and expects to read back:
 * AutoRelockTime.
 *
 * Only what CHANGED is written, which is why the previous value is asked
 * for: a controller re-writing a value it already set should cost no flash.
 * Call after a successful attribute write.
 *
 * @return 0; `-EINVAL` for an invalid request; or the first negative
 *         tm_kv_result from the backend. A failure is not fatal --
 *         the RAM value stands for this boot.
 */
int matter_dl_attr_store(const struct matter_device_info *info, uint32_t prev_auto_relock_s);

/**
 * Write LockState, so the bolt and what the controller reads come back after a
 * reboot as they were. Like AutoRelockTime it is not part of the operational
 * identity, and it survives fabric removal: the bolt does not move when a
 * controller leaves.
 *
 * @return 0, or a negative tm_kv_result from the backend.
 */
int matter_dl_lock_state_store(uint8_t lock_state);

/**
 * Read it back over whatever the port initialised it to.
 *
 * A field with nothing stored is LEFT ALONE rather than zeroed, because zero is
 * a legal value and the caller's boot default is the better answer.
 *
 * @return 0, or `-EINVAL` when @p info is NULL. Backend failures leave the
 *         caller's defaults untouched and are deliberately not returned.
 */
int matter_dl_attr_load(struct matter_device_info *info);

/**
 * Forget it, so the next boot uses the port's defaults.
 *
 * @return 0 when the key is absent or removed, or the first negative
 *         tm_kv_result from the backend.
 */
int matter_dl_attr_erase(void);

#endif /* MATTER_FAB_STORE_H */
