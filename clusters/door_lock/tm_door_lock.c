/* SPDX-License-Identifier: ISC */

/*
 * See tm_door_lock.h. One Door Lock per node: the state is this file's.
 */
#include <tinymatter/tm_door_lock.h>

#include <string.h>

#include <tinymatter/matter_im.h>
#include <tinymatter/tm_kv.h>
#include <tinymatter/tm_platform.h>

/*
 * FeatureMap leads, because it is the attribute that decides what the rest
 * mean. The four other globals close the list, and the list includes them
 * because it IS AttributeList: the same array expands a wildcard and answers
 * 0xFFFB, so the two cannot disagree about what this cluster carries.
 */
static const uint32_t k_lock_attrs[] = {
	MATTER_ATTR_FEATURE_MAP,
	MATTER_ATTR_DL_LOCK_STATE,
	MATTER_ATTR_DL_LOCK_TYPE,
	MATTER_ATTR_DL_ACTUATOR_ENABLED,
	MATTER_ATTR_DL_AUTO_RELOCK_TIME,
	MATTER_ATTR_DL_OPERATING_MODE,
	MATTER_ATTR_DL_SUPPORTED_OPERATING_MODES,
	MATTER_ATTR_CLUSTER_REVISION,
	MATTER_ATTR_ATTRIBUTE_LIST,
	MATTER_ATTR_ACCEPTED_CMD_LIST,
	MATTER_ATTR_GENERATED_CMD_LIST,
};

/*
 * AcceptedCommandList / GeneratedCommandList: exactly what lock_invoke()
 * dispatches and what it answers with. An id here that lock_invoke() refuses
 * invites an invoke that earns UNSUPPORTED_COMMAND, so the three must agree.
 */
static const uint32_t k_lock_accepted_cmds[] = {
	MATTER_CMD_DL_LOCK_DOOR,
	MATTER_CMD_DL_UNLOCK_DOOR,
};

/*
 * What LockState reports, and what LockDoor/UnlockDoor change.
 *
 * Zero is not a legal LockState, so it means "never set" and is reported
 * as Locked -- a reader that has been asked nothing is not unlocked.
 * It matters even with no actuator behind it, because a controller draws the
 * tile from it and refuses to send UnlockDoor to something already reporting
 * Unlocked.
 */
static uint8_t s_lock_state;

/*
 * AutoRelockTime, in seconds; 0 means no automatic relock.
 *
 * Implemented because its ABSENCE changes controller behaviour: Apple
 * Home shows an auto-lock timing control for locks that carry this
 * attribute and improvises without it -- observed on hardware as an
 * unrequested LockDoor a few seconds after every UnlockDoor. The node
 * itself enforces nothing here yet: the value is reported and writable
 * so the controller owns the policy.
 */
static uint32_t s_auto_relock_s;

/* What storage holds, so only a change costs a flash write. */
static uint8_t s_saved_lock_state;
static uint32_t s_saved_auto_relock_s;

/* Where init() put this cluster, for a change made locally. */
static uint16_t s_endpoint = MATTER_ENDPOINT_LOCK;

/* The LockOperation blob: type, source, fabric index, then the node id LE. */
#define BLOB_LEN 11u

static uint8_t reported(uint8_t lock_state)
{
	return lock_state == MATTER_DL_LOCK_STATE_UNLOCKED ? MATTER_DL_LOCK_STATE_UNLOCKED
							   : MATTER_DL_LOCK_STATE_LOCKED;
}

uint8_t tm_door_lock_state(void)
{
	return reported(s_lock_state);
}

static void lock_read(const struct tm_req *req, uint32_t attr, struct matter_tlv_writer *w,
		      matter_tlv_tag_t tag)
{
	(void)req;

	switch (attr) {
	case MATTER_ATTR_DL_LOCK_STATE:
		/*
		 * What LockDoor/UnlockDoor last set, because a controller that
		 * sends UnlockDoor and then reads Locked has been told its
		 * command did nothing.
		 */
		(void)matter_tlv_put_u64(w, tag, reported(s_lock_state));
		return;
	case MATTER_ATTR_DL_LOCK_TYPE:
		/* 0x00 is DeadBolt (DoorLock/Enums.h, DlLockType). */
		(void)matter_tlv_put_u64(w, tag, 0u);
		return;
	case MATTER_ATTR_DL_ACTUATOR_ENABLED:
		/*
		 * False. There IS no actuator on this board, and claiming one
		 * would invite a Lock/Unlock command this endpoint cannot
		 * honour.
		 */
		(void)matter_tlv_put_bool(w, tag, false);
		return;
	case MATTER_ATTR_DL_AUTO_RELOCK_TIME:
		/* Whatever the controller last wrote; 0 (never set) = no
		 * automatic relock. Reported so the controller shows its
		 * timing UI instead of improvising a relock of its own. */
		(void)matter_tlv_put_u64(w, tag, s_auto_relock_s);
		return;
	case MATTER_ATTR_DL_OPERATING_MODE:
		(void)matter_tlv_put_u64(w, tag, MATTER_DL_OPERATING_MODE_NORMAL);
		return;
	case MATTER_ATTR_DL_SUPPORTED_OPERATING_MODES:
		(void)matter_tlv_put_u64(w, tag, MATTER_DL_SUPPORTED_OPERATING_MODES);
		return;
	default:
		return;
	}
}

static uint8_t lock_write(const struct tm_req *req, uint32_t attr, const uint8_t *tlv, size_t len)
{
	struct matter_tlv_reader r;
	uint64_t v = 0u;

	if (attr != MATTER_ATTR_DL_AUTO_RELOCK_TIME) {
		return MATTER_IM_STATUS_UNSUPPORTED_WRITE;
	}
	if (tlv == NULL || len == 0u) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	matter_tlv_reader_init(&r, tlv, len);
	if (matter_tlv_next(&r) != 0 || matter_tlv_get_u64(&r, &v) != 0) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	/* uint32 per the cluster spec; a wider value is the controller's
	 * error, not something to truncate. */
	if (v > 0xFFFFFFFFu) {
		return MATTER_IM_STATUS_CONSTRAINT_ERROR;
	}
	s_auto_relock_s = (uint32_t)v;
	tm_attr_changed(req->endpoint, MATTER_CLUSTER_DOOR_LOCK, MATTER_ATTR_DL_AUTO_RELOCK_TIME);
	return MATTER_IM_STATUS_SUCCESS;
}

/*
 * Record a LockOperation event, to be carried by the next report. After the
 * state has changed, not before: the event says what happened.
 *
 * @p fabric_index is the fabric that asked, or 0 when none did -- reported as
 * null, together with @p source_node, because an automatic relock has no
 * fabric and claiming one would name the wrong controller.
 */
static void record(uint16_t endpoint, uint8_t operation, uint8_t source, uint8_t fabric_index,
		   uint64_t source_node)
{
	uint8_t blob[BLOB_LEN];

	/* Zero is not a legal operational node id, so it doubles as "unknown"
	 * and is reported as null. */
	if (fabric_index == 0u) {
		source_node = 0u;
	}
	blob[0] = operation;
	blob[1] = source;
	blob[2] = fabric_index;
	for (size_t i = 0u; i < 8u; i++) {
		blob[3u + i] = (uint8_t)(source_node >> (8u * i));
	}
	(void)tm_event_emit(endpoint, MATTER_CLUSTER_DOOR_LOCK, MATTER_EVENT_DL_LOCK_OPERATION,
			    MATTER_EVENT_PRIORITY_CRITICAL, blob, sizeof(blob));
}

static uint8_t lock_invoke(const struct tm_req *req, uint32_t cmd, const uint8_t *fields,
			   size_t len, uint32_t *response)
{
	(void)fields;
	(void)len;
	(void)response;

	/*
	 * The tile's two buttons. Answered with a bare status, which is what
	 * DoorLock defines for both -- there is no LockDoorResponse, and
	 * inventing one leaves the controller waiting.
	 *
	 * The optional PINCode field is ignored rather than rejected: this node
	 * advertises no PIN_CREDENTIAL feature, so a controller sends none, and
	 * refusing a command over a field nobody sends would fail every press.
	 */
	s_lock_state = cmd == MATTER_CMD_DL_UNLOCK_DOOR ? MATTER_DL_LOCK_STATE_UNLOCKED
							: MATTER_DL_LOCK_STATE_LOCKED;
	/*
	 * Recorded here rather than by the caller, because this is the only
	 * place that knows the command ran AND which fabric asked. SourceNode is
	 * left unknown: the fabric's own node id is THIS node's -- it would name
	 * the lock as the thing that unlocked the lock. The peer's id is in
	 * req->node_id, unreported until a controller is seen to want it.
	 */
	record(req->endpoint,
	       cmd == MATTER_CMD_DL_UNLOCK_DOOR ? MATTER_DL_LOCK_OP_UNLOCK : MATTER_DL_LOCK_OP_LOCK,
	       MATTER_DL_OP_SOURCE_REMOTE, req->fabric_index, 0u);
	/*
	 * The application is told from here, the one point every controller's
	 * change reaches. In the source project hanging the light off a second
	 * path alone gave a board whose LED ignored the app.
	 */
	tm_door_lock_actuate(s_lock_state);
	/*
	 * The tile reads LockState, not the InvokeResponse. A controller takes
	 * the SUCCESS and then waits for the attribute to be reported on its
	 * subscription before it moves -- so answering the command and stopping
	 * there is a lock that opens and a UI that spins forever.
	 */
	tm_attr_changed(req->endpoint, MATTER_CLUSTER_DOOR_LOCK, MATTER_ATTR_DL_LOCK_STATE);
	return MATTER_IM_STATUS_SUCCESS;
}

/*
 * The LockOperation fields.
 *
 * UserIndex is always null: this node keeps no users. A null nullable says
 * "not known", which is true; a zero would name user slot 0, which is not.
 *
 * The credential list (field 5) is deliberately absent: it is optional, it
 * would carry a credential index this node does not track per operation, and
 * a list invented to fill a field is worse than an absent optional.
 */
static void lock_event(const struct tm_req *req, uint32_t event, const uint8_t *blob,
		       struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	uint64_t source_node = 0u;

	(void)req;
	(void)event;
	for (size_t i = 0u; i < 8u; i++) {
		source_node |= (uint64_t)blob[3u + i] << (8u * i);
	}
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_TYPE), blob[0]);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_SOURCE), blob[1]);
	(void)matter_tlv_put_null(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_USER_INDEX));
	/*
	 * Each nullable stands on its own. A controller command has a fabric and
	 * an unknown node; a change no controller asked for has neither. Naming a
	 * node that did not ask would tell a controller that IT unlocked the door.
	 */
	if (blob[2] != 0u) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_FABRIC_INDEX),
					 blob[2]);
	} else {
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_FABRIC_INDEX));
	}
	if (source_node != 0u) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_SOURCE_NODE),
					 source_node);
	} else {
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(MATTER_DL_LOCK_OP_FIELD_SOURCE_NODE));
	}
	(void)matter_tlv_end_container(w);
}

/*
 * Stored values survive fabric removal: the bolt does not move when a
 * controller leaves. One with nothing stored keeps its boot default, because
 * zero is a legal value and Locked is the better answer for LockState.
 */
static void lock_init(uint16_t endpoint)
{
	uint32_t relock;
	uint8_t lock_state;
	size_t len;

	s_endpoint = endpoint;
	/* Until a stored value says otherwise. The sample's bolt powers up
	 * locked, and 0 (NotFullyLocked) is what a jammed bolt reports. */
	s_lock_state = MATTER_DL_LOCK_STATE_LOCKED;
	len = sizeof(relock);
	if (tm_kv_get(TM_KV_KEY_MATTER_DL_AUTO_RELOCK, &relock, &len) == TM_KV_OK &&
	    len == sizeof(relock)) {
		s_auto_relock_s = relock;
	}
	len = sizeof(lock_state);
	if (tm_kv_get(TM_KV_KEY_MATTER_DL_LOCK_STATE, &lock_state, &len) == TM_KV_OK &&
	    len == sizeof(lock_state)) {
		s_lock_state = lock_state;
	}
	s_saved_lock_state = s_lock_state;
	s_saved_auto_relock_s = s_auto_relock_s;
	tm_door_lock_actuate(reported(s_lock_state));
}

/*
 * Persisted here, on the node's work queue, rather than in the command path
 * on OpenThread's small stack; and outside the lock, because a flash write can
 * wait on a sector erase while the Thread receive path drops every datagram
 * that finds the lock held. A failed write is not fatal: the RAM value stands
 * for this boot, and the next change tries again.
 */
static void lock_changed(uint16_t endpoint)
{
	uint8_t lock_state;
	uint32_t relock;

	(void)endpoint;
	tm_lock();
	lock_state = s_lock_state;
	relock = s_auto_relock_s;
	tm_unlock();
	if (lock_state != s_saved_lock_state &&
	    tm_kv_set(TM_KV_KEY_MATTER_DL_LOCK_STATE, &lock_state, sizeof(lock_state)) == TM_KV_OK) {
		s_saved_lock_state = lock_state;
	}
	if (relock != s_saved_auto_relock_s &&
	    tm_kv_set(TM_KV_KEY_MATTER_DL_AUTO_RELOCK, &relock, sizeof(relock)) == TM_KV_OK) {
		s_saved_auto_relock_s = relock;
	}
}

void tm_door_lock_record(uint8_t operation, uint8_t source, uint8_t fabric_index,
			 uint64_t source_node)
{
	record(s_endpoint, operation, source, fabric_index, source_node);
}

void tm_door_lock_set(uint8_t lock_state, uint8_t source)
{
	tm_lock();
	s_lock_state = reported(lock_state);
	record(s_endpoint,
	       s_lock_state == MATTER_DL_LOCK_STATE_UNLOCKED ? MATTER_DL_LOCK_OP_UNLOCK
							     : MATTER_DL_LOCK_OP_LOCK,
	       source, 0u, 0u);
	tm_attr_changed(s_endpoint, MATTER_CLUSTER_DOOR_LOCK, MATTER_ATTR_DL_LOCK_STATE);
	tm_unlock();
}

int tm_door_lock_erase(void)
{
	static const uint16_t keys[] = {
		TM_KV_KEY_MATTER_DL_AUTO_RELOCK,
		TM_KV_KEY_MATTER_DL_LOCK_STATE,
	};
	int first_err = 0;

	for (size_t i = 0u; i < sizeof(keys) / sizeof(keys[0]); i++) {
		int rc = tm_kv_delete(keys[i]);

		if (rc != TM_KV_OK && rc != TM_KV_NOT_FOUND && first_err == 0) {
			first_err = rc;
		}
	}
	return first_err;
}

const struct tm_cluster tm_door_lock = {
	.id = MATTER_CLUSTER_DOOR_LOCK,
	.attrs = k_lock_attrs,
	.n_attrs = sizeof(k_lock_attrs) / sizeof(k_lock_attrs[0]),
	.accepted = k_lock_accepted_cmds,
	.n_accepted = sizeof(k_lock_accepted_cmds) / sizeof(k_lock_accepted_cmds[0]),
	/* Writes need Administer, as they always have here; the cluster spec
	 * asks only Manage of AutoRelockTime. */
	.write_privilege = MATTER_AC_PRIVILEGE_ADMINISTER,
	.revision = MATTER_DL_CLUSTER_REVISION,
	/* No features: claiming PIN, RFID, schedules or users would commit this
	 * node to the whole credential and schedule surface, none of which it
	 * has. */
	.features = 0u,
	.read = lock_read,
	.write = lock_write,
	.invoke = lock_invoke,
	.event = lock_event,
	.init = lock_init,
	.changed = lock_changed,
};

static const struct tm_cluster *const k_lock_clusters[] = { &tm_door_lock };

const struct tm_endpoint tm_door_lock_endpoint = {
	.id = MATTER_ENDPOINT_LOCK,
	.device_type = MATTER_DEVICE_TYPE_DOOR_LOCK,
	.device_revision = MATTER_DEVICE_TYPE_LOCK_REV,
	.clusters = k_lock_clusters,
	.n_clusters = 1u,
};
