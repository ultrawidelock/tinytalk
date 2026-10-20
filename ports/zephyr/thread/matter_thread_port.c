/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file matter_thread_port.c — matter_thread.h on top of Zephyr's OpenThread.
 *
 * The dataset arrives from the commissioner as raw meshcop TLVs and
 * otDatasetSetActiveTlvs() takes raw meshcop TLVs, so nothing here has to
 * understand the format -- which is the point. This node parses exactly one
 * field out of it, the Extended PAN ID, and only so it can name the network
 * back to the commissioner.
 */
#include <tinytalk/matter_thread.h>

/* For MATTER_INSTANCE_NAME_LEN: the SRP instance name is sized by the thing
 * that produces it, matter_fabric_instance_name(). */
#include <tinytalk/matter_case.h>
#include <tinytalk/matter_clusters.h> /* MATTER_SUPPORTED_FABRICS */
#include <tinytalk/matter_fabric.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(matter_thread, CONFIG_TINYTALK_THREAD_LOG_LEVEL);

/* matter_thread_on_datagram(), CASE included, runs on OpenThread's thread. */
BUILD_ASSERT(CONFIG_OPENTHREAD_THREAD_STACK_SIZE >= CONFIG_TINYTALK_THREAD_RX_STACK_SIZE,
	     "OpenThread's thread is smaller than CONFIG_TINYTALK_THREAD_RX_STACK_SIZE");

/* Every call below is either OpenThread's own API or one of the four
 * openthread_*() helpers that the standalone module provides, so the Zephyr
 * L2 was never what this needed. */

#include <openthread.h>
#include <openthread/dataset.h>
#include <openthread/ip6.h>
#include <openthread/link.h>
#include <openthread/srp_client.h>
#include <openthread/thread.h>
#include <openthread/udp.h>

#include <psa/crypto.h>
#include <zephyr/settings/settings.h>

#include <stdio.h>
#include <string.h>

/* Attachment completion is event-driven. The callback runs on OpenThread's
 * thread with its API lock held, so it may only signal this semaphore. */
static K_SEM_DEFINE(s_attach_changed, 0, 1);

/* The parent last logged, so a parent change is logged once. */
static otExtAddress s_logged_parent;
static bool s_have_logged_parent;

/*
 * INF: role and parent changes, on OpenThread's thread with its lock held,
 * which is where its getters may be called. A controller that stops reaching
 * the node is checked against these first.
 */
static void log_role_and_parent(otChangedFlags flags)
{
	otInstance *ot = openthread_get_default_instance();
	otRouterInfo parent;
	otDeviceRole role;

	if (ot == NULL || (flags & (OT_CHANGED_THREAD_ROLE | OT_CHANGED_THREAD_RLOC_ADDED)) == 0u) {
		return;
	}
	role = otThreadGetDeviceRole(ot);
	if ((flags & OT_CHANGED_THREAD_ROLE) != 0u) {
		LOG_INF("Thread role %s, rloc16 0x%04x", otThreadDeviceRoleToString(role),
			(unsigned int)otThreadGetRloc16(ot));
	}
	if (role != OT_DEVICE_ROLE_CHILD || otThreadGetParentInfo(ot, &parent) != OT_ERROR_NONE ||
	    (s_have_logged_parent &&
	     memcmp(&parent.mExtAddress, &s_logged_parent, sizeof(s_logged_parent)) == 0)) {
		return;
	}
	s_logged_parent = parent.mExtAddress;
	s_have_logged_parent = true;
	LOG_INF("Thread parent %02x%02x%02x%02x%02x%02x%02x%02x, rloc16 0x%04x",
		parent.mExtAddress.m8[0], parent.mExtAddress.m8[1], parent.mExtAddress.m8[2],
		parent.mExtAddress.m8[3], parent.mExtAddress.m8[4], parent.mExtAddress.m8[5],
		parent.mExtAddress.m8[6], parent.mExtAddress.m8[7], (unsigned int)parent.mRloc16);
}

static void attach_state_changed(otChangedFlags flags, void *context)
{
	ARG_UNUSED(context);
	log_role_and_parent(flags);
	if ((flags & (OT_CHANGED_THREAD_ROLE | OT_CHANGED_IP6_ADDRESS_ADDED |
		      OT_CHANGED_IP6_ADDRESS_REMOVED | OT_CHANGED_THREAD_NETDATA)) != 0u) {
		k_sem_give(&s_attach_changed);
	}
}

static struct openthread_state_changed_callback s_attach_cb = {
	.otCallback = attach_state_changed,
};

static bool s_attach_cb_registered;

static int attach_callback_ensure(void)
{
	if (s_attach_cb_registered) {
		return MATTER_OK;
	}
	if (openthread_state_changed_callback_register(&s_attach_cb) != 0) {
		LOG_ERR("cannot register Thread attachment notification");
		return MATTER_E_STATE;
	}
	s_attach_cb_registered = true;
	return MATTER_OK;
}

/**
 * A per-lifetime suffix on the SRP host name, and the reason it exists.
 *
 * Name ownership on the border router is first-come BY KEY. The SRP client's
 * ECDSA key lives in OpenThread's settings, a chip erase destroys it, and the
 * next boot then asks for a name the server still holds under the OLD key.
 * That is refused with OT_ERROR_DUPLICATED for as long as the KEY lease runs
 * -- 14 days at OpenThread's default -- and presents as a node that attaches to
 * Thread, never registers, and leaves the commissioner on "Adding to Home"
 * with nothing to say why. The bare EUI-64 is stable across an erase, which is
 * precisely what makes it collide with itself.
 *
 * This value dies in the same erase that takes the key, so a new key always
 * asks for a name nobody owns. The orphaned registration is left to expire on
 * its own: it costs a record on somebody else's server and nothing here.
 *
 * A factory reset that clears all of settings takes the key and this value
 * together.
 */
#define SRP_HOST_ID_KEY "srp/hid"

/**
 * How long to ask the border router to hold the name against this key.
 *
 * OpenThread requests 14 days (OPENTHREAD_CONFIG_SRP_CLIENT_DEFAULT_KEY_LEASE),
 * which is how long a collision lasts if one ever happens anyway. An hour
 * bounds that, and costs a re-registration the client is already doing for the
 * 2-hour service lease. The server clamps this to its own limits and does not
 * report what it settled on, so it is a request, not a guarantee: the suffix
 * above is what PREVENTS a collision, this only shortens one.
 */
#define SRP_KEY_LEASE_S 3600u

/**
 * The commissionable record's lease, shorter than the 2-hour default.
 *
 * It is the one record whose ghost strands a commissioner: a node that loses
 * power, crashes or is reflashed with a window open leaves it on the border
 * router, and Apple Home tries PASE over Thread to the vanished node instead of
 * using BLE, stuck at "Connecting" (2026-10-16). Two minutes bounds that on a
 * server that grants it; Apple's did not, and kept one over 22 min, so the next
 * boot also removes it by name (SRP_COMM_KEY). OpenThread renews a lease under
 * 240 s at half its length, so an open window costs one SRP update a minute.
 */
#define SRP_COMM_LEASE_S 120u

int matter_thread_start(const uint8_t *dataset, size_t len)
{
	otInstance *ot = openthread_get_default_instance();
	otOperationalDatasetTlvs tlvs;
	otError err;

	if (ot == NULL || dataset == NULL || len == 0u || len > sizeof(tlvs.mTlvs)) {
		return MATTER_E_INVAL;
	}

	memcpy(tlvs.mTlvs, dataset, len);
	tlvs.mLength = (uint8_t)len;

	openthread_mutex_lock();
	err = otDatasetSetActiveTlvs(ot, &tlvs);
	openthread_mutex_unlock();
	if (err != OT_ERROR_NONE) {
		LOG_ERR("dataset rejected by OpenThread (%d)", err);
		return MATTER_E_INVAL;
	}
	if (attach_callback_ensure() != MATTER_OK) {
		return MATTER_E_STATE;
	}

	/*
	 * openthread_run() takes the mutex itself, so it must be called with the
	 * lock released. It enables IPv6 and then the Thread interface, which is
	 * when attaching actually begins.
	 */
	if (openthread_run() != 0) {
		LOG_ERR("OpenThread refused to start");
		return MATTER_E_STATE;
	}

	LOG_INF("OpenThread started on the commissioner's dataset (%u B)", (unsigned int)len);
	return MATTER_OK;
}

/**
 * Whether this node is already attached to the network @p xpanid names.
 * See matter_thread.h for why this exists.
 */
int matter_thread_clear(void)
{
	otInstance *ot = openthread_get_default_instance();
	otOperationalDatasetTlvs empty = { 0 };
	otError thread_err;
	otError dataset_err;

	if (ot == NULL) {
		return MATTER_E_STATE;
	}

	/* Release SRP's references before disabling the interface it uses. */
	matter_thread_advertise_reset();
	openthread_mutex_lock();
	thread_err = otThreadSetEnabled(ot, false);
	dataset_err = otDatasetSetActiveTlvs(ot, &empty);
	openthread_mutex_unlock();

	if (thread_err != OT_ERROR_NONE || dataset_err != OT_ERROR_NONE) {
		LOG_ERR("failed to clear Thread state (%d, %d)", thread_err, dataset_err);
		return MATTER_E_STATE;
	}
	return MATTER_OK;
}

bool matter_thread_attached_to(const uint8_t *xpanid)
{
	otInstance *ot = openthread_get_default_instance();
	const otExtendedPanId *active;
	otDeviceRole role;
	bool same;

	if (ot == NULL || xpanid == NULL) {
		return false;
	}

	openthread_mutex_lock();
	role = otThreadGetDeviceRole(ot);
	active = otThreadGetExtendedPanId(ot);
	/* Compared under the lock: the pointer is into OpenThread's own state. */
	same = (active != NULL) && memcmp(active->m8, xpanid, MATTER_THREAD_XPANID_LEN) == 0;
	openthread_mutex_unlock();

	/* DETACHED and DISABLED both mean "not on it", whatever the stored id
	 * says; only the three attached roles count. */
	if (!same || (role != OT_DEVICE_ROLE_CHILD && role != OT_DEVICE_ROLE_ROUTER &&
		      role != OT_DEVICE_ROLE_LEADER)) {
		return false;
	}
	LOG_INF("already attached to the commissioner's Thread network; not restarting");
	return true;
}

int matter_thread_interface(struct matter_thread_iface *out)
{
	otInstance *ot = openthread_get_default_instance();
	const otNetifAddress *addr;
	otDeviceRole role;

	memset(out, 0, sizeof(*out));
	if (ot == NULL) {
		return MATTER_E_STATE;
	}
	/* Node lock, then OpenThread's: the order every node call into the
	 * port takes. */
	openthread_mutex_lock();
	role = otThreadGetDeviceRole(ot);
	out->attached = role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER ||
			role == OT_DEVICE_ROLE_LEADER;
	memcpy(out->ext_addr, otLinkGetExtendedAddress(ot)->m8, sizeof(out->ext_addr));
	for (addr = otIp6GetUnicastAddresses(ot);
	     addr != NULL && out->n_addrs < MATTER_THREAD_IFACE_ADDRS_MAX; addr = addr->mNext) {
		memcpy(out->addrs[out->n_addrs++], addr->mAddress.mFields.m8, 16u);
	}
	out->thread_version = otThreadGetVersion();
	openthread_mutex_unlock();
	return MATTER_OK;
}

/* The scan in progress: where its results go, and the signal that it ended.
 * Written by OpenThread's callback, on its thread, and read once it has. */
static K_SEM_DEFINE(s_scan_done, 0, 1);
static struct matter_thread_scan_result *s_scan_out;
static uint8_t s_scan_cap;
static uint8_t s_scan_count;

static void scan_cb(otActiveScanResult *result, void *context)
{
	struct matter_thread_scan_result *r;

	ARG_UNUSED(context);
	if (result == NULL) {
		k_sem_give(&s_scan_done);
		return;
	}
	/* Beacons from anything that is not a Thread network carry no name. */
	if (s_scan_count >= s_scan_cap || result->mNetworkName.m8[0] == '\0') {
		return;
	}
	r = &s_scan_out[s_scan_count++];
	memset(r, 0, sizeof(*r));
	memcpy(r->ext_addr, result->mExtAddress.m8, sizeof(r->ext_addr));
	memcpy(r->xpanid, result->mExtendedPanId.m8, sizeof(r->xpanid));
	memcpy(r->name, result->mNetworkName.m8, sizeof(r->name) - 1u);
	r->pan_id = result->mPanId;
	r->channel = result->mChannel;
	r->version = result->mVersion;
	r->rssi = result->mRssi;
	r->lqi = result->mLqi;
}

/* Every channel at OpenThread's default dwell: about 16 x 300 ms. */
#define SCAN_TIMEOUT_MS 10000

int matter_thread_scan(struct matter_thread_scan_result *out, uint8_t cap, uint8_t *n)
{
	otInstance *ot = openthread_get_default_instance();
	otError err;

	*n = 0u;
	/* On OpenThread's own thread the callback could never run while this
	 * waits for it: refuse rather than deadlock. */
	if (ot == NULL || out == NULL || k_current_get() == openthread_thread_id_get()) {
		return MATTER_E_STATE;
	}
	k_sem_reset(&s_scan_done);
	s_scan_out = out;
	s_scan_cap = cap;
	s_scan_count = 0u;
	openthread_mutex_lock();
	err = otLinkActiveScan(ot, 0u, 0u, scan_cb, NULL);
	openthread_mutex_unlock();
	if (err != OT_ERROR_NONE) {
		LOG_WRN("Thread scan not started (%d)", err);
		return MATTER_E_STATE;
	}
	if (k_sem_take(&s_scan_done, K_MSEC(SCAN_TIMEOUT_MS)) != 0) {
		LOG_WRN("Thread scan did not finish in %u ms", (unsigned int)SCAN_TIMEOUT_MS);
		return MATTER_E_STATE;
	}
	*n = s_scan_count;
	LOG_INF("Thread scan: %u network(s)", (unsigned int)s_scan_count);
	return MATTER_OK;
}

/**
 * Is this an address something off the Thread mesh could route to?
 *
 * NOT a test for "is it global". A border router's off-mesh-routable prefix is
 * very often a unique-local one, indistinguishable from the mesh-local prefix
 * by its first byte -- an earlier version of this checked fc00::/7 and would
 * have reported a perfectly routable OMR address as unreachable. The only
 * sound test is against the mesh-local prefix this network actually uses.
 */
static bool addr_is_offmesh(otInstance *ot, const otNetifAddress *a)
{
	const otMeshLocalPrefix *ml = otThreadGetMeshLocalPrefix(ot);

	/* fe80::/10 */
	if (a->mAddress.mFields.m8[0] == 0xFEu && (a->mAddress.mFields.m8[1] & 0xC0u) == 0x80u) {
		return false;
	}
	if (ml != NULL && memcmp(a->mAddress.mFields.m8, ml->m8, OT_MESH_LOCAL_PREFIX_SIZE) == 0) {
		return false;
	}
	return true;
}

/**
 * Count the number of preferred off-mesh unicast addresses this node holds. Iterates over Thread
 * unicast addresses and counts those marked preferred that route to a destination not on the mesh.
 */
static int count_offmesh(otInstance *ot)
{
	const otNetifAddress *a;
	int n = 0;

	for (a = otIp6GetUnicastAddresses(ot); a != NULL; a = a->mNext) {
		if (a->mPreferred && addr_is_offmesh(ot, a)) {
			n++;
		}
	}
	return n;
}

/**
 * Every address this node holds, and whether any of them is reachable.
 *
 * A registered SRP name is not the same as a reachable node. Auto host address
 * mode publishes the PREFERRED unicast addresses, and falls back to the
 * mesh-local EID when there are none -- and a mesh-local address does not leave
 * the Thread mesh, so a commissioner on Wi-Fi resolves the name and then routes
 * nowhere. That failure is invisible from the SRP result, which is why it is
 * printed here instead of assumed.
 */
static void log_addresses(otInstance *ot)
{
	const otNetifAddress *a;
	char buf[OT_IP6_ADDRESS_STRING_SIZE];

	for (a = otIp6GetUnicastAddresses(ot); a != NULL; a = a->mNext) {
		otIp6AddressToString(&a->mAddress, buf, sizeof(buf));
		LOG_DBG("  addr %s  preferred=%d %s", buf, (int)a->mPreferred,
			addr_is_offmesh(ot, a) ? "(off-mesh)" : "(local)");
	}
	if (count_offmesh(ot) == 0) {
		LOG_WRN("NO off-mesh-routable address -- the border router is publishing no "
			"prefix this node can autoconfigure from");
	}
}

int matter_thread_wait_attached(uint32_t timeout_ms)
{
	otInstance *ot = openthread_get_default_instance();
	int64_t started_ms = k_uptime_get();
	bool announced = false;

	if (ot == NULL || attach_callback_ensure() != MATTER_OK) {
		return MATTER_E_STATE;
	}

	for (;;) {
		otDeviceRole role;
		int offmesh;
		int64_t now_ms;
		uint32_t waited;

		openthread_mutex_lock();
		role = otThreadGetDeviceRole(ot);
		offmesh = count_offmesh(ot);
		openthread_mutex_unlock();
		now_ms = k_uptime_get();
		waited = now_ms > started_ms ? (uint32_t)(now_ms - started_ms) : 0u;

		if (role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER ||
		    role == OT_DEVICE_ROLE_LEADER) {
			if (!announced) {
				LOG_INF("Thread attached after %u ms, role %d", waited, (int)role);
				announced = true;
			}
			/*
			 * Attached is NOT reachable. The off-mesh-routable
			 * address is autoconfigured from a prefix the border
			 * router publishes in network data, which arrives some
			 * time AFTER the attach -- and a node that registers SRP
			 * before it exists publishes only its mesh-local
			 * address, which no commissioner off the mesh can route
			 * to. Waiting here is what makes ConnectNetwork's
			 * Success mean something.
			 */
			if (offmesh > 0) {
				LOG_INF("reachable after %u ms (%d off-mesh address(es))", waited,
					offmesh);
				return MATTER_OK;
			}
		}
		if (waited >= timeout_ms) {
			if (announced) {
				LOG_WRN("attached but STILL no off-mesh address after %u ms",
					waited);
			} else {
				LOG_WRN("Thread still %s after %u ms",
					role == OT_DEVICE_ROLE_DETACHED ? "detached" : "disabled",
					waited);
			}
			openthread_mutex_lock();
			log_addresses(ot);
			openthread_mutex_unlock();
			return MATTER_E_TIMEOUT;
		}

		(void)k_sem_take(&s_attach_changed, K_MSEC(timeout_ms - waited));
	}
}

/*
 * Everything the SRP client is handed must OUTLIVE the call. otSrpClientAddService()
 * links the service into a list it keeps and does not copy the strings, so a
 * stack buffer here would be a use-after-return that shows up as a garbled
 * service name on somebody else's border router.
 */
static char s_host_name[26]; /* 16 hex of EUI-64 + '-' + 8 hex of host id + NUL */
static bool s_host_name_ready;
static char s_service_type[] = "_matter._tcp";
static char s_txt_sii[] = "500";
static char s_txt_sai[] = "300";

/**
 * One registration per fabric, because a node on two fabrics has two names.
 *
 * The instance name is derived from the compressed fabric id and this node's id
 * ON that fabric, so the second administrator resolving the first fabric's name
 * finds an address it cannot open a session to. A single slot here published
 * whichever fabric registered last and left the other unreachable.
 */
struct srp_reg {
	char instance_name[MATTER_INSTANCE_NAME_LEN];
	char subtype[19]; /* "_I" + 16 hex digits + NUL */
	const char *subtype_labels[2];
	otSrpClientService service;
	otDnsTxtEntry txt[2];
	enum {
		SRP_SLOT_FREE,
		SRP_SLOT_ACTIVE,
		SRP_SLOT_REMOVING,
	} state;
};
static struct srp_reg s_regs[MATTER_SUPPORTED_FABRICS];

/*
 * What the Matter layer wants published, separate from the objects OpenThread
 * owns. otSrpClientAddService() retains every pointer in struct srp_reg until
 * the removal callback returns it. A retry can therefore change this table
 * while the old service objects remain byte-for-byte untouched.
 */
struct srp_wanted_reg {
	char instance_name[MATTER_INSTANCE_NAME_LEN];
	uint16_t port;
	bool used;
};
static struct srp_wanted_reg s_wanted_regs[MATTER_SUPPORTED_FABRICS];

/** The SRP host is registered once, whatever number of services hang off it. */
static bool s_host_ready;

/* True from a successful RemoveHostAndServices() until its callback returns
 * the retired host and services. New requests are accepted into the wanted
 * tables during this interval and reconciled once ownership comes back. */
static bool s_srp_resetting;

/**
 * Whether the commissionable service is registered.
 *
 * Separate ACTIVE and REMOVING states are required because OpenThread owns the
 * service object until it returns it through srp_cb(). Treating a requested
 * removal as completed immediately is the reuse race this state prevents.
 */
static enum {
	SRP_COMM_FREE,
	SRP_COMM_ACTIVE,
	SRP_COMM_REMOVING,
} s_comm_state;
static otSrpClientService s_comm_service;

struct srp_wanted_commissionable {
	uint8_t random[8];
	uint16_t discriminator;
	uint16_t port;
	bool used;
};
static struct srp_wanted_commissionable s_wanted_comm;

/*
 * The window record's name, kept in settings while it is registered.
 *
 * Apple's border router keeps a record its node never retracted well past the
 * lease asked for (over 14 min against 2 min, 2026-10-16), and does not drop a
 * host's services when the host itself is removed: only removing the record by
 * name clears it. A crash, power cut or reset with a window open leaves exactly
 * that, and a factory reset after it strands it: Home dials it over Thread and
 * never uses BLE. The next boot registers this name again and removes it.
 */
#define SRP_COMM_KEY "srp/comm"
static uint8_t s_stale_comm_random[8];
static bool s_stale_comm;

/**
 * Settings callback to read a 32-bit host ID from persistent storage. Reads exactly
 * sizeof(uint32_t) bytes into the output parameter, returning 0 on all paths.
 */
static int host_id_read(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg,
			void *param)
{
	uint32_t *out = param;

	ARG_UNUSED(key);

	if (len == sizeof(*out)) {
		(void)read_cb(cb_arg, out, sizeof(*out));
	}
	return 0;
}

static int comm_read(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg,
		     void *param)
{
	ARG_UNUSED(key);
	ARG_UNUSED(param);

	if (len == sizeof(s_stale_comm_random) &&
	    read_cb(cb_arg, s_stale_comm_random, len) == (ssize_t)len) {
		s_stale_comm = true;
	}
	return 0;
}

/**
 * The host-name suffix: read it, or mint one and keep it. See SRP_HOST_ID_KEY.
 *
 * Zero is the "not stored" marker, so it is never a valid id -- which costs one
 * value out of 2^32 and saves carrying a separate "have I got one" flag through
 * the settings backend.
 */
static uint32_t srp_host_id(void)
{
	static uint32_t id;

	if (id != 0u) {
		return id;
	}
	/* Idempotent, and this can run before anything else has needed
	 * settings. */
	(void)settings_subsys_init();
	(void)settings_load_subtree_direct(SRP_HOST_ID_KEY, host_id_read, &id);
	if (id == 0u) {
		/*
		 * PSA's, not otRandomNonCryptoGetUint32(): this runs on the
		 * Matter work queue without the OpenThread lock held. A CSPRNG
		 * for a name that gets published in the clear is not strictly
		 * required, but this codebase does not want two classes of
		 * random source, and a value
		 * drawn once per lifetime cannot be the wrong place to pay.
		 */
		do {
			if (psa_generate_random((uint8_t *)&id, sizeof(id)) != PSA_SUCCESS) {
				LOG_ERR("no RNG for the SRP host id");
				return 0u;
			}
		} while (id == 0u);
		if (settings_save_one(SRP_HOST_ID_KEY, &id, sizeof(id)) != 0) {
			/* Registration still works; it is the NEXT boot that
			 * would ask for a different name and orphan this one. */
			LOG_WRN("SRP host id not persisted");
		}
	}
	return id;
}

static otUdpSocket s_udp;
static bool s_udp_open;

/**
 * Whatever arrives on the operational port, reported and dropped.
 *
 * There is no CASE responder yet, so this cannot answer. What it can do is
 * prove the half that would otherwise be invisible: a datagram here means the
 * commissioner resolved this node's name through the border router and routed
 * to it. Without it, "stuck at connecting" cannot be told apart from a service
 * that was never registered.
 */
/** The peer of the datagram in flight; see matter_thread_peer_current(). */
static struct matter_thread_peer s_cur_peer;

/**
 * Copy the current inbound peer address and port to the caller's buffer. Called by Matter protocol
 * handlers to discover where a datagram came from. Returns without effect if out is NULL.
 */
void matter_thread_peer_current(struct matter_thread_peer *out)
{
	if (out == NULL) {
		return;
	}
	*out = s_cur_peer;
}

/**
 * Send a datagram to a peer over Thread UDP. Returns MATTER_E_STATE if the peer is invalid, the
 * address family is unsupported, the message buffer cannot be allocated, or the send fails;
 * MATTER_E_NOSPACE if the message buffer is full; MATTER_OK on success.
 */
int matter_thread_send_to(const struct matter_thread_peer *peer, const uint8_t *msg, size_t len)
{
	otInstance *ot = openthread_get_default_instance();
	otMessageInfo info;
	otMessage *out;

	if (peer == NULL || !peer->valid || msg == NULL || len == 0u || ot == NULL) {
		return MATTER_E_STATE;
	}

	memset(&info, 0, sizeof(info));
	memcpy(info.mPeerAddr.mFields.m8, peer->addr, sizeof(peer->addr));
	info.mPeerPort = peer->port;
	/*
	 * mSockAddr left unspecified so the stack picks a source address for
	 * this destination. The reply path can copy the one the request arrived
	 * on; there is no request here to copy from, and pinning the wrong
	 * source is how a datagram leaves and is never answered.
	 */

	/* Zephyr's OpenThread contract requires its mutex around every OT API.
	 * The socket-open flag is protected by that same mutex when bind publishes
	 * it, so read it only after acquiring the lock too. Owner -> OT is safe:
	 * the OT receive callback never waits for the Matter owner. */
	openthread_mutex_lock();
	if (!s_udp_open) {
		openthread_mutex_unlock();
		return MATTER_E_STATE;
	}
	out = otUdpNewMessage(ot, NULL);
	if (out == NULL) {
		openthread_mutex_unlock();
		LOG_ERR("no message buffer for an unsolicited send");
		return MATTER_E_NOSPACE;
	}
	if (otMessageAppend(out, msg, (uint16_t)len) != OT_ERROR_NONE ||
	    otUdpSend(ot, &s_udp, out, &info) != OT_ERROR_NONE) {
		/* otUdpSend takes ownership on success only. */
		otMessageFree(out);
		openthread_mutex_unlock();
		LOG_ERR("unsolicited %u B send failed", (unsigned int)len);
		return MATTER_E_STATE;
	}
	openthread_mutex_unlock();
	LOG_DBG("sent %u B unsolicited", (unsigned int)len);
	return MATTER_OK;
}

/**
 * OpenThread UDP RX callback. Reads the incoming datagram, logs its size, invokes
 * matter_thread_on_datagram to generate a reply, and sends the reply back to the peer. Uses static
 * buffers sized for Sigma3 (RX) and full subscription reports (reply) respectively. Temporarily
 * publishes the peer address so the Matter handler can discover where traffic arrived from.
 */
static int udp_reply_send(void *ctx, const uint8_t *reply, size_t reply_len)
{
	const otMessageInfo *request_info = ctx;
	otMessageInfo reply_info;
	otMessage *out;

	if (request_info == NULL) {
		return MATTER_E_STATE;
	}
	/* Reply to where the datagram came from. The source address is copied too,
	 * so a commissioner reached through a border router gets an answer on the
	 * same route. This runs inside udp_rx while request_info is still valid. */
	memset(&reply_info, 0, sizeof(reply_info));
	reply_info.mPeerAddr = request_info->mPeerAddr;
	reply_info.mPeerPort = request_info->mPeerPort;
	reply_info.mSockAddr = request_info->mSockAddr;
	out = otUdpNewMessage(openthread_get_default_instance(), NULL);
	if (out == NULL) {
		LOG_ERR("  no message buffer for the reply");
		return MATTER_E_NOSPACE;
	}
	if (otMessageAppend(out, reply, (uint16_t)reply_len) != OT_ERROR_NONE ||
	    otUdpSend(openthread_get_default_instance(), &s_udp, out, &reply_info) !=
		    OT_ERROR_NONE) {
		/* otUdpSend takes ownership on success only. */
		otMessageFree(out);
		LOG_ERR("  reply could not be sent");
		return MATTER_E_STATE;
	}
	return MATTER_OK;
}

static void udp_rx(void *ctx, otMessage *msg, const otMessageInfo *info)
{
	/*
	 * Sized for a Sigma3, not a Sigma1. A Sigma1 is 196 bytes, but a Sigma3
	 * carries the initiator's whole certificate chain encrypted -- with an
	 * intermediate certificate present that is comfortably past 512, and the
	 * only symptom of an undersized buffer here is this function declining to
	 * look at the message that ends the handshake.
	 *
	 * Static because this runs on OpenThread's own thread, whose stack is one
	 * of the two things deliberately left un-shrunk.
	 */
	static uint8_t buf[MATTER_CASE_SIGMA3_MAX];
	/*
	 * NOT Sigma2. The largest thing this sends is a ReportData answering a
	 * subscription to the whole data model -- measured at 1479 B of payload
	 * on hardware against Sigma2's 494 -- plus both headers and the AEAD
	 * tag. Sized off the report buffer for that reason; while it was sized
	 * off Sigma2 the node built the report correctly and then could not
	 * copy it out, which reads in the log as "needs 1513 B, have 1024".
	 */
	static uint8_t reply[MATTER_THREAD_REPLY_MAX];
	size_t reply_len;
	uint16_t len = otMessageGetLength(msg) - otMessageGetOffset(msg);

	ARG_UNUSED(ctx);

	LOG_DBG("UDP %u B on port %u from peer port %u", (unsigned int)len,
		(unsigned int)info->mSockPort, (unsigned int)info->mPeerPort);

	if (len > sizeof(buf)) {
		LOG_WRN("  too large to look at (%u B)", (unsigned int)len);
		return;
	}
	if (otMessageRead(msg, otMessageGetOffset(msg), buf, len) != len) {
		LOG_WRN("  could not be read out");
		return;
	}

	/*
	 * Published for the duration of the handler only. A subscription
	 * outlives the SubscribeRequest that created it and a report has to be
	 * addressed somewhere, so the handler takes a copy while this is live.
	 */
	memcpy(s_cur_peer.addr, info->mPeerAddr.mFields.m8, sizeof(s_cur_peer.addr));
	s_cur_peer.port = info->mPeerPort;
	s_cur_peer.valid = true;

	reply_len = matter_thread_on_datagram(buf, len, reply, sizeof(reply), udp_reply_send,
					      (void *)info);

	s_cur_peer.valid = false;

	if (reply_len == 0u) {
		return;
	}

	LOG_DBG("  replied %u B", (unsigned int)reply_len);
}

/**
 * Every address this node holds, and whether any of them is reachable.
 *
 * A registered SRP name is not the same as a reachable node. Auto host address
 * mode publishes the PREFERRED unicast addresses, and falls back to the
 * mesh-local EID when there are none -- and a mesh-local address does not leave
 * the Thread mesh, so a commissioner on Wi-Fi resolves the name and then routes
 * nowhere. That failure is invisible from the SRP result, which is why it is
 * printed here instead of assumed.
 *
 * The address to look for is an off-mesh-routable one, which only exists if the
 * border router is publishing a prefix this node has picked up.
 */

/* All three helpers require OpenThread's API lock. srp_cb() already runs with
 * it held; public entry points take it before calling them. */
static int srp_reconcile_locked(otInstance *ot);

static void srp_active_clear_locked(void)
{
	memset(s_regs, 0, sizeof(s_regs));
	memset(&s_comm_service, 0, sizeof(s_comm_service));
	s_comm_state = SRP_COMM_FREE;
	s_host_ready = false;
}

static void srp_release_removed_locked(const otSrpClientService *removed)
{
	const otSrpClientService *service = removed;

	while (service != NULL) {
		const otSrpClientService *next = service->mNext;

		for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
			if (service == &s_regs[i].service) {
				memset(&s_regs[i], 0, sizeof(s_regs[i]));
				break;
			}
		}
		if (service == &s_comm_service) {
			memset(&s_comm_service, 0, sizeof(s_comm_service));
			s_comm_state = SRP_COMM_FREE;
		}
		service = next;
	}
}

/* Off the callback, which runs inside the client: removing the last boot's
 * window record once the server holds it again. */
static void srp_stale_comm_fn(struct k_work *work)
{
	bool stale;

	ARG_UNUSED(work);
	openthread_mutex_lock();
	stale = s_stale_comm;
	s_stale_comm = false;
	openthread_mutex_unlock();
	if (stale && matter_thread_unadvertise_commissionable() == MATTER_OK) {
		LOG_INF("SRP: removed the window record left before this boot");
	}
}
static K_WORK_DEFINE(s_stale_comm_work, srp_stale_comm_fn);

/** The SRP server's verdict, which otSrpClientAddService() cannot give. */
static void srp_cb(otError err, const otSrpClientHostInfo *host, const otSrpClientService *services,
		   const otSrpClientService *removed, void *ctx)
{
	ARG_UNUSED(ctx);

	/* OpenThread has unlinked every object in this list before invoking us;
	 * this callback is the first point at which its storage may be reclaimed. */
	srp_release_removed_locked(removed);

	if (s_srp_resetting && host != NULL &&
	    host->mState == OT_SRP_CLIENT_ITEM_STATE_REMOVED) {
		/* RemoveHostAndServices retires the complete list. The removed list
		 * above is the ownership receipt; clearing the arrays now is safe even
		 * when there were no services to return. */
		srp_active_clear_locked();
		s_srp_resetting = false;
		LOG_INF("SRP reset complete; reconciling queued registrations");
	}

	if (err == OT_ERROR_NONE) {
		LOG_INF("SRP registered: host state %d, service state %d",
			host != NULL ? (int)host->mState : -1,
			services != NULL ? (int)services->mState : -1);
	} else {
		LOG_ERR("SRP registration FAILED (%d) -- the commissioner cannot resolve this node",
			err);
	}
	if (err == OT_ERROR_NONE && s_stale_comm && s_comm_state == SRP_COMM_ACTIVE &&
	    s_comm_service.mState == OT_SRP_CLIENT_ITEM_STATE_REGISTERED) {
		k_work_submit(&s_stale_comm_work);
	}
	if (!s_srp_resetting && srp_reconcile_locked(openthread_get_default_instance()) != MATTER_OK) {
		LOG_ERR("queued SRP registrations could not be reconciled");
	}
	log_addresses(openthread_get_default_instance());
}

/**
 * Release all SRP registrations for the host and services. Clears both the SRP client state and the
 * local registration cache, so the next advertise re-registers from scratch. Called when fabrics
 * are rolled back to avoid leaving dangling registrations under old names.
 */
void matter_thread_advertise_reset(void)
{
	otInstance *ot = openthread_get_default_instance();
	otError rm;

	if (ot == NULL) {
		memset(s_wanted_regs, 0, sizeof(s_wanted_regs));
		memset(&s_wanted_comm, 0, sizeof(s_wanted_comm));
		srp_active_clear_locked();
		s_srp_resetting = false;
		return;
	}

	/*
	 * Rolling back the fabrics has to release their SRP registrations too.
	 *
	 * There is one slot per supported fabric and a slot is only reused when
	 * the instance name matches EXACTLY -- but the name is derived from the
	 * compressed fabric id and node id, so a new commissioner never matches
	 * the old one. A board that came up with restored fabrics therefore held
	 * both slots against names that no longer existed, and the next pairing
	 * died right after PASE with "no SRP slot left", which looks from the
	 * phone like an accessory stuck on "connecting".
	 *
	 * The host goes with them: the services hang off it, and the next
	 * advertise re-registers both from scratch.
	 */
	/*
	 * RETRACT, do not just forget. otSrpClientClearHostAndServices() is
	 * local-only: it drops this node's copy and never tells the server, so
	 * the border router kept advertising every abandoned instance until its
	 * lease ran out -- seven of them accumulated in one evening of failed
	 * pairings (dns-sd -B _matter._tcp, 2026-08-06), each one a name a
	 * commissioner can still resolve and then fail to reach.
	 *
	 * aRemoveKeyLease = true: the key lease is what reserves the name for a
	 * client that will come back, and these names are never coming back --
	 * the instance name is derived from a fabric that just ceased to exist.
	 *
	 * aSendUnregToServer = true: covers the case where this rollback lands
	 * before the registration was confirmed, which is precisely the failed
	 * pairing that leaves rubbish behind.
	 */
	openthread_mutex_lock();
	/* Reset means none of the old fabric-derived names is wanted. A new
	 * commissioner can add its replacement while removal is in flight. */
	memset(s_wanted_regs, 0, sizeof(s_wanted_regs));
	memset(&s_wanted_comm, 0, sizeof(s_wanted_comm));
	if (s_srp_resetting) {
		openthread_mutex_unlock();
		return;
	}

	rm = otSrpClientRemoveHostAndServices(ot, true, true);
	if (rm == OT_ERROR_NONE) {
		for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
			if (s_regs[i].state == SRP_SLOT_ACTIVE) {
				s_regs[i].state = SRP_SLOT_REMOVING;
			}
		}
		if (s_comm_state == SRP_COMM_ACTIVE) {
			s_comm_state = SRP_COMM_REMOVING;
		}
		s_srp_resetting = true;
		LOG_INF("SRP registrations retiring");
	} else {
		/* ALREADY means the host is already removed. For any other refusal,
		 * ClearHostAndServices is the documented immediate ownership return;
		 * the server-side lease may linger, but no retained object is reused. */
		if (rm != OT_ERROR_ALREADY) {
			LOG_WRN("SRP remove not started (%d); clearing locally", rm);
		}
		otSrpClientClearHostAndServices(ot);
		srp_active_clear_locked();
		s_srp_resetting = false;
		LOG_INF("SRP registrations released locally");
	}
	openthread_mutex_unlock();
}

bool matter_thread_advertise_pending(void)
{
	bool pending;

	openthread_mutex_lock();
	pending = s_srp_resetting;
	openthread_mutex_unlock();
	return pending;
}

/*
 * The host name, built outside the OpenThread lock because srp_host_id() reaches
 * into the settings backend and that is not somewhere to go holding it.
 *
 * The host name only has to be unique on the SRP server, and the EUI-64 already
 * is -- across boards. The suffix is what makes it unique across this board's
 * own erases; see SRP_HOST_ID_KEY.
 */
static void srp_host_name_build(otInstance *ot)
{
	otExtAddress eui;

	/* OpenThread retains this pointer with the host registration. Even writing
	 * the same bytes again would violate its immutable-buffer contract. */
	if (s_host_name_ready) {
		return;
	}
	otPlatRadioGetIeeeEui64(ot, eui.m8);
	(void)snprintf(s_host_name, sizeof(s_host_name), "%02X%02X%02X%02X%02X%02X%02X%02X-%08X",
		       eui.m8[0], eui.m8[1], eui.m8[2], eui.m8[3], eui.m8[4], eui.m8[5], eui.m8[6],
		       eui.m8[7], (unsigned int)srp_host_id());
	(void)settings_load_subtree_direct(SRP_COMM_KEY, comm_read, NULL);
	s_host_name_ready = true;
}

/*
 * The HOST is registered once; every service hangs off it, operational and
 * commissionable alike, and whichever registers first brings it up for the
 * other. Caller holds the OpenThread lock and has already built s_host_name.
 *
 * Calling otSrpClientSetHostName() again once the client is running returns
 * OT_ERROR_INVALID_STATE (13) and takes the whole registration down with it --
 * which is what refused the second fabric after its AddNOC was accepted, leaving
 * the new administrator a fabric it could not resolve.
 */
static otError srp_host_register(otInstance *ot)
{
	otError err;

	if (s_host_ready) {
		return OT_ERROR_NONE;
	}
	if (s_srp_resetting) {
		return OT_ERROR_INVALID_STATE;
	}
	otSrpClientSetCallback(ot, srp_cb, NULL);
	otSrpClientSetKeyLeaseInterval(ot, SRP_KEY_LEASE_S);
	err = otSrpClientSetHostName(ot, s_host_name);
	if (err == OT_ERROR_NONE) {
		err = otSrpClientEnableAutoHostAddress(ot);
	}
	if (err == OT_ERROR_NONE) {
		s_host_ready = true;
	}
	return err;
}

/* The active commissionable buffers are a second ownership bank: pending
 * parameters can change while OpenThread still owns this bank. */
static char s_comm_service_type[] = "_matterc._udp";
static char s_comm_instance[17];
static char s_comm_sub_short[5];
static char s_comm_sub_long[7];
static const char *s_comm_sub_labels[3];
static char s_comm_txt_d[5];
static char s_comm_txt_cm[2];
static char s_comm_txt_vp[12];
static otDnsTxtEntry s_comm_txt[5];

static struct srp_reg *srp_active_find(const char *instance_name)
{
	for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (s_regs[i].state != SRP_SLOT_FREE &&
		    strcmp(s_regs[i].instance_name, instance_name) == 0) {
			return &s_regs[i];
		}
	}
	return NULL;
}

static struct srp_reg *srp_free_find(void)
{
	for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (s_regs[i].state == SRP_SLOT_FREE) {
			return &s_regs[i];
		}
	}
	return NULL;
}

static int srp_register_operational_locked(otInstance *ot, const struct srp_wanted_reg *wanted)
{
	otSockAddr bind_addr;
	struct srp_reg *reg = srp_free_find();
	otError err;

	if (reg == NULL) {
		return MATTER_E_NOSPACE;
	}
	memset(reg, 0, sizeof(*reg));
	(void)snprintf(reg->instance_name, sizeof(reg->instance_name), "%s", wanted->instance_name);
	reg->subtype[0] = '_';
	reg->subtype[1] = 'I';
	memcpy(&reg->subtype[2], reg->instance_name, 16u);
	reg->subtype[18] = '\0';
	reg->subtype_labels[0] = reg->subtype;

	reg->txt[0].mKey = "SII";
	reg->txt[0].mValue = (const uint8_t *)s_txt_sii;
	reg->txt[0].mValueLength = (uint16_t)strlen(s_txt_sii);
	reg->txt[1].mKey = "SAI";
	reg->txt[1].mValue = (const uint8_t *)s_txt_sai;
	reg->txt[1].mValueLength = (uint16_t)strlen(s_txt_sai);
	reg->service.mName = s_service_type;
	reg->service.mInstanceName = reg->instance_name;
	reg->service.mSubTypeLabels = reg->subtype_labels;
	reg->service.mPort = wanted->port;
	reg->service.mTxtEntries = reg->txt;
	reg->service.mNumTxtEntries = 2u;

	/* Bind before publishing so a resolved name never points at a closed
	 * socket. The socket is shared by every operational fabric. */
	if (!s_udp_open) {
		memset(&bind_addr, 0, sizeof(bind_addr));
		bind_addr.mPort = wanted->port;
		if (otUdpOpen(ot, &s_udp, udp_rx, NULL) == OT_ERROR_NONE &&
		    otUdpBind(ot, &s_udp, &bind_addr, OT_NETIF_THREAD) == OT_ERROR_NONE) {
			s_udp_open = true;
			LOG_INF("listening on UDP %u", (unsigned int)wanted->port);
		} else {
			LOG_ERR("could not listen on UDP %u", (unsigned int)wanted->port);
		}
	}

	err = srp_host_register(ot);
	if (err == OT_ERROR_NONE) {
		err = otSrpClientAddService(ot, &reg->service);
		if (err == OT_ERROR_ALREADY) {
			/*
			 * THE SLOT IS STILL IN OPENTHREAD'S OWN LIST, and without
			 * this nothing ever gets it out again.
			 *
			 * matter_thread_advertise_reset() memsets s_regs while the
			 * retraction it just started is still in flight, so the
			 * otSrpClientService living inside each slot is zeroed while
			 * mServices still points at it. Reusing the slot refills that
			 * same struct, and AddService then compares the entry against
			 * ITSELF -- Client::Service::Matches is service+instance name
			 * equality, and both sides are the name just written here --
			 * so it returns ALREADY (srp_client.cpp:765).
			 *
			 * Nothing recovers on its own. The error path below leaves
			 * `used` false, the slot search above therefore hands the NEXT
			 * fabric the same struct, and every registration for the rest
			 * of the boot is refused identically.
			 *
			 * MEASURED 2026-08-16: five "SRP registration refused (24)"
			 * and not one _matter._tcp instance published, on a node that
			 * had just committed a fabric over a healthy CASE session.
			 * The commissioner could not resolve what it had just added,
			 * so the Home app sat on "Adding to Home" until the board was
			 * rebooted -- which cured it only because a boot starts with
			 * an empty client list.
			 *
			 * otSrpClientClearService is the documented way back: it drops
			 * the entry locally BY POINTER (mServices.Remove) and the
			 * header explicitly blesses reusing the same struct in a
			 * following AddService (srp_client.h:566). It costs nothing on
			 * the server -- the retraction for the OLD name was already
			 * sent by otSrpClientRemoveHostAndServices(..., true, true).
			 */
			LOG_WRN("SRP entry for %s was still held; clearing and re-adding",
				reg->instance_name);
			(void)otSrpClientClearService(ot, &reg->service);
			err = otSrpClientAddService(ot, &reg->service);
		}
	}
	if (err != OT_ERROR_NONE) {
		/* AddService did not take ownership on error. Keeping this slot
		 * would hide the queued request and recreate the OT_ERROR_ALREADY
		 * loop seen on hardware. */
		memset(reg, 0, sizeof(*reg));
		LOG_ERR("SRP registration refused (%d)", err);
		return MATTER_E_STATE;
	}
	reg->state = SRP_SLOT_ACTIVE;
	otSrpClientEnableAutoStartMode(ot, NULL, NULL);
	LOG_INF("SRP: %s.%s._matter._tcp on %s.local port %u", reg->instance_name, reg->subtype,
		s_host_name, (unsigned int)wanted->port);
	return MATTER_OK;
}

static int srp_register_commissionable_locked(otInstance *ot)
{
	otError err;
	uint16_t discriminator = s_wanted_comm.discriminator;

	(void)snprintf(s_comm_instance, sizeof(s_comm_instance),
		       "%02X%02X%02X%02X%02X%02X%02X%02X", s_wanted_comm.random[0],
		       s_wanted_comm.random[1], s_wanted_comm.random[2], s_wanted_comm.random[3],
		       s_wanted_comm.random[4], s_wanted_comm.random[5], s_wanted_comm.random[6],
		       s_wanted_comm.random[7]);
	(void)snprintf(s_comm_sub_short, sizeof(s_comm_sub_short), "_S%u",
		       (unsigned int)((discriminator >> 8) & 0x0Fu));
	(void)snprintf(s_comm_sub_long, sizeof(s_comm_sub_long), "_L%u",
		       (unsigned int)(discriminator & 0x0FFFu));
	s_comm_sub_labels[0] = s_comm_sub_short;
	s_comm_sub_labels[1] = s_comm_sub_long;
	s_comm_sub_labels[2] = NULL;
	(void)snprintf(s_comm_txt_d, sizeof(s_comm_txt_d), "%u",
		       (unsigned int)(discriminator & 0x0FFFu));
	(void)snprintf(s_comm_txt_cm, sizeof(s_comm_txt_cm), "2");
	(void)snprintf(s_comm_txt_vp, sizeof(s_comm_txt_vp), "%u+%u",
		       (unsigned int)CONFIG_TINYTALK_VENDOR_ID,
		       (unsigned int)CONFIG_TINYTALK_PRODUCT_ID);
	s_comm_txt[0] = (otDnsTxtEntry){ .mKey = "D",
					.mValue = (const uint8_t *)s_comm_txt_d,
					.mValueLength = (uint16_t)strlen(s_comm_txt_d) };
	s_comm_txt[1] = (otDnsTxtEntry){ .mKey = "CM",
					.mValue = (const uint8_t *)s_comm_txt_cm,
					.mValueLength = (uint16_t)strlen(s_comm_txt_cm) };
	s_comm_txt[2] = (otDnsTxtEntry){ .mKey = "VP",
					.mValue = (const uint8_t *)s_comm_txt_vp,
					.mValueLength = (uint16_t)strlen(s_comm_txt_vp) };
	s_comm_txt[3] = (otDnsTxtEntry){ .mKey = "SII",
					.mValue = (const uint8_t *)s_txt_sii,
					.mValueLength = (uint16_t)strlen(s_txt_sii) };
	s_comm_txt[4] = (otDnsTxtEntry){ .mKey = "SAI",
					.mValue = (const uint8_t *)s_txt_sai,
					.mValueLength = (uint16_t)strlen(s_txt_sai) };
	memset(&s_comm_service, 0, sizeof(s_comm_service));
	s_comm_service.mName = s_comm_service_type;
	s_comm_service.mInstanceName = s_comm_instance;
	s_comm_service.mSubTypeLabels = s_comm_sub_labels;
	s_comm_service.mPort = s_wanted_comm.port;
	s_comm_service.mTxtEntries = s_comm_txt;
	s_comm_service.mNumTxtEntries = 5u;
	s_comm_service.mLease = SRP_COMM_LEASE_S;

	err = srp_host_register(ot);
	if (err == OT_ERROR_NONE) {
		err = otSrpClientAddService(ot, &s_comm_service);
	}
	if (err != OT_ERROR_NONE) {
		memset(&s_comm_service, 0, sizeof(s_comm_service));
		LOG_ERR("commissionable SRP registration refused (%d)", err);
		return MATTER_E_STATE;
	}
	s_comm_state = SRP_COMM_ACTIVE;
	LOG_INF("SRP: %s.%s/%s._matterc._udp port %u (D=%s)", s_comm_instance, s_comm_sub_short,
		s_comm_sub_long, (unsigned int)s_wanted_comm.port, s_comm_txt_d);
	return MATTER_OK;
}

static int srp_reconcile_locked(otInstance *ot)
{
	int rc = MATTER_OK;

	if (ot == NULL || s_srp_resetting) {
		return ot == NULL ? MATTER_E_STATE : MATTER_OK;
	}
	for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (!s_wanted_regs[i].used || srp_active_find(s_wanted_regs[i].instance_name) != NULL) {
			continue;
		}
		/* A removed-service callback will free a slot and call this function
		 * again. The desired registration is accepted and safely queued. */
		if (srp_free_find() == NULL) {
			continue;
		}
		int one = srp_register_operational_locked(ot, &s_wanted_regs[i]);

		if (one != MATTER_OK && rc == MATTER_OK) {
			rc = one;
		}
	}
	/* The last boot's window record, registered again only to be removed by
	 * name; see SRP_COMM_KEY. */
	if (s_stale_comm && !s_wanted_comm.used && s_comm_state == SRP_COMM_FREE) {
		memcpy(s_wanted_comm.random, s_stale_comm_random, sizeof(s_wanted_comm.random));
		s_wanted_comm.discriminator = CONFIG_TINYTALK_DISCRIMINATOR;
		s_wanted_comm.port = MATTER_OPERATIONAL_PORT;
		s_wanted_comm.used = true;
	}
	if (s_wanted_comm.used && s_comm_state == SRP_COMM_FREE) {
		int one = srp_register_commissionable_locked(ot);

		if (one != MATTER_OK && rc == MATTER_OK) {
			rc = one;
		}
	}
	return rc;
}

int matter_thread_advertise(const char *instance_name, uint16_t port)
{
	otInstance *ot = openthread_get_default_instance();
	struct srp_wanted_reg *wanted = NULL;
	int rc;

	if (ot == NULL || instance_name == NULL || strlen(instance_name) >= MATTER_INSTANCE_NAME_LEN) {
		return MATTER_E_INVAL;
	}
	srp_host_name_build(ot);
	openthread_mutex_lock();
	for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (s_wanted_regs[i].used &&
		    strcmp(s_wanted_regs[i].instance_name, instance_name) == 0) {
			wanted = &s_wanted_regs[i];
			break;
		}
		if (!s_wanted_regs[i].used && wanted == NULL) {
			wanted = &s_wanted_regs[i];
		}
	}
	if (wanted == NULL) {
		openthread_mutex_unlock();
		LOG_ERR("no desired SRP slot left for %s", instance_name);
		return MATTER_E_NOSPACE;
	}
	if (!wanted->used) {
		(void)snprintf(wanted->instance_name, sizeof(wanted->instance_name), "%s",
			       instance_name);
		wanted->port = port;
		wanted->used = true;
	}
	rc = srp_reconcile_locked(ot);
	openthread_mutex_unlock();
	return rc;
}

int matter_thread_advertise_commissionable(uint16_t discriminator, uint16_t port)
{
	otInstance *ot = openthread_get_default_instance();
	uint8_t random[sizeof(s_wanted_comm.random)];
	bool adopted;
	int rc;

	if (ot == NULL) {
		return MATTER_E_STATE;
	}
	if (psa_generate_random(random, sizeof(random)) != PSA_SUCCESS) {
		LOG_ERR("no RNG for the commissionable instance name");
		return MATTER_E_STATE;
	}
	srp_host_name_build(ot);
	openthread_mutex_lock();
	adopted = !s_wanted_comm.used;
	if (adopted) {
		memcpy(s_wanted_comm.random, random, sizeof(random));
		s_wanted_comm.discriminator = discriminator;
		s_wanted_comm.port = port;
		s_wanted_comm.used = true;
	}
	/* A window opened while the last boot's record is still being cleared
	 * takes that record over instead of racing its removal. */
	s_stale_comm = false;
	rc = srp_reconcile_locked(ot);
	openthread_mutex_unlock();
	if (adopted && settings_save_one(SRP_COMM_KEY, random, sizeof(random)) != 0) {
		LOG_WRN("window record name not persisted");
	}
	return rc;
}

int matter_thread_unadvertise(const char *instance_name)
{
	otInstance *ot = openthread_get_default_instance();
	struct srp_reg *reg;
	otError err = OT_ERROR_NONE;

	if (instance_name == NULL) {
		return MATTER_E_INVAL;
	}
	if (ot == NULL) {
		return MATTER_E_STATE;
	}
	openthread_mutex_lock();
	for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (s_wanted_regs[i].used &&
		    strcmp(s_wanted_regs[i].instance_name, instance_name) == 0) {
			memset(&s_wanted_regs[i], 0, sizeof(s_wanted_regs[i]));
			break;
		}
	}
	reg = srp_active_find(instance_name);
	if (reg != NULL && reg->state == SRP_SLOT_ACTIVE && !s_srp_resetting) {
		err = otSrpClientRemoveService(ot, &reg->service);
		if (err == OT_ERROR_NONE) {
			reg->state = SRP_SLOT_REMOVING;
		} else if (err == OT_ERROR_NOT_FOUND) {
			memset(reg, 0, sizeof(*reg));
		}
	}
	openthread_mutex_unlock();
	if (err != OT_ERROR_NONE && err != OT_ERROR_NOT_FOUND) {
		LOG_WRN("SRP removal of %s refused (%d); retaining its owned slot", instance_name,
			err);
		return MATTER_E_STATE;
	}
	return MATTER_OK;
}

int matter_thread_unadvertise_commissionable(void)
{
	otInstance *ot = openthread_get_default_instance();
	otError err = OT_ERROR_NONE;

	if (ot == NULL) {
		return MATTER_E_STATE;
	}
	openthread_mutex_lock();
	memset(&s_wanted_comm, 0, sizeof(s_wanted_comm));
	if (s_comm_state == SRP_COMM_ACTIVE && !s_srp_resetting) {
		err = otSrpClientRemoveService(ot, &s_comm_service);
		if (err == OT_ERROR_NONE) {
			s_comm_state = SRP_COMM_REMOVING;
		} else if (err == OT_ERROR_NOT_FOUND) {
			memset(&s_comm_service, 0, sizeof(s_comm_service));
			s_comm_state = SRP_COMM_FREE;
		}
	}
	openthread_mutex_unlock();
	if (err != OT_ERROR_NONE && err != OT_ERROR_NOT_FOUND) {
		LOG_WRN("commissionable SRP removal refused (%d); retaining its owned slot", err);
		return MATTER_E_STATE;
	}
	(void)settings_delete(SRP_COMM_KEY);
	return MATTER_OK;
}

