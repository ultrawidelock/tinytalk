/* SPDX-License-Identifier: ISC */

/*
 * tinytalk door-lock sample.
 *
 * Boot order, learned from the source project's commissioning glue:
 *
 *   1. PSA Crypto, then settings: the fabric store and OpenThread keep their
 *      state there, and the node signs and derives with PSA.
 *   2. Bluetooth, then the Matter node (matter_commission_init), which restores
 *      any stored fabric and, with Thread, rejoins the network.
 *   3. Advertise the 0xFFF6 commissionable service while there is no fabric.
 *
 * From there the commissioner drives it: PASE over BLE, the fabric added over
 * CASE, then the Thread attach and the SRP registration, both done by the node
 * and ports/zephyr/thread.
 *
 * The Door Lock cluster (clusters/door_lock) sits on endpoint 1 and drives
 * LED0: on while unlocked. Button 0: a short
 * press opens a basic commissioning window for WINDOW_S seconds; a press held
 * for FACTORY_RESET_MS erases the stored fabrics and reboots.
 */
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/reboot.h>

#include <psa/crypto.h>

#include <tinytalk/matter_commission.h>
#include <tinytalk/matter_fab_store.h>
#include <tinytalk/tm_door_lock.h>

#include "matter_ble_zephyr.h"

LOG_MODULE_REGISTER(door_lock, LOG_LEVEL_INF);

#define WINDOW_S         900u
#define FACTORY_RESET_MS 5000

static const struct matter_commission_config s_matter_cfg = {
	.vendor_id = CONFIG_TINYTALK_VENDOR_ID,
	.product_id = CONFIG_TINYTALK_PRODUCT_ID,
	.verifier_hex = CONFIG_TINYTALK_SPAKE2P_VERIFIER,
	.salt_hex = CONFIG_TINYTALK_SPAKE2P_SALT,
	.iterations = CONFIG_TINYTALK_SPAKE2P_ITERATIONS,
	.product_name = "tinytalk door lock",
	.hardware_version = 1u,
	.software_version = 1u,
	.endpoints = &tm_door_lock_endpoint,
	.n_endpoints = 1u,
};

static const struct gpio_dt_spec s_led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
static const struct gpio_dt_spec s_button = GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);

/* ---- advertising ------------------------------------------------------------
 *
 * The node asks for this through matter_commission_readvertise() with its own
 * lock held, so the work is done here, on the system work queue.
 */
static uint8_t s_svc_data[MATTER_BLE_SVC_DATA_LEN];

static void adv_work_fn(struct k_work *work)
{
	bool want = !matter_commission_has_fabric() || matter_commission_window_open();
	const struct bt_data ad[] = {
		BT_DATA_BYTES(BT_DATA_FLAGS, BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR),
		BT_DATA(BT_DATA_SVC_DATA16, s_svc_data, sizeof(s_svc_data)),
	};
	int rc;

	ARG_UNUSED(work);
	/* The GATT table follows the advert: no commissioning service while the
	 * node is not offering to be commissioned. -EBUSY means a link is up and
	 * the next pass will try again. */
	(void)matter_ble_publish(want);
	(void)bt_le_adv_stop();
	if (!want) {
		return;
	}
	if (matter_ble_commissionable_svc_data(s_svc_data, sizeof(s_svc_data)) != 0) {
		LOG_ERR("no commissionable payload");
		return;
	}
	rc = bt_le_adv_start(BT_LE_ADV_PARAM(BT_LE_ADV_OPT_CONN, BT_GAP_ADV_FAST_INT_MIN_2,
					     BT_GAP_ADV_FAST_INT_MAX_2, NULL),
			     ad, ARRAY_SIZE(ad), NULL, 0);
	if (rc != 0 && rc != -EALREADY) {
		LOG_ERR("advertising failed (%d)", rc);
	}
}
static K_WORK_DEFINE(s_adv_work, adv_work_fn);

void matter_commission_readvertise(void)
{
	k_work_submit(&s_adv_work);
}

/* A connection stops connectable advertising; the next one starts when the
 * connection object is free again. */
static void on_recycled(void)
{
	k_work_submit(&s_adv_work);
}

BT_CONN_CB_DEFINE(s_conn_cb) = {
	.recycled = on_recycled,
};

/* ---- the bolt ---------------------------------------------------------------- */

void tm_door_lock_actuate(uint8_t lock_state)
{
	(void)gpio_pin_set_dt(&s_led, lock_state == MATTER_DL_LOCK_STATE_UNLOCKED);
	LOG_INF("door %s", lock_state == MATTER_DL_LOCK_STATE_UNLOCKED ? "unlocked" : "locked");
}

/* ---- the button --------------------------------------------------------------- */

static struct gpio_callback s_button_cb;
static int64_t s_pressed_at;

static void factory_reset_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	if (gpio_pin_get_dt(&s_button) != 1) {
		return;
	}
	LOG_WRN("button held: factory reset");
	(void)matter_fab_erase();
	sys_reboot(SYS_REBOOT_COLD);
}
static K_WORK_DELAYABLE_DEFINE(s_factory_reset_work, factory_reset_fn);

static void open_window_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	if (matter_commission_open_window(WINDOW_S) == 0) {
		LOG_INF("commissioning window open for %u s", WINDOW_S);
	} else {
		LOG_INF("commissioning window already open");
	}
}
static K_WORK_DEFINE(s_open_window_work, open_window_fn);

static void on_button(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(cb);
	ARG_UNUSED(pins);
	if (gpio_pin_get_dt(&s_button) == 1) {
		s_pressed_at = k_uptime_get();
		(void)k_work_reschedule(&s_factory_reset_work, K_MSEC(FACTORY_RESET_MS));
		return;
	}
	(void)k_work_cancel_delayable(&s_factory_reset_work);
	if (k_uptime_get() - s_pressed_at < FACTORY_RESET_MS) {
		k_work_submit(&s_open_window_work);
	}
}

static int button_init(void)
{
	int rc;

	if (!gpio_is_ready_dt(&s_button)) {
		return -ENODEV;
	}
	rc = gpio_pin_configure_dt(&s_button, GPIO_INPUT);
	if (rc == 0) {
		rc = gpio_pin_interrupt_configure_dt(&s_button, GPIO_INT_EDGE_BOTH);
	}
	if (rc == 0) {
		gpio_init_callback(&s_button_cb, on_button, BIT(s_button.pin));
		rc = gpio_add_callback(s_button.port, &s_button_cb);
	}
	return rc;
}

int main(void)
{
	int rc;

	if (gpio_is_ready_dt(&s_led)) {
		(void)gpio_pin_configure_dt(&s_led, GPIO_OUTPUT_INACTIVE);
	}
	if (button_init() != 0) {
		LOG_WRN("no button: commissioning window and factory reset unavailable");
	}

	if (psa_crypto_init() != PSA_SUCCESS) {
		LOG_ERR("PSA Crypto did not start");
		return 0;
	}
	rc = settings_subsys_init();
	if (rc != 0) {
		LOG_ERR("settings did not start (%d)", rc);
		return 0;
	}
	rc = bt_enable(NULL);
	if (rc != 0) {
		LOG_ERR("Bluetooth did not start (%d)", rc);
		return 0;
	}
	rc = matter_commission_init(&s_matter_cfg);
	if (rc != 0) {
		LOG_ERR("Matter node did not start (%d)", rc);
		return 0;
	}

	LOG_INF("manual pairing code %s, discriminator 0x%03x", TM_SAMPLE_MANUAL_CODE,
		CONFIG_TINYTALK_DISCRIMINATOR);
	matter_commission_readvertise();
	return 0;
}
