/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file tm_identify.h
 * @brief The Identify cluster, as a module an application puts on an endpoint
 *        (tm_app.h): IdentifyTime, IdentifyType, Identify and TriggerEffect.
 *
 * The Door Lock device type requires it (matter-devices.xml, MA-doorlock), and
 * tm_door_lock_endpoint lists it after the Door Lock. Revision 6 and the
 * mandatory set from identify-cluster.xml. The node does no identifying of its
 * own: the application's hooks do, if it installs any.
 */
#pragma once

#include <stdint.h>

#include <tinytalk/tm_app.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MATTER_CLUSTER_IDENTIFY          0x0003u
#define MATTER_IDENTIFY_CLUSTER_REVISION 6u

#define MATTER_ATTR_IDENTIFY_TIME 0x0000u
#define MATTER_ATTR_IDENTIFY_TYPE 0x0001u

#define MATTER_CMD_IDENTIFY       0x00u
#define MATTER_CMD_TRIGGER_EFFECT 0x40u

/* IdentifyTypeEnum. */
#define MATTER_IDENTIFY_TYPE_NONE              0x00u
#define MATTER_IDENTIFY_TYPE_LIGHT_OUTPUT      0x01u
#define MATTER_IDENTIFY_TYPE_VISIBLE_INDICATOR 0x02u
#define MATTER_IDENTIFY_TYPE_AUDIBLE_BEEP      0x03u
#define MATTER_IDENTIFY_TYPE_DISPLAY           0x04u
#define MATTER_IDENTIFY_TYPE_ACTUATOR          0x05u

/* EffectIdentifierEnum. */
#define MATTER_IDENTIFY_EFFECT_BLINK          0x00u
#define MATTER_IDENTIFY_EFFECT_BREATHE        0x01u
#define MATTER_IDENTIFY_EFFECT_OKAY           0x02u
#define MATTER_IDENTIFY_EFFECT_CHANNEL_CHANGE 0x0Bu
#define MATTER_IDENTIFY_EFFECT_FINISH         0xFEu
#define MATTER_IDENTIFY_EFFECT_STOP           0xFFu

/**
 * What the application does when asked to identify. Both run with the node's
 * lock held (tm_app.h), so they start something and return. Either may be
 * NULL.
 */
struct tm_identify_hooks {
	/** Identify for @p seconds; 0 means stop. */
	void (*identify)(uint16_t endpoint, uint16_t seconds);
	/** Run one effect (an EffectIdentifierEnum value). */
	void (*effect)(uint16_t endpoint, uint8_t effect, uint8_t variant);
};

/**
 * Set what IdentifyType reports and the hooks that do the identifying. Until
 * it is called IdentifyType is None and nothing is called. Call before
 * matter_commission_init(); @p hooks must outlive the node.
 */
void tm_identify_configure(uint8_t identify_type, const struct tm_identify_hooks *hooks);

extern const struct tm_cluster tm_identify;

#ifdef __cplusplus
}
#endif
