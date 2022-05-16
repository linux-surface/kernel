// SPDX-License-Identifier: GPL-2.0+
/*
 * Surface System Aggregator Module (SSAM) subsystem device hubs.
 *
 * Provides device-hubs for SSAM subsystems and performs instantiation for the
 * devices managed by them.
 *
 * Copyright (C) 2020-2021 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <linux/surface_aggregator/device.h>


/* -- SSAM generic subsystem hub driver framework. -------------------------- */

enum ssam_hub_state {
	SSAM_HUB_UNINITIALIZED,
	SSAM_HUB_CONNECTED,
	SSAM_HUB_DISCONNECTED,
};

struct ssam_hub {
	struct ssam_device *sdev;

	enum ssam_hub_state state;
	struct delayed_work update_work;
	unsigned long connect_delay;

	struct ssam_event_notifier notif;

	int (*get_state)(struct ssam_hub *hub, enum ssam_hub_state *state);
};

static void ssam_hub_update_workfn(struct work_struct *work)
{
	struct ssam_hub *hub = container_of(work, struct ssam_hub, update_work.work);
	enum ssam_hub_state state;
	int status = 0;

	status = hub->get_state(hub, &state);
	if (status)
		return;

	if (hub->state == state)
		return;
	hub->state = state;

	if (hub->state == SSAM_HUB_CONNECTED)
		status = ssam_device_register_clients(hub->sdev);
	else
		ssam_remove_clients(&hub->sdev->dev);

	if (status)
		dev_err(&hub->sdev->dev, "failed to update hub child devices: %d\n", status);
}

static int ssam_hub_mark_hot_removed(struct device *dev, void *_data)
{
	struct ssam_device *sdev = to_ssam_device(dev);

	if (is_ssam_device(dev))
		ssam_device_mark_hot_removed(sdev);

	return 0;
}

static void ssam_hub_update(struct ssam_hub *hub, bool connected)
{
	unsigned long delay;

	/* Mark devices as hot-removed before we remove any */
	if (!connected)
		device_for_each_child_reverse(&hub->sdev->dev, NULL, ssam_hub_mark_hot_removed);

	/*
	 * Delay update when the base/keyboard cover is being connected to give
	 * devices/EC some time to set up.
	 */
	delay = connected ? hub->connect_delay : 0;

	schedule_delayed_work(&hub->update_work, delay);
}

static int __maybe_unused ssam_hub_resume(struct device *dev)
{
	struct ssam_hub *hub = dev_get_drvdata(dev);

	schedule_delayed_work(&hub->update_work, 0);
	return 0;
}
static SIMPLE_DEV_PM_OPS(ssam_hub_pm_ops, NULL, ssam_hub_resume);

static int ssam_hub_setup(struct ssam_device *sdev, struct ssam_hub *hub)
{
	int status;

	hub->sdev = sdev;
	hub->state = SSAM_HUB_UNINITIALIZED;

	INIT_DELAYED_WORK(&hub->update_work, ssam_hub_update_workfn);

	ssam_device_set_drvdata(sdev, hub);

	status = ssam_device_notifier_register(sdev, &hub->notif);
	if (status)
		return status;

	schedule_delayed_work(&hub->update_work, 0);
	return 0;
}

static void ssam_hub_remove(struct ssam_device *sdev)
{
	struct ssam_hub *hub = ssam_device_get_drvdata(sdev);

	ssam_device_notifier_unregister(sdev, &hub->notif);
	cancel_delayed_work_sync(&hub->update_work);
	ssam_remove_clients(&sdev->dev);
}


/* -- SSAM base-hub driver. ------------------------------------------------- */

/*
 * Some devices (especially battery) may need a bit of time to be fully usable
 * after being (re-)connected. This delay has been determined via
 * experimentation.
 */
#define SSAM_BASE_UPDATE_CONNECT_DELAY		msecs_to_jiffies(2500)

SSAM_DEFINE_SYNC_REQUEST_R(ssam_bas_query_opmode, u8, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x0d,
	.instance_id     = 0x00,
});

#define SSAM_BAS_OPMODE_TABLET		0x00
#define SSAM_EVENT_BAS_CID_CONNECTION	0x0c

static int ssam_base_hub_query_state(struct ssam_hub *hub, enum ssam_hub_state *state)
{
	u8 opmode;
	int status;

	status = ssam_retry(ssam_bas_query_opmode, hub->sdev->ctrl, &opmode);
	if (status < 0) {
		dev_err(&hub->sdev->dev, "failed to query base state: %d\n", status);
		return status;
	}

	if (opmode != SSAM_BAS_OPMODE_TABLET)
		*state = SSAM_HUB_CONNECTED;
	else
		*state = SSAM_HUB_DISCONNECTED;

	return 0;
}

static u32 ssam_base_hub_notif(struct ssam_event_notifier *nf, const struct ssam_event *event)
{
	struct ssam_hub *hub = container_of(nf, struct ssam_hub, notif);

	if (event->command_id != SSAM_EVENT_BAS_CID_CONNECTION)
		return 0;

	if (event->length < 1) {
		dev_err(&hub->sdev->dev, "unexpected payload size: %u\n", event->length);
		return 0;
	}

	ssam_hub_update(hub, event->data[0]);

	/*
	 * Do not return SSAM_NOTIF_HANDLED: The event should be picked up and
	 * consumed by the detachment system driver. We're just a (more or less)
	 * silent observer.
	 */
	return 0;
}

static int ssam_base_hub_probe(struct ssam_device *sdev)
{
	struct ssam_hub *hub;

	hub = devm_kzalloc(&sdev->dev, sizeof(*hub), GFP_KERNEL);
	if (!hub)
		return -ENOMEM;

	hub->notif.base.priority = INT_MAX;  /* This notifier should run first. */
	hub->notif.base.fn = ssam_base_hub_notif;
	hub->notif.event.reg = SSAM_EVENT_REGISTRY_SAM;
	hub->notif.event.id.target_category = SSAM_SSH_TC_BAS,
	hub->notif.event.id.instance = 0,
	hub->notif.event.mask = SSAM_EVENT_MASK_NONE;
	hub->notif.event.flags = SSAM_EVENT_SEQUENCED;

	hub->connect_delay = SSAM_BASE_UPDATE_CONNECT_DELAY;
	hub->get_state = ssam_base_hub_query_state;

	return ssam_hub_setup(sdev, hub);
}

static const struct ssam_device_id ssam_base_hub_match[] = {
	{ SSAM_VDEV(HUB, 0x02, SSAM_ANY_IID, 0x00) },
	{ },
};

static struct ssam_device_driver ssam_base_hub_driver = {
	.probe = ssam_base_hub_probe,
	.remove = ssam_hub_remove,
	.match_table = ssam_base_hub_match,
	.driver = {
		.name = "surface_aggregator_base_hub",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
		.pm = &ssam_hub_pm_ops,
	},
};


/* -- SSAM KIP-subsystem hub driver. ---------------------------------------- */

/*
 * Some devices may need a bit of time to be fully usable after being
 * (re-)connected. This delay has been determined via experimentation.
 */
#define SSAM_KIP_UPDATE_CONNECT_DELAY		msecs_to_jiffies(250)

#define SSAM_EVENT_KIP_CID_CONNECTION		0x2c

SSAM_DEFINE_SYNC_REQUEST_R(__ssam_kip_get_connection_state, u8, {
	.target_category = SSAM_SSH_TC_KIP,
	.target_id       = 0x01,
	.command_id      = 0x2c,
	.instance_id     = 0x00,
});

static int ssam_kip_get_connection_state(struct ssam_hub *hub, enum ssam_hub_state *state)
{
	int status;
	u8 connected;

	status = ssam_retry(__ssam_kip_get_connection_state, hub->sdev->ctrl, &connected);
	if (status < 0) {
		dev_err(&hub->sdev->dev, "failed to query KIP connection state: %d\n", status);
		return status;
	}

	*state = connected ? SSAM_HUB_CONNECTED : SSAM_HUB_DISCONNECTED;
	return 0;
}

static u32 ssam_kip_hub_notif(struct ssam_event_notifier *nf, const struct ssam_event *event)
{
	struct ssam_hub *hub = container_of(nf, struct ssam_hub, notif);

	if (event->command_id != SSAM_EVENT_KIP_CID_CONNECTION)
		return 0;	/* Return "unhandled". */

	if (event->length < 1) {
		dev_err(&hub->sdev->dev, "unexpected payload size: %u\n", event->length);
		return 0;
	}

	ssam_hub_update(hub, event->data[0]);
	return SSAM_NOTIF_HANDLED;
}

static int ssam_kip_hub_probe(struct ssam_device *sdev)
{
	struct ssam_hub *hub;

	hub = devm_kzalloc(&sdev->dev, sizeof(*hub), GFP_KERNEL);
	if (!hub)
		return -ENOMEM;

	hub->notif.base.priority = INT_MAX;  /* This notifier should run first. */
	hub->notif.base.fn = ssam_kip_hub_notif;
	hub->notif.event.reg = SSAM_EVENT_REGISTRY_SAM;
	hub->notif.event.id.target_category = SSAM_SSH_TC_KIP,
	hub->notif.event.id.instance = 0,
	hub->notif.event.mask = SSAM_EVENT_MASK_TARGET;
	hub->notif.event.flags = SSAM_EVENT_SEQUENCED;

	hub->connect_delay = SSAM_KIP_UPDATE_CONNECT_DELAY;
	hub->get_state = ssam_kip_get_connection_state;

	return ssam_hub_setup(sdev, hub);
}

static const struct ssam_device_id ssam_kip_hub_match[] = {
	{ SSAM_SDEV(KIP, 0x01, 0x00, 0x00) },
	{ },
};

static struct ssam_device_driver ssam_kip_hub_driver = {
	.probe = ssam_kip_hub_probe,
	.remove = ssam_hub_remove,
	.match_table = ssam_kip_hub_match,
	.driver = {
		.name = "surface_kip_hub",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
		.pm = &ssam_hub_pm_ops,
	},
};


/* -- Module initialization. ------------------------------------------------ */

/* Combined match table, keep up-to-date with individual tables above. */
static const struct ssam_device_id ssam_hub_match[] = {
	{ SSAM_VDEV(HUB, 0x02, SSAM_ANY_IID, 0x00) },
	{ SSAM_SDEV(KIP, 0x01, 0x00, 0x00) },
	{ },
};
MODULE_DEVICE_TABLE(ssam, ssam_hub_match);

static int __init ssam_device_hub_init(void)
{
	int status;

	status = ssam_device_driver_register(&ssam_base_hub_driver);
	if (status)
		goto err_base;

	status = ssam_device_driver_register(&ssam_kip_hub_driver);
	if (status)
		goto err_kip;

	return 0;

err_kip:
	ssam_device_driver_unregister(&ssam_base_hub_driver);
err_base:
	return status;
}
module_init(ssam_device_hub_init);

static void __exit ssam_device_hub_exit(void)
{
	ssam_device_driver_unregister(&ssam_kip_hub_driver);
	ssam_device_driver_unregister(&ssam_base_hub_driver);
}
module_exit(ssam_device_hub_exit);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Subsystem device hubs for Surface System Aggregator Module");
MODULE_LICENSE("GPL");
