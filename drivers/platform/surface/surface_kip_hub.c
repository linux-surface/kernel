// SPDX-License-Identifier: GPL-2.0+
/*
 * Surface System Aggregator Module (SSAM) client device hub for KIP subsystem.
 *
 * Copyright (C) 2021 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <linux/surface_aggregator/controller.h>
#include <linux/surface_aggregator/device.h>

/*
 * Some devices may need a bit of time to be fully usable after being
 * (re-)connected. This delay has been determined via experimentation.
 * 
 * FIXME: If we ever move battery devices here, this might need to be
 * increased.
 */
#define SSAM_KIP_UPDATE_CONNECT_DELAY		msecs_to_jiffies(250)

#define SSAM_EVENT_KIP_CID_CONNECTION		0x2c

enum ssam_kip_hub_state {
	SSAM_KIP_HUB_UNINITIALIZED,
	SSAM_KIP_HUB_CONNECTED,
	SSAM_KIP_HUB_DISCONNECTED,
};

struct ssam_kip_hub {
	struct ssam_device *sdev;

	enum ssam_kip_hub_state state;
	struct delayed_work update_work;

	struct ssam_event_notifier notif;
};

SSAM_DEFINE_SYNC_REQUEST_R(__ssam_kip_get_connection_state, u8, {
	.target_category = SSAM_SSH_TC_KIP,
	.target_id       = 0x01,
	.command_id      = 0x2c,
	.instance_id     = 0x00,
});

static int ssam_kip_get_connection_state(struct ssam_kip_hub *hub, enum ssam_kip_hub_state *state)
{
	int status;
	u8 connected;

	status = ssam_retry(__ssam_kip_get_connection_state, hub->sdev->ctrl, &connected);
	if (status < 0) {
		dev_err(&hub->sdev->dev, "failed to query KIP connection state: %d\n", status);
		return status;
	}

	*state = connected ? SSAM_KIP_HUB_CONNECTED : SSAM_KIP_HUB_DISCONNECTED;
	return 0;
}

static ssize_t ssam_kip_hub_state_show(struct device *dev, struct device_attribute *attr,
					char *buf)
{
	struct ssam_kip_hub *hub = dev_get_drvdata(dev);
	bool connected = hub->state == SSAM_KIP_HUB_CONNECTED;

	return sysfs_emit(buf, "%d\n", connected);
}

static struct device_attribute ssam_kip_hub_attr_state =
	__ATTR(state, 0444, ssam_kip_hub_state_show, NULL);

static struct attribute *ssam_kip_hub_attrs[] = {
	&ssam_kip_hub_attr_state.attr,
	NULL,
};

static const struct attribute_group ssam_kip_hub_group = {
	.attrs = ssam_kip_hub_attrs,
};

static void ssam_kip_hub_update_workfn(struct work_struct *work)
{
	struct ssam_kip_hub *hub = container_of(work, struct ssam_kip_hub, update_work.work);
	enum ssam_kip_hub_state state;
	int status = 0;

	status = ssam_kip_get_connection_state(hub, &state);
	if (status)
		return;

	if (hub->state == state)
		return;
	hub->state = state;

	if (hub->state == SSAM_KIP_HUB_CONNECTED)
		status = ssam_of_register_clients(hub->sdev->ctrl, &hub->sdev->dev);
	else
		ssam_hot_remove_clients(&hub->sdev->dev);

	if (status)
		dev_err(&hub->sdev->dev, "failed to update KIP-hub devices: %d\n", status);
}

static u32 ssam_kip_hub_notif(struct ssam_event_notifier *nf, const struct ssam_event *event)
{
	struct ssam_kip_hub *hub = container_of(nf, struct ssam_kip_hub, notif);
	unsigned long delay;

	if (event->command_id != SSAM_EVENT_KIP_CID_CONNECTION)
		return 0;	/* Return "unhandled". */

	if (event->length < 1) {
		dev_err(&hub->sdev->dev, "unexpected payload size: %u\n", event->length);
		return 0;
	}

	/*
	 * Delay update when KIP devices are being connected to give devices/EC
	 * some time to set up.
	 */
	delay = event->data[0] ? SSAM_KIP_UPDATE_CONNECT_DELAY : 0;

	schedule_delayed_work(&hub->update_work, delay);

	return SSAM_NOTIF_HANDLED;
}

static int __maybe_unused ssam_kip_hub_resume(struct device *dev)
{
	struct ssam_kip_hub *hub = dev_get_drvdata(dev);

	schedule_delayed_work(&hub->update_work, 0);
	return 0;
}
static SIMPLE_DEV_PM_OPS(ssam_kip_hub_pm_ops, NULL, ssam_kip_hub_resume);

static int ssam_kip_hub_probe(struct ssam_device *sdev)
{
	struct ssam_kip_hub *hub;
	int status;

	hub = devm_kzalloc(&sdev->dev, sizeof(*hub), GFP_KERNEL);
	if (!hub)
		return -ENOMEM;

	hub->sdev = sdev;
	hub->state = SSAM_KIP_HUB_UNINITIALIZED;

	hub->notif.base.priority = INT_MAX;  /* This notifier should run first. */
	hub->notif.base.fn = ssam_kip_hub_notif;
	hub->notif.event.reg = SSAM_EVENT_REGISTRY_SAM;
	hub->notif.event.id.target_category = SSAM_SSH_TC_KIP,
	hub->notif.event.id.instance = 0,
	hub->notif.event.mask = SSAM_EVENT_MASK_TARGET;
	hub->notif.event.flags = SSAM_EVENT_SEQUENCED;

	INIT_DELAYED_WORK(&hub->update_work, ssam_kip_hub_update_workfn);

	ssam_device_set_drvdata(sdev, hub);

	status = ssam_device_notifier_register(sdev, &hub->notif);
	if (status)
		return status;

	status = sysfs_create_group(&sdev->dev.kobj, &ssam_kip_hub_group);
	if (status)
		goto err;

	schedule_delayed_work(&hub->update_work, 0);
	return 0;

err:
	ssam_device_notifier_unregister(sdev, &hub->notif);
	cancel_delayed_work_sync(&hub->update_work);
	ssam_remove_clients(&sdev->dev);
	return status;
}

static void ssam_kip_hub_remove(struct ssam_device *sdev)
{
	struct ssam_kip_hub *hub = ssam_device_get_drvdata(sdev);

	sysfs_remove_group(&sdev->dev.kobj, &ssam_kip_hub_group);

	ssam_device_notifier_unregister(sdev, &hub->notif);
	cancel_delayed_work_sync(&hub->update_work);
	ssam_remove_clients(&sdev->dev);
}

static const struct ssam_device_id ssam_kip_hub_match[] = {
	{ SSAM_SDEV(KIP, 0x01, 0x00, 0x00) },
	{ },
};
MODULE_DEVICE_TABLE(ssam, ssam_kip_hub_match);

static struct ssam_device_driver ssam_kip_hub_driver = {
	.probe = ssam_kip_hub_probe,
	.remove = ssam_kip_hub_remove,
	.match_table = ssam_kip_hub_match,
	.driver = {
		.name = "surface_kip_hub",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
		.pm = &ssam_kip_hub_pm_ops,
	},
};
module_ssam_device_driver(ssam_kip_hub_driver);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("HUB for Surface System Aggregator KIP client devices");
MODULE_LICENSE("GPL");
