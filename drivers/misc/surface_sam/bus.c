// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/device.h>
#include <linux/uuid.h>

#include "bus.h"
#include "controller.h"


static ssize_t modalias_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct ssam_device *sdev = to_ssam_device(dev);

	return snprintf(buf, PAGE_SIZE - 1, "ssam:c%02Xt%02Xi%02xf%02X\n",
			sdev->uid.category, sdev->uid.channel,
			sdev->uid.instance, sdev->uid.function);
}
static DEVICE_ATTR_RO(modalias);

static struct attribute *ssam_device_attrs[] = {
	&dev_attr_modalias.attr,
	NULL,
};
ATTRIBUTE_GROUPS(ssam_device);

static int ssam_device_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct ssam_device *sdev = to_ssam_device(dev);

	return add_uevent_var(env, "MODALIAS=ssam:c%02Xt%02Xi%02xf%02X",
			      sdev->uid.category, sdev->uid.channel,
			      sdev->uid.instance, sdev->uid.function);
}

static void ssam_device_release(struct device *dev)
{
	struct ssam_device *sdev = to_ssam_device(dev);

	ssam_controller_put(sdev->ctrl);
	kfree(sdev);
}

const struct device_type ssam_device_type = {
	.name    = "ssam_client",
	.groups  = ssam_device_groups,
	.uevent  = ssam_device_uevent,
	.release = ssam_device_release,
};
EXPORT_SYMBOL_GPL(ssam_device_type);


struct ssam_device *ssam_device_alloc(struct ssam_controller *ctrl,
				      struct ssam_device_uid uid)
{
	struct ssam_device *sdev;

	sdev = kzalloc(sizeof(*sdev), GFP_KERNEL);
	if (!sdev)
		return NULL;

	device_initialize(&sdev->dev);
	sdev->dev.bus = &ssam_bus_type;
	sdev->dev.type = &ssam_device_type;
	sdev->dev.parent = ssam_controller_device(ctrl);
	sdev->ctrl = ssam_controller_get(ctrl);
	sdev->uid = uid;

	dev_set_name(&sdev->dev, "%02x:%02x:%02x:%02x",
		     sdev->uid.category, sdev->uid.channel, sdev->uid.instance,
		     sdev->uid.function);

	return sdev;
}
EXPORT_SYMBOL_GPL(ssam_device_alloc);

int ssam_device_add(struct ssam_device *sdev)
{
	enum ssam_controller_state state;
	int status;

	/*
	 * Ensure that we can only add new devices to a controller if it has
	 * been started and is not going away soon. This works in combination
	 * with ssam_controller_remove_clients to ensure driver presence for the
	 * controller device, i.e. it ensures that the controller (sdev->ctrl)
	 * is always valid and can be used for requests as long as the client
	 * device we add here is registered as child under it. This essentially
	 * guarantees that the client driver can always expect the preconditions
	 * for functions like ssam_request_sync (controller has to be started
	 * and is not suspended) to hold and thus does not have to check for
	 * them.
	 *
	 * Note that for this to work, the controller has to be a parent device.
	 * If it is not a direct parent, care has to be taken that the device is
	 * removed via ssam_device_remove, as device_unregister does not remove
	 * child devices recursively.
	 */
	ssam_controller_statelock(sdev->ctrl);

	state = smp_load_acquire(&sdev->ctrl->state);
	if (state != SSAM_CONTROLLER_STARTED) {
		ssam_controller_stateunlock(sdev->ctrl);
		return -ENXIO;
	}

	status = device_add(&sdev->dev);

	ssam_controller_stateunlock(sdev->ctrl);
	return status;
}
EXPORT_SYMBOL_GPL(ssam_device_add);

void ssam_device_remove(struct ssam_device *sdev)
{
	device_unregister(&sdev->dev);
}
EXPORT_SYMBOL_GPL(ssam_device_remove);


static inline bool ssam_device_id_compatible(const struct ssam_device_id *id,
					     struct ssam_device_uid uid)
{
	if (id->category != uid.category)
		return false;

	if ((id->match_flags & SSAM_MATCH_CHANNEL) && id->channel != uid.channel)
		return false;

	if ((id->match_flags & SSAM_MATCH_INSTANCE) && id->instance != uid.instance)
		return false;

	if ((id->match_flags & SSAM_MATCH_FUNCTION) && id->function != uid.function)
		return false;

	return true;
}

static inline bool ssam_device_id_is_null(const struct ssam_device_id *id)
{
	return id->category == 0
		&& id->channel == 0
		&& id->instance == 0
		&& id->function == 0;
}

const struct ssam_device_id *ssam_device_id_match(
		const struct ssam_device_id *table,
		const struct ssam_device_uid uid)
{
	const struct ssam_device_id *id;

	for (id = table; !ssam_device_id_is_null(id); ++id)
		if (ssam_device_id_compatible(id, uid))
			return id;

	return NULL;
}
EXPORT_SYMBOL_GPL(ssam_device_id_match);

const struct ssam_device_id *ssam_device_get_match(
		const struct ssam_device *dev)
{
	const struct ssam_device_driver *sdrv;

	sdrv = to_ssam_device_driver(dev->dev.driver);
	if (!sdrv)
		return NULL;

	if (!sdrv->match_table)
		return NULL;

	return ssam_device_id_match(sdrv->match_table, dev->uid);
}
EXPORT_SYMBOL_GPL(ssam_device_get_match);

const void *ssam_device_get_match_data(const struct ssam_device *dev)
{
	const struct ssam_device_id *id;

	id = ssam_device_get_match(dev);
	if (!id)
		return NULL;

	return (const void *)id->driver_data;
}
EXPORT_SYMBOL_GPL(ssam_device_get_match_data);


static int ssam_bus_match(struct device *dev, struct device_driver *drv)
{
	struct ssam_device_driver *sdrv = to_ssam_device_driver(drv);
	struct ssam_device *sdev = to_ssam_device(dev);

	if (!is_ssam_device(dev))
		return 0;

	return !!ssam_device_id_match(sdrv->match_table, sdev->uid);
}

static int ssam_bus_probe(struct device *dev)
{
	struct ssam_device_driver *sdrv = to_ssam_device_driver(dev->driver);

	return sdrv->probe(to_ssam_device(dev));
}

static int ssam_bus_remove(struct device *dev)
{
	struct ssam_device_driver *sdrv = to_ssam_device_driver(dev->driver);

	if (sdrv->remove)
		sdrv->remove(to_ssam_device(dev));

	return 0;
}

struct bus_type ssam_bus_type = {
	.name   = "ssam",
	.match  = ssam_bus_match,
	.probe  = ssam_bus_probe,
	.remove = ssam_bus_remove,
};
EXPORT_SYMBOL_GPL(ssam_bus_type);


int __ssam_device_driver_register(struct ssam_device_driver *sdrv,
				  struct module *owner)
{
	sdrv->driver.owner = owner;
	sdrv->driver.bus = &ssam_bus_type;

	/* force drivers to async probe so I/O is possible in probe */
        sdrv->driver.probe_type = PROBE_PREFER_ASYNCHRONOUS;

	return driver_register(&sdrv->driver);
}
EXPORT_SYMBOL_GPL(__ssam_device_driver_register);

void ssam_device_driver_unregister(struct ssam_device_driver *sdrv)
{
	driver_unregister(&sdrv->driver);
}
EXPORT_SYMBOL_GPL(ssam_device_driver_unregister);


static int ssam_remove_device(struct device *dev, void *_data)
{
	struct ssam_device *sdev = to_ssam_device(dev);

	if (is_ssam_device(dev))
		ssam_device_remove(sdev);

	return 0;
}

/*
 * Controller lock should be held during this call and subsequent
 * de-initialization.
 */
void ssam_controller_remove_clients(struct ssam_controller *ctrl)
{
	struct device *dev = ssam_controller_device(ctrl);

	device_for_each_child_reverse(dev, NULL, ssam_remove_device);
}


int ssam_bus_register(void)
{
	return bus_register(&ssam_bus_type);
}

void ssam_bus_unregister(void) {
	return bus_unregister(&ssam_bus_type);
}
