// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * userspace-consumer.c
 *
 * Copyright 2009 CompuLab, Ltd.
 *
 * Author: Mike Rapoport <mike@compulab.co.il>
 *
 * Based of virtual consumer driver:
 *   Copyright 2008 Wolfson Microelectronics PLC.
 *   Author: Mark Brown <broonie@opensource.wolfsonmicro.com>
 */

#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regulator/consumer.h>
#include <linux/regulator/userspace-consumer.h>
#include <linux/slab.h>
#include <linux/of.h>

struct userspace_consumer_data {
	const char *name;
	bool notify_enable;
	struct notifier_block nb;
	struct mutex lock;
	bool enabled;
	unsigned long events;
	struct kobject *kobj;

	int num_supplies;
	struct regulator_bulk_data *supplies;
};

static DEFINE_MUTEX(events_lock);

static ssize_t events_show(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	struct userspace_consumer_data *data = dev_get_drvdata(dev);
	unsigned long e;

	mutex_lock(&events_lock);
	e = data->events;
	data->events = 0;
	mutex_unlock(&events_lock);

	return sprintf(buf, "0x%lx\n", e);
}

static ssize_t name_show(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct userspace_consumer_data *data = dev_get_drvdata(dev);

	return sprintf(buf, "%s\n", data->name);
}

static ssize_t state_show(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	struct userspace_consumer_data *data = dev_get_drvdata(dev);

	if (data->enabled)
		return sprintf(buf, "enabled\n");

	return sprintf(buf, "disabled\n");
}

static ssize_t state_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct userspace_consumer_data *data = dev_get_drvdata(dev);
	bool enabled;
	int ret;

	/*
	 * sysfs_streq() doesn't need the \n's, but we add them so the strings
	 * will be shared with show_state(), above.
	 */
	if (sysfs_streq(buf, "enabled\n") || sysfs_streq(buf, "1"))
		enabled = true;
	else if (sysfs_streq(buf, "disabled\n") || sysfs_streq(buf, "0"))
		enabled = false;
	else {
		dev_err(dev, "Configuring invalid mode\n");
		return count;
	}

	mutex_lock(&data->lock);
	if (enabled != data->enabled) {
		if (enabled)
			ret = regulator_bulk_enable(data->num_supplies,
						    data->supplies);
		else
			ret = regulator_bulk_disable(data->num_supplies,
						     data->supplies);

		if (ret == 0)
			data->enabled = enabled;
		else
			dev_err(dev, "Failed to configure state: %d\n", ret);
	}
	mutex_unlock(&data->lock);

	return count;
}

static DEVICE_ATTR_RO(events);
static DEVICE_ATTR_RO(name);
static DEVICE_ATTR_RW(state);

static struct attribute *attributes[] = {
	&dev_attr_name.attr,
	&dev_attr_state.attr,
	&dev_attr_events.attr,
	NULL,
};

static const struct attribute_group attr_group = {
	.attrs	= attributes,
};

static int regulator_userspace_notify(struct notifier_block *nb,
				      unsigned long event,
				      void *ignored)
{
	struct userspace_consumer_data *data =
		container_of(nb, struct userspace_consumer_data, nb);

	mutex_lock(&events_lock);
	data->events |= event;
	mutex_unlock(&events_lock);

	sysfs_notify(data->kobj, NULL, dev_attr_events.attr.name);

	return NOTIFY_OK;
}

static struct regulator_userspace_consumer_data *get_pdata_from_dt_node(
		struct platform_device *pdev)
{
	struct regulator_userspace_consumer_data *pdata;
	struct device_node *np = pdev->dev.of_node;
	struct property *prop;
	const char *supply;
	int num_supplies;
	int count = 0;

	pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return ERR_PTR(-ENOMEM);

	pdata->name = of_get_property(np, "regulator-name", NULL);
	pdata->init_on = of_property_read_bool(np, "regulator-boot-on");
	num_supplies = of_property_count_strings(np, "regulator-supplies");
	if (num_supplies < 0) {
		dev_err(&pdev->dev,
			"could not parse property regulator-supplies\n");
		return ERR_PTR(-EINVAL);
	}
	pdata->num_supplies = num_supplies;
	pdata->supplies = devm_kzalloc(&pdev->dev, num_supplies *
				sizeof(*pdata->supplies), GFP_KERNEL);
	if (!pdata->supplies)
		return ERR_PTR(-ENOMEM);

	of_property_for_each_string(np, "regulator-supplies", prop, supply)
		pdata->supplies[count++].supply = supply;

	return pdata;
}

static int regulator_userspace_consumer_probe(struct platform_device *pdev)
{
	struct regulator_userspace_consumer_data *pdata;
	struct userspace_consumer_data *drvdata;
	int ret, i;

	pdata = dev_get_platdata(&pdev->dev);
	if (!pdata && pdev->dev.of_node) {
		pdata = get_pdata_from_dt_node(pdev);
		if (IS_ERR(pdata))
			return PTR_ERR(pdata);
	}
	if (!pdata)
		return -EINVAL;

	drvdata = devm_kzalloc(&pdev->dev,
			       sizeof(struct userspace_consumer_data),
			       GFP_KERNEL);
	if (drvdata == NULL)
		return -ENOMEM;

	drvdata->name = pdata->name;
	drvdata->num_supplies = pdata->num_supplies;
	drvdata->supplies = pdata->supplies;
	drvdata->kobj = &pdev->dev.kobj;

	mutex_init(&drvdata->lock);

	ret = devm_regulator_bulk_get(&pdev->dev, drvdata->num_supplies,
				      drvdata->supplies);
	if (ret) {
		dev_err(&pdev->dev, "Failed to get supplies: %d\n", ret);
		return ret;
	}

	ret = sysfs_create_group(&pdev->dev.kobj, &attr_group);
	if (ret != 0)
		return ret;

	if (pdata->init_on) {
		ret = regulator_bulk_enable(drvdata->num_supplies,
					    drvdata->supplies);
		if (ret) {
			dev_err(&pdev->dev,
				"Failed to set initial state: %d\n", ret);
			goto err_enable;
		}
	}

	drvdata->nb.notifier_call = regulator_userspace_notify;
	for (i = 0; i < drvdata->num_supplies; i++) {
		ret = devm_regulator_register_notifier(drvdata->supplies[i].consumer, &drvdata->nb);
		if (ret)
			goto err_enable;
	}

	drvdata->enabled = pdata->init_on;

	platform_set_drvdata(pdev, drvdata);

	return 0;

err_enable:
	sysfs_remove_group(&pdev->dev.kobj, &attr_group);

	return ret;
}

static int regulator_userspace_consumer_remove(struct platform_device *pdev)
{
	struct userspace_consumer_data *data = platform_get_drvdata(pdev);

	sysfs_remove_group(&pdev->dev.kobj, &attr_group);

	if (data->enabled)
		regulator_bulk_disable(data->num_supplies, data->supplies);

	return 0;
}

static const struct of_device_id regulator_userspace_consumer_of_match[] = {
	{ .compatible = "9elements,output-supply", },
	{},
};
MODULE_DEVICE_TABLE(of, regulator_userspace_consumer_of_match);

static struct platform_driver regulator_userspace_consumer_driver = {
	.probe		= regulator_userspace_consumer_probe,
	.remove		= regulator_userspace_consumer_remove,
	.driver		= {
		.name		= "reg-userspace-consumer",
		.of_match_table = regulator_userspace_consumer_of_match,
	},
};

module_platform_driver(regulator_userspace_consumer_driver);

MODULE_AUTHOR("Mike Rapoport <mike@compulab.co.il>");
MODULE_DESCRIPTION("Userspace consumer for voltage and current regulators");
MODULE_LICENSE("GPL");
