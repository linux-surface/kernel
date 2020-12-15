// SPDX-License-Identifier: GPL-2.0
/* Author: Dan Scally <djrscally@gmail.com> */
#include <linux/acpi.h>
#include <linux/gpio/consumer.h>
#include <linux/gpio/machine.h>
#include <linux/i2c.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/regulator/driver.h>

#include "int3472.h"

/*
 * The regulators have to have .ops to be valid, but the only ops we actually
 * support are .enable and .disable which are handled via .ena_gpiod. Pass an
 * empty struct to clear the check without lying about capabilities.
 */
static const struct regulator_ops int3472_gpio_regulator_ops = { 0 };

static int int3472_map_gpio_to_sensor(struct int3472_device *int3472,
				      struct acpi_resource *ares, char *func)
{
	char *path = ares->data.gpio.resource_source.string_ptr;
	struct gpiod_lookup table_entry;
	struct acpi_device *adev;
	acpi_handle handle;
	acpi_status status;
	int ret;

	/* Make sure we don't overflow, and leave room for a terminator */
	if (int3472->n_sensor_gpios >= INT3472_MAX_SENSOR_GPIOS) {
		dev_warn(&int3472->sensor->dev, "Too many GPIOs mapped\n");
		return -EINVAL;
	}

	/* Fetch ACPI handle for the GPIO chip  */
	status = acpi_get_handle(NULL, path, &handle);
	if (ACPI_FAILURE(status))
		return -EINVAL;

	ret = acpi_bus_get_device(handle, &adev);
	if (ret)
		return -ENODEV;

	table_entry = (struct gpiod_lookup)GPIO_LOOKUP_IDX(acpi_dev_name(adev),
							   ares->data.gpio.pin_table[0],
							   func, 0, GPIO_ACTIVE_HIGH);

	memcpy(&int3472->gpios.table[int3472->n_sensor_gpios], &table_entry,
	       sizeof(table_entry));
	int3472->n_sensor_gpios++;

	return 0;
}

static struct int3472_sensor_regulator_map *
int3472_get_sensor_supply_map(struct int3472_device *int3472)
{
	struct int3472_sensor_regulator_map *ret;
	union acpi_object *obj;
	unsigned int i;

	/*
	 * Sensor modules seem to be identified by a unique string. We use that
	 * to make sure we pass the right device and supply names to the new
	 * regulator's consumer_supplies
	 */
	obj = acpi_evaluate_dsm_typed(int3472->sensor->handle,
				      &cio2_sensor_module_guid, 0x00,
				      0x01, NULL, ACPI_TYPE_STRING);

	if (!obj) {
		dev_err(&int3472->sensor->dev,
			"Failed to get sensor module string from _DSM\n");
		return ERR_PTR(-ENODEV);
	}

	if (obj->string.type != ACPI_TYPE_STRING) {
		dev_err(&int3472->sensor->dev,
			"Sensor _DSM returned a non-string value\n");
		ret = ERR_PTR(-EINVAL);
		goto out_free_obj;
	}

	ret = ERR_PTR(-ENODEV);
	for (i = 0; i < ARRAY_SIZE(int3472_sensor_regulator_maps); i++) {
		if (!strcmp(int3472_sensor_regulator_maps[i].sensor_module_name,
			    obj->string.pointer)) {
			ret = &int3472_sensor_regulator_maps[i];
			goto out_free_obj;
		}
	}

out_free_obj:
	ACPI_FREE(obj);
	return ret;
}

static int int3472_register_regulator(struct int3472_device *int3472,
				      struct acpi_resource *ares)
{
	char *path = ares->data.gpio.resource_source.string_ptr;
	struct int3472_sensor_regulator_map *regulator_map;
	struct regulator_init_data init_data = { };
	struct int3472_gpio_regulator *regulator;
	struct regulator_config cfg = { };
	int ret;

	/*
	* We lookup supply names from machine specific tables, based on a
	* unique identifier in the sensor's _DSM
	*/
	regulator_map = int3472_get_sensor_supply_map(int3472);
	if (IS_ERR_OR_NULL(regulator_map)) {
		dev_err(&int3472->sensor->dev,
			"Found no supplies defined for this sensor\n");
		return PTR_ERR(regulator_map);
	}

	if (int3472->n_regulators >= regulator_map->n_supplies) {
		dev_err(&int3472->sensor->dev,
			"All known supplies are already mapped\n");
		return -EINVAL;
	}

	init_data.supply_regulator = NULL;
	init_data.constraints.valid_ops_mask = REGULATOR_CHANGE_STATUS;
	init_data.num_consumer_supplies = 1;
	init_data.consumer_supplies = &regulator_map->supplies[int3472->n_regulators];

	regulator = kmalloc(sizeof(*regulator), GFP_KERNEL);
	if (!regulator)
		return -ENOMEM;

	snprintf(regulator->regulator_name, GPIO_REGULATOR_NAME_LENGTH,
		 "gpio-regulator-%d", int3472->n_regulators);
	snprintf(regulator->supply_name, GPIO_REGULATOR_SUPPLY_NAME_LENGTH,
		 "supply-%d", int3472->n_regulators);

	regulator->rdesc = INT3472_REGULATOR(regulator->regulator_name,
					     regulator->supply_name,
					     int3472->n_regulators,
					     &int3472_gpio_regulator_ops);

	regulator->gpio = acpi_get_gpiod(path, ares->data.gpio.pin_table[0]);
	if (IS_ERR(regulator->gpio)) {
		ret = PTR_ERR(regulator->gpio);
		goto err_free_regulator;
	}

	cfg.dev = &int3472->adev->dev;
	cfg.init_data = &init_data;
	cfg.ena_gpiod = regulator->gpio;

	regulator->rdev = regulator_register(&regulator->rdesc, &cfg);
	if (IS_ERR(regulator->rdev)) {
		ret = PTR_ERR(regulator->rdev);
		goto err_free_gpio;
	}

	list_add(&regulator->list, &int3472->regulators);
	int3472->n_regulators++;

	return 0;

err_free_gpio:
	gpiod_put(regulator->gpio);
err_free_regulator:
	kfree(regulator);

	return ret;
}

static int int3472_handle_gpio_resources(struct acpi_resource *ares,
					 void *data)
{
	struct int3472_device *int3472 = data;
	union acpi_object *obj;
	int ret = 0;

	if (ares->type != ACPI_RESOURCE_TYPE_GPIO ||
	    ares->data.gpio.connection_type != ACPI_RESOURCE_GPIO_TYPE_IO)
		return EINVAL; /* Deliberately positive */

	/*
	 * n_gpios + 2 because the index of this _DSM function is 1-based and
	 * the first function is just a count.
	 */
	obj = acpi_evaluate_dsm_typed(int3472->adev->handle,
				      &int3472_gpio_guid, 0x00,
				      int3472->n_gpios + 2,
				      NULL, ACPI_TYPE_INTEGER);

	if (!obj) {
		dev_warn(&int3472->adev->dev,
			 "No _DSM entry for this GPIO pin\n");
		return ENODEV;
	}

	switch (obj->integer.value & 0xff) { /* low byte holds type data */
	case 0x00: /* Purpose unclear, possibly a reset GPIO pin */
		ret = int3472_map_gpio_to_sensor(int3472, ares, "reset");
		if (ret)
			dev_warn(&int3472->adev->dev,
				 "Failed to map reset pin to sensor\n");

		break;
	case 0x01: /* Power regulators (we think) */
	case 0x0c:
		ret = int3472_register_regulator(int3472, ares);
		if (ret)
			dev_warn(&int3472->adev->dev,
				 "Failed to map regulator to sensor\n");

		break;
	case 0x0b: /* Power regulators, but to a device separate to sensor */
		ret = int3472_register_regulator(int3472, ares);
		if (ret)
			dev_warn(&int3472->adev->dev,
				 "Failed to map regulator to sensor\n");

		break;
	case 0x0d: /* Indicator LEDs */
		ret = int3472_map_gpio_to_sensor(int3472, ares, "indicator-led");
		if (ret)
			dev_warn(&int3472->adev->dev,
				 "Failed to map indicator led to sensor\n");

		break;
	default:
		/* if we've gotten here, we're not sure what they are yet */
		dev_warn(&int3472->adev->dev,
			 "GPIO type 0x%llx unknown; the sensor may not work\n",
			 (obj->integer.value & 0xff));
		ret = EINVAL;
	}

	int3472->n_gpios++;
	ACPI_FREE(obj);
	return abs(ret);
}

static void int3472_parse_crs(struct int3472_device *int3472)
{
	struct list_head resource_list;

	INIT_LIST_HEAD(&resource_list);

	acpi_dev_get_resources(int3472->adev, &resource_list,
			       int3472_handle_gpio_resources, int3472);

	acpi_dev_free_resource_list(&resource_list);
	gpiod_add_lookup_table(&int3472->gpios);
}

static int int3472_add(struct acpi_device *adev)
{
	struct acpi_buffer buffer = { ACPI_ALLOCATE_BUFFER, NULL };
	struct int3472_device *int3472;
	struct int3472_cldb cldb;
	union acpi_object *obj;
	acpi_status status;
	int ret = 0;

	/*
	 * This driver is only intended to support "dummy" INT3472 devices
	 * which appear in ACPI designed for Windows. These are distinguishable
	 * from INT3472 entries representing an actual tps68470 PMIC through
	 * the presence of a CLDB buffer with a particular value set.
	 */
	status = acpi_evaluate_object(adev->handle, "CLDB", NULL, &buffer);
	if (ACPI_FAILURE(status))
		return -ENODEV;

	obj = buffer.pointer;
	if (!obj) {
		dev_err(&adev->dev, "ACPI device has no CLDB object\n");
		return -ENODEV;
	}

	if (obj->type != ACPI_TYPE_BUFFER) {
		dev_err(&adev->dev, "CLDB object is not an ACPI buffer\n");
		ret = -EINVAL;
		goto out_free_buff;
	}

	if (obj->buffer.length > sizeof(cldb)) {
		dev_err(&adev->dev, "The CLDB buffer is too large\n");
		ret = -EINVAL;
		goto out_free_buff;
	}

	memcpy(&cldb, obj->buffer.pointer, obj->buffer.length);

	/*
	 * control_logic_type = 1 indicates this is a dummy INT3472 device of
	 * the kind we're looking for. If any other value then we shouldn't try
	 * to handle it
	 */
	if (cldb.control_logic_type != 1) {
		ret = -EINVAL;
		goto out_free_buff;
	}

	/* Space for 4 GPIOs - one more than we've seen so far plus a null */
	int3472 = kzalloc(sizeof(*int3472) +
			 ((INT3472_MAX_SENSOR_GPIOS + 1) * sizeof(struct gpiod_lookup)),
			 GFP_KERNEL);
	if (!int3472) {
		ret = -ENOMEM;
		goto out_free_buff;
	}

	int3472->adev = adev;
	adev->driver_data = int3472;

	int3472->sensor = acpi_dev_get_next_dep_dev(adev, NULL);
	if (!int3472->sensor) {
		dev_err(&adev->dev,
			"This INT3472 entry seems to have no dependents.\n");
		ret = -ENODEV;
		goto out_free_int3472;
	}

	int3472->gpios.dev_id = i2c_acpi_dev_name(int3472->sensor);

	INIT_LIST_HEAD(&int3472->regulators);

	int3472_parse_crs(int3472);

	goto out_free_buff;

out_free_int3472:
	kfree(int3472);
out_free_buff:
	kfree(buffer.pointer);
	return ret;
}

static int int3472_remove(struct acpi_device *adev)
{
	struct int3472_gpio_regulator *reg;
	struct int3472_device *int3472;

	int3472 = acpi_driver_data(adev);

	acpi_dev_put(int3472->sensor);
	gpiod_remove_lookup_table(&int3472->gpios);

	list_for_each_entry(reg, &int3472->regulators, list) {
		gpiod_put(reg->gpio);
		regulator_unregister(reg->rdev);
	}

	kfree(int3472);

	return 0;
}

static const struct acpi_device_id int3472_device_id[] = {
	{ "INT3472", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, int3472_device_id);

static struct acpi_driver int3472_driver = {
	.name = "int3472",
	.ids = int3472_device_id,
	.ops = {
		.add = int3472_add,
		.remove = int3472_remove,
	},
	.owner = THIS_MODULE,
};

module_acpi_driver(int3472_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Dan Scally <djrscally@gmail.com>");
MODULE_DESCRIPTION("ACPI Driver for Discrete type INT3472 ACPI Devices");
