// SPDX-License-Identifier: GPL-2.0
/* Author: Dan Scally <djrscally@gmail.com> */

#include <linux/acpi.h>
#include <linux/clkdev.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/regulator/driver.h>

#include "intel_skl_int3472_common.h"

/* 79234640-9e10-4fea-a5c1-b5aa8b19756f */
static const guid_t int3472_gpio_guid =
	GUID_INIT(0x79234640, 0x9e10, 0x4fea,
		  0xa5, 0xc1, 0xb5, 0xaa, 0x8b, 0x19, 0x75, 0x6f);

/* 822ace8f-2814-4174-a56b-5f029fe079ee */
static const guid_t cio2_sensor_module_guid =
	GUID_INIT(0x822ace8f, 0x2814, 0x4174,
		  0xa5, 0x6b, 0x5f, 0x02, 0x9f, 0xe0, 0x79, 0xee);

/*
 * Here follows platform specific mapping information that we can pass to
 * the functions mapping resources to the sensors. Where the sensors have
 * a power enable pin defined in DSDT we need to provide a supply name so
 * the sensor drivers can find the regulator. Optionally, we can provide a
 * NULL terminated array of function name mappings to deal with any platform
 * specific deviations from the documented behaviour of GPIOs.
 *
 * Map a GPIO function name to NULL to prevent the driver from mapping that
 * GPIO at all.
 */

static const struct int3472_gpio_function_remap ov2680_gpio_function_remaps[] = {
	INT3472_GPIO_FUNCTION_REMAP("reset", NULL),
	INT3472_GPIO_FUNCTION_REMAP("powerdown", "reset"),
	{ }
};

static struct int3472_sensor_config int3472_sensor_configs[] = {
	/* Lenovo Miix 510-12ISK - OV2680, Front */
	{ "GNDF140809R", { 0 }, ov2680_gpio_function_remaps},
	/* Lenovo Miix 510-12ISK - OV5648, Rear */
	{ "GEFF150023R", REGULATOR_SUPPLY("avdd", "i2c-OVTI5648:00"), NULL},
	/* Surface Go 1&2 - OV5693, Front */
	{ "YHCU", REGULATOR_SUPPLY("avdd", "i2c-INT33BE:00"), NULL},
};

/*
 * The regulators have to have .ops to be valid, but the only ops we actually
 * support are .enable and .disable which are handled via .ena_gpiod. Pass an
 * empty struct to clear the check without lying about capabilities.
 */
static const struct regulator_ops int3472_gpio_regulator_ops = { 0 };

static int skl_int3472_clk_enable(struct clk_hw *hw)
{
	struct int3472_gpio_clock *clk = to_int3472_clk(hw);

	gpiod_set_value(clk->gpio, 1);

	return 0;
}

static void skl_int3472_clk_disable(struct clk_hw *hw)
{
	struct int3472_gpio_clock *clk = to_int3472_clk(hw);

	gpiod_set_value(clk->gpio, 0);
}

static int skl_int3472_clk_prepare(struct clk_hw *hw)
{
	/*
	 * We're just turning a GPIO on to enable, so nothing to do here, but
	 * we want to provide the op so prepare_enable() works.
	 */
	return 0;
}

static void skl_int3472_clk_unprepare(struct clk_hw *hw)
{
	/* Likewise, nothing to do here... */
}

static const struct clk_ops skl_int3472_clock_ops = {
	.prepare = skl_int3472_clk_prepare,
	.unprepare = skl_int3472_clk_unprepare,
	.enable = skl_int3472_clk_enable,
	.disable = skl_int3472_clk_disable,
};

static struct int3472_sensor_config *
skl_int3472_get_sensor_module_config(struct int3472_device *int3472)
{
	unsigned int i = ARRAY_SIZE(int3472_sensor_configs);
	struct int3472_sensor_config *ret;
	union acpi_object *obj;

	obj = acpi_evaluate_dsm_typed(int3472->sensor->handle,
				      &cio2_sensor_module_guid, 0x00,
				      0x01, NULL, ACPI_TYPE_STRING);

	if (!obj) {
		dev_err(&int3472->pdev->dev,
			"Failed to get sensor module string from _DSM\n");
		return ERR_PTR(-ENODEV);
	}

	if (obj->string.type != ACPI_TYPE_STRING) {
		dev_err(&int3472->pdev->dev,
			"Sensor _DSM returned a non-string value\n");
		ret = ERR_PTR(-EINVAL);
		goto out_free_obj;
	}

	ret = ERR_PTR(-ENODEV);
	while (i--) {
		if (!strcmp(int3472_sensor_configs[i].sensor_module_name,
			    obj->string.pointer)) {
			ret = &int3472_sensor_configs[i];
			goto out_free_obj;
		}
	}

out_free_obj:
	ACPI_FREE(obj);
	return ret;
}

static int skl_int3472_map_gpio_to_sensor(struct int3472_device *int3472,
					  struct acpi_resource *ares,
					  char *func, u32 polarity)
{
	char *path = ares->data.gpio.resource_source.string_ptr;
	struct int3472_sensor_config *sensor_config;
	struct gpiod_lookup table_entry;
	struct acpi_device *adev;
	acpi_handle handle;
	acpi_status status;
	int ret;

	sensor_config = skl_int3472_get_sensor_module_config(int3472);
	if (!IS_ERR(sensor_config) && sensor_config->function_maps) {
		unsigned int i = 0;

		while (sensor_config->function_maps[i].documented) {
			if (!strcmp(func, sensor_config->function_maps[i].documented)) {
				func = sensor_config->function_maps[i].actual;

				break;
			}

			i++;
		}
	}

	if (!func)
		return 0;

	if (int3472->n_sensor_gpios >= INT3472_MAX_SENSOR_GPIOS) {
		dev_warn(&int3472->pdev->dev, "Too many GPIOs mapped\n");
		return -EINVAL;
	}

	status = acpi_get_handle(NULL, path, &handle);
	if (ACPI_FAILURE(status))
		return -EINVAL;

	ret = acpi_bus_get_device(handle, &adev);
	if (ret)
		return -ENODEV;

	table_entry = (struct gpiod_lookup)GPIO_LOOKUP_IDX(acpi_dev_name(adev),
							   ares->data.gpio.pin_table[0],
							   func, 0, polarity);

	memcpy(&int3472->gpios.table[int3472->n_sensor_gpios], &table_entry,
	       sizeof(table_entry));

	int3472->n_sensor_gpios++;

	return 0;
}

static int skl_int3472_register_clock(struct int3472_device *int3472,
				      struct acpi_resource *ares)
{
	char *path = ares->data.gpio.resource_source.string_ptr;
	struct clk_init_data init = { 0 };
	int ret = 0;

	init.name = kasprintf(GFP_KERNEL, "%s-clk",
			      acpi_dev_name(int3472->adev));
	init.ops = &skl_int3472_clock_ops;

	int3472->clock.gpio = acpi_get_gpiod(path,
					     ares->data.gpio.pin_table[0]);
	if (IS_ERR(int3472->clock.gpio)) {
		ret = PTR_ERR(int3472->clock.gpio);
		goto out_free_init_name;
	}

	int3472->clock.clk_hw.init = &init;
	int3472->clock.clk = clk_register(&int3472->adev->dev,
					  &int3472->clock.clk_hw);
	if (IS_ERR(int3472->clock.clk)) {
		ret = PTR_ERR(int3472->clock.clk);
		goto err_put_gpio;
	}

	ret = clk_register_clkdev(int3472->clock.clk, "xvclk", int3472->sensor_name);
	if (ret)
		goto err_unregister_clk;

	goto out_free_init_name;

err_unregister_clk:
	clk_unregister(int3472->clock.clk);
err_put_gpio:
	gpiod_put(int3472->clock.gpio);
out_free_init_name:
	kfree(init.name);

	return ret;
}

static int skl_int3472_register_regulator(struct int3472_device *int3472,
					  struct acpi_resource *ares)
{
	char *path = ares->data.gpio.resource_source.string_ptr;
	struct int3472_sensor_config *sensor_config;
	struct regulator_init_data init_data = { };
	struct regulator_config cfg = { };
	int ret;

	sensor_config = skl_int3472_get_sensor_module_config(int3472);
	if (IS_ERR_OR_NULL(sensor_config)) {
		dev_err(&int3472->pdev->dev, "No sensor module config\n");
		return PTR_ERR(sensor_config);
	}

	if (!sensor_config->supply_map.supply) {
		dev_err(&int3472->pdev->dev, "No supply name defined\n");
		return -ENODEV;
	}

	init_data.supply_regulator = NULL;
	init_data.constraints.valid_ops_mask = REGULATOR_CHANGE_STATUS;
	init_data.num_consumer_supplies = 1;
	init_data.consumer_supplies = &sensor_config->supply_map;

	snprintf(int3472->regulator.regulator_name,
		 GPIO_REGULATOR_NAME_LENGTH, "int3472-discrete-regulator");
	snprintf(int3472->regulator.supply_name,
		 GPIO_REGULATOR_SUPPLY_NAME_LENGTH, "supply-0");

	int3472->regulator.rdesc = INT3472_REGULATOR(
						int3472->regulator.regulator_name,
						int3472->regulator.supply_name,
						&int3472_gpio_regulator_ops);

	int3472->regulator.gpio = acpi_get_gpiod(path,
						 ares->data.gpio.pin_table[0]);
	if (IS_ERR(int3472->regulator.gpio)) {
		dev_err(&int3472->pdev->dev, "Failed to get GPIO line\n");
		return PTR_ERR(int3472->regulator.gpio);
	}

	cfg.dev = &int3472->adev->dev;
	cfg.init_data = &init_data;
	cfg.ena_gpiod = int3472->regulator.gpio;

	int3472->regulator.rdev = regulator_register(&int3472->regulator.rdesc,
						     &cfg);
	if (IS_ERR(int3472->regulator.rdev)) {
		ret = PTR_ERR(int3472->regulator.rdev);
		goto err_free_gpio;
	}

	return 0;

err_free_gpio:
	gpiod_put(int3472->regulator.gpio);

	return ret;
}

/**
 * skl_int3472_handle_gpio_resources: maps PMIC resources to consuming sensor
 * @ares: A pointer to a &struct acpi_resource
 * @data: A pointer to a &struct int3472_device
 *
 * This function handles GPIO resources that are against an INT3472
 * ACPI device, by checking the value of the corresponding _DSM entry.
 * This will return a 32bit int, where the lowest byte represents the
 * function of the GPIO pin:
 *
 * 0x00 Reset
 * 0x01 Power down
 * 0x0b Power enable
 * 0x0c Clock enable
 * 0x0d Privacy LED
 *
 * There are some known platform specific quirks where that does not quite
 * hold up; for example where a pin with type 0x01 (Power down) is mapped to
 * a sensor pin that performs a reset function or entries in _CRS and _DSM that
 * do not actually correspond to a physical connection. These will be handled by
 * the mapping sub-functions.
 *
 * GPIOs will either be mapped directly to the sensor device or else used
 * to create clocks and regulators via the usual frameworks.
 *
 * Return:
 * * 0		- When all resources found are handled properly.
 * * -EINVAL	- If the resource is not a GPIO IO resource
 * * -ENODEV	- If the resource has no corresponding _DSM entry
 * * -Other	- Errors propagated from one of the sub-functions.
 */
static int skl_int3472_handle_gpio_resources(struct acpi_resource *ares,
					     void *data)
{
	struct int3472_device *int3472 = data;
	union acpi_object *obj;
	int ret = 0;

	if (ares->type != ACPI_RESOURCE_TYPE_GPIO ||
	    ares->data.gpio.connection_type != ACPI_RESOURCE_GPIO_TYPE_IO)
		return EINVAL; /* Deliberately positive so parsing continues */

	/*
	 * n_gpios + 2 because the index of this _DSM function is 1-based and
	 * the first function is just a count.
	 */
	obj = acpi_evaluate_dsm_typed(int3472->adev->handle,
				      &int3472_gpio_guid, 0x00,
				      int3472->n_gpios + 2,
				      NULL, ACPI_TYPE_INTEGER);

	if (!obj) {
		dev_warn(&int3472->pdev->dev,
			 "No _DSM entry for this GPIO pin\n");
		return ENODEV;
	}

	switch (obj->integer.value & 0xff) {
	case INT3472_GPIO_TYPE_RESET:
		ret = skl_int3472_map_gpio_to_sensor(int3472, ares, "reset",
						     GPIO_ACTIVE_LOW);
		if (ret)
			dev_err(&int3472->pdev->dev,
				"Failed to map reset pin to sensor\n");

		break;
	case INT3472_GPIO_TYPE_POWERDOWN:
		ret = skl_int3472_map_gpio_to_sensor(int3472, ares, "powerdown",
						     GPIO_ACTIVE_LOW);
		if (ret)
			dev_err(&int3472->pdev->dev,
				"Failed to map powerdown pin to sensor\n");

		break;
	case INT3472_GPIO_TYPE_CLK_ENABLE:
		ret = skl_int3472_register_clock(int3472, ares);
		if (ret)
			dev_err(&int3472->pdev->dev,
				"Failed to map clock to sensor\n");

		break;
	case INT3472_GPIO_TYPE_POWER_ENABLE:
		ret = skl_int3472_register_regulator(int3472, ares);
		if (ret) {
			dev_err(&int3472->pdev->dev,
				"Failed to map regulator to sensor\n");
		}

		break;
	case INT3472_GPIO_TYPE_PRIVACY_LED:
		ret = skl_int3472_map_gpio_to_sensor(int3472, ares,
						     "indicator-led",
						     GPIO_ACTIVE_HIGH);
		if (ret)
			dev_err(&int3472->pdev->dev,
				"Failed to map indicator led to sensor\n");

		break;
	default:
		dev_warn(&int3472->pdev->dev,
			 "GPIO type 0x%llx unknown; the sensor may not work\n",
			 (obj->integer.value & 0xff));
		ret = EINVAL;
	}

	int3472->n_gpios++;
	ACPI_FREE(obj);

	return ret;
}

static int skl_int3472_parse_crs(struct int3472_device *int3472)
{
	struct list_head resource_list;
	int ret = 0;

	INIT_LIST_HEAD(&resource_list);

	ret = acpi_dev_get_resources(int3472->adev, &resource_list,
				     skl_int3472_handle_gpio_resources,
				     int3472);

	if (!ret) {
		gpiod_add_lookup_table(&int3472->gpios);
		int3472->gpios_mapped = true;
	}

	acpi_dev_free_resource_list(&resource_list);

	return ret;
}

int skl_int3472_discrete_probe(struct platform_device *pdev)
{
	struct acpi_device *adev = ACPI_COMPANION(&pdev->dev);
	struct int3472_device *int3472;
	struct int3472_cldb cldb;
	int ret = 0;

	ret = skl_int3472_fill_cldb(adev, &cldb);
	if (ret || cldb.control_logic_type != 1)
		return -EINVAL;

	int3472 = kzalloc(sizeof(*int3472) +
			 ((INT3472_MAX_SENSOR_GPIOS + 1) * sizeof(struct gpiod_lookup)),
			 GFP_KERNEL);
	if (!int3472)
		return -ENOMEM;

	int3472->adev = adev;
	int3472->pdev = pdev;
	platform_set_drvdata(pdev, int3472);

	int3472->sensor = acpi_dev_get_next_dep_dev(adev, NULL);
	if (!int3472->sensor) {
		dev_err(&pdev->dev,
			"This INT3472 entry seems to have no dependents.\n");
		ret = -ENODEV;
		goto err_free_int3472;
	}
	int3472->sensor_name = kasprintf(GFP_KERNEL, I2C_DEV_NAME_FORMAT, acpi_dev_name(int3472->sensor));
	int3472->gpios.dev_id = int3472->sensor_name;

	ret = skl_int3472_parse_crs(int3472);
	if (ret) {
		skl_int3472_discrete_remove(pdev);
		goto err_return_ret;
	}

	return 0;

err_free_int3472:
	kfree(int3472);
err_return_ret:
	return ret;
}

int skl_int3472_discrete_remove(struct platform_device *pdev)
{
	struct int3472_device *int3472;

	int3472 = platform_get_drvdata(pdev);

	if (int3472->gpios_mapped)
		gpiod_remove_lookup_table(&int3472->gpios);

	if (!IS_ERR_OR_NULL(int3472->regulator.rdev)) {
		gpiod_put(int3472->regulator.gpio);
		regulator_unregister(int3472->regulator.rdev);
	}

	if (!IS_ERR_OR_NULL(int3472->clock.clk)) {
		gpiod_put(int3472->clock.gpio);
		clk_unregister(int3472->clock.clk);
	}

	acpi_dev_put(int3472->sensor);

	kfree(int3472->sensor_name);
	kfree(int3472);

	return 0;
}
