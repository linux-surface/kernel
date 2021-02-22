// SPDX-License-Identifier: GPL-2.0
/* Author: Dan Scally <djrscally@gmail.com> */

#include <linux/acpi.h>
#include <linux/clkdev.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/platform_device.h>
#include <linux/regulator/driver.h>
#include <linux/slab.h>

#include "intel_skl_int3472_common.h"

/*
 * 79234640-9e10-4fea-a5c1-b5aa8b19756f
 * This _DSM GUID returns information about the GPIO lines mapped to a
 * discrete INT3472 device. Function number 1 returns a count of the GPIO
 * lines that are mapped. Subsequent functions return 32 bit ints encoding
 * information about the GPIO line, including its purpose.
 */
static const guid_t int3472_gpio_guid =
	GUID_INIT(0x79234640, 0x9e10, 0x4fea,
		  0xa5, 0xc1, 0xb5, 0xaa, 0x8b, 0x19, 0x75, 0x6f);

/*
 * 822ace8f-2814-4174-a56b-5f029fe079ee
 * This _DSM GUID returns a string from the sensor device, which acts as a
 * module identifier.
 */
static const guid_t cio2_sensor_module_guid =
	GUID_INIT(0x822ace8f, 0x2814, 0x4174,
		  0xa5, 0x6b, 0x5f, 0x02, 0x9f, 0xe0, 0x79, 0xee);

/*
 * Here follows platform specific mapping information that we can pass to
 * the functions mapping resources to the sensors. Where the sensors have
 * a power enable pin defined in DSDT we need to provide a supply name so
 * the sensor drivers can find the regulator. The device name will be derived
 * from the sensor's ACPI device within the code. Optionally, we can provide a
 * NULL terminated array of function name mappings to deal with any platform
 * specific deviations from the documented behaviour of GPIOs.
 *
 * Map a GPIO function name to NULL to prevent the driver from mapping that
 * GPIO at all.
 */

static const struct int3472_gpio_function_remap ov2680_gpio_function_remaps[] = {
	{ "reset", NULL },
	{ "powerdown", "reset" },
	{ }
};

static struct int3472_sensor_config int3472_sensor_configs[] = {
	/* Lenovo Miix 510-12ISK - OV2680, Front */
	{ "GNDF140809R", { 0 }, ov2680_gpio_function_remaps},
	/* Lenovo Miix 510-12ISK - OV5648, Rear */
	{ "GEFF150023R", REGULATOR_SUPPLY("avdd", NULL), NULL},
	/* Surface Go 1&2 - OV5693, Front */
	{ "YHCU", REGULATOR_SUPPLY("avdd", NULL), NULL},
};

/*
 * The regulators have to have .ops to be valid, but the only ops we actually
 * support are .enable and .disable which are handled via .ena_gpiod. Pass an
 * empty struct to clear the check without lying about capabilities.
 */
static const struct regulator_ops int3472_gpio_regulator_ops = { 0 };

static int skl_int3472_clk_prepare(struct clk_hw *hw)
{
	struct int3472_gpio_clock *clk = to_int3472_clk(hw);

	gpiod_set_value(clk->ena_gpio, 1);
	if (clk->led_gpio)
		gpiod_set_value(clk->led_gpio, 1);

	return 0;
}

static void skl_int3472_clk_unprepare(struct clk_hw *hw)
{
	struct int3472_gpio_clock *clk = to_int3472_clk(hw);

	gpiod_set_value(clk->ena_gpio, 0);
	if (clk->led_gpio)
		gpiod_set_value(clk->led_gpio, 0);
}

static int skl_int3472_clk_enable(struct clk_hw *hw)
{
	/*
	 * We're just turning a GPIO on to enable, which operation has the
	 * potential to sleep. Given enable cannot sleep, but prepare can,
	 * we toggle the GPIO in prepare instead. Thus, nothing to do here.
	 */
	return 0;
}

static void skl_int3472_clk_disable(struct clk_hw *hw)
{
	/* Likewise, nothing to do here... */
}

static unsigned int skl_int3472_get_clk_frequency(struct int3472_discrete_device *int3472)
{
	union acpi_object *obj;
	unsigned int ret = 0;

	obj = skl_int3472_get_acpi_buffer(int3472->sensor, "SSDB");
	if (IS_ERR(obj))
		return 0; /* report rate as 0 on error */

	if (obj->buffer.length < CIO2_SENSOR_SSDB_MCLKSPEED_OFFSET + sizeof(u32)) {
		dev_err(int3472->dev, "The buffer is too small\n");
		goto out_free_buff;
	}

	ret = *(u32 *)(obj->buffer.pointer + CIO2_SENSOR_SSDB_MCLKSPEED_OFFSET);

out_free_buff:
	kfree(obj);
	return ret;
}

static unsigned long skl_int3472_clk_recalc_rate(struct clk_hw *hw,
						 unsigned long parent_rate)
{
	struct int3472_gpio_clock *clk = to_int3472_clk(hw);
	struct int3472_discrete_device *int3472 = to_int3472_device(clk);

	return int3472->clock.frequency;
}

static const struct clk_ops skl_int3472_clock_ops = {
	.prepare = skl_int3472_clk_prepare,
	.unprepare = skl_int3472_clk_unprepare,
	.enable = skl_int3472_clk_enable,
	.disable = skl_int3472_clk_disable,
	.recalc_rate = skl_int3472_clk_recalc_rate,
};

static struct int3472_sensor_config *
skl_int3472_get_sensor_module_config(struct int3472_discrete_device *int3472)
{
	struct int3472_sensor_config *ret;
	union acpi_object *obj;
	unsigned int i;

	obj = acpi_evaluate_dsm_typed(int3472->sensor->handle,
				      &cio2_sensor_module_guid, 0x00,
				      0x01, NULL, ACPI_TYPE_STRING);

	if (!obj) {
		dev_err(int3472->dev,
			"Failed to get sensor module string from _DSM\n");
		return ERR_PTR(-ENODEV);
	}

	if (obj->string.type != ACPI_TYPE_STRING) {
		dev_err(int3472->dev,
			"Sensor _DSM returned a non-string value\n");
		ret = ERR_PTR(-EINVAL);
		goto out_free_obj;
	}

	ret = NULL;
	for (i = 0; i < ARRAY_SIZE(int3472_sensor_configs); i++) {
		if (!strcmp(int3472_sensor_configs[i].sensor_module_name,
			    obj->string.pointer)) {
			ret = &int3472_sensor_configs[i];
			break;
		}
	}

out_free_obj:
	ACPI_FREE(obj);
	return ret;
}

static int skl_int3472_map_gpio_to_sensor(struct int3472_discrete_device *int3472,
					  struct acpi_resource *ares,
					  char *func, u32 polarity)
{
	char *path = ares->data.gpio.resource_source.string_ptr;
	const struct int3472_sensor_config *sensor_config;
	struct gpiod_lookup *table_entry;
	struct acpi_device *adev;
	acpi_handle handle;
	acpi_status status;
	int ret;

	if (int3472->n_sensor_gpios >= INT3472_MAX_SENSOR_GPIOS) {
		dev_warn(int3472->dev, "Too many GPIOs mapped\n");
		return -EINVAL;
	}

	sensor_config = int3472->sensor_config;
	if (!IS_ERR_OR_NULL(sensor_config) && sensor_config->function_maps) {
		const struct int3472_gpio_function_remap *remap =
			sensor_config->function_maps;

		for (; remap->documented; ++remap)
			if (!strcmp(func, remap->documented)) {
				func = remap->actual;
				break;
			}
	}

	/* Functions mapped to NULL should not be mapped to the sensor */
	if (!func)
		return 0;

	status = acpi_get_handle(NULL, path, &handle);
	if (ACPI_FAILURE(status))
		return -EINVAL;

	ret = acpi_bus_get_device(handle, &adev);
	if (ret)
		return -ENODEV;

	table_entry = &int3472->gpios.table[int3472->n_sensor_gpios];
	table_entry->key = acpi_dev_name(adev);
	table_entry->chip_hwnum = ares->data.gpio.pin_table[0];
	table_entry->con_id = func;
	table_entry->idx = 0;
	table_entry->flags = polarity;

	int3472->n_sensor_gpios++;

	return 0;
}

static int skl_int3472_map_gpio_to_clk(struct int3472_discrete_device *int3472,
				       struct acpi_resource *ares, u8 type)
{
	char *path = ares->data.gpio.resource_source.string_ptr;
	struct gpio_desc *gpio;

	switch (type) {
	case INT3472_GPIO_TYPE_CLK_ENABLE:
		gpio = acpi_get_gpiod(path, ares->data.gpio.pin_table[0],
				      "int3472,clk-enable");
		if (IS_ERR(gpio))
			return (PTR_ERR(gpio));

		int3472->clock.ena_gpio = gpio;
		break;
	case INT3472_GPIO_TYPE_PRIVACY_LED:
		gpio = acpi_get_gpiod(path, ares->data.gpio.pin_table[0],
				      "int3472,privacy-led");
		if (IS_ERR(gpio))
			return (PTR_ERR(gpio));

		int3472->clock.led_gpio = gpio;
		break;
	default:
		dev_err(int3472->dev, "Invalid GPIO type 0x%hx for clock\n",
			type);
		break;
	}

	return 0;
}

static int skl_int3472_register_clock(struct int3472_discrete_device *int3472)
{
	struct clk_init_data init = {
		.ops = &skl_int3472_clock_ops,
		.flags = CLK_GET_RATE_NOCACHE,
	};
	int ret = 0;

	init.name = kasprintf(GFP_KERNEL, "%s-clk",
			      acpi_dev_name(int3472->adev));
	if (!init.name)
		return -ENOMEM;

	int3472->clock.frequency = skl_int3472_get_clk_frequency(int3472);

	int3472->clock.clk_hw.init = &init;
	int3472->clock.clk = clk_register(&int3472->adev->dev,
					  &int3472->clock.clk_hw);
	if (IS_ERR(int3472->clock.clk)) {
		ret = PTR_ERR(int3472->clock.clk);
		goto out_free_init_name;
	}

	int3472->clock.cl = clkdev_create(int3472->clock.clk, NULL,
					  int3472->sensor_name);
	if (!int3472->clock.cl) {
		ret = -ENOMEM;
		goto err_unregister_clk;
	}

	goto out_free_init_name;

err_unregister_clk:
	clk_unregister(int3472->clock.clk);
out_free_init_name:
	kfree(init.name);

	return ret;
}

static int skl_int3472_register_regulator(struct int3472_discrete_device *int3472,
					  struct acpi_resource *ares)
{
	char *path = ares->data.gpio.resource_source.string_ptr;
	struct int3472_sensor_config *sensor_config;
	struct regulator_init_data init_data = { };
	struct regulator_config cfg = { };
	int ret;

	sensor_config = int3472->sensor_config;
	if (IS_ERR_OR_NULL(sensor_config)) {
		dev_err(int3472->dev, "No sensor module config\n");
		return PTR_ERR(sensor_config);
	}

	if (!sensor_config->supply_map.supply) {
		dev_err(int3472->dev, "No supply name defined\n");
		return -ENODEV;
	}

	init_data.constraints.valid_ops_mask = REGULATOR_CHANGE_STATUS;
	init_data.num_consumer_supplies = 1;
	sensor_config->supply_map.dev_name = int3472->sensor_name;
	init_data.consumer_supplies = &sensor_config->supply_map;

	snprintf(int3472->regulator.regulator_name,
		 sizeof(int3472->regulator.regulator_name), "%s-regulator",
		 acpi_dev_name(int3472->adev));
	snprintf(int3472->regulator.supply_name,
		 GPIO_REGULATOR_SUPPLY_NAME_LENGTH, "supply-0");

	int3472->regulator.rdesc = INT3472_REGULATOR(
						int3472->regulator.regulator_name,
						int3472->regulator.supply_name,
						&int3472_gpio_regulator_ops);

	int3472->regulator.gpio = acpi_get_gpiod(path,
						 ares->data.gpio.pin_table[0],
						 "int3472,regulator");
	if (IS_ERR(int3472->regulator.gpio)) {
		dev_err(int3472->dev, "Failed to get regulator GPIO lines\n");
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
 * skl_int3472_handle_gpio_resources: Map PMIC resources to consuming sensor
 * @ares: A pointer to a &struct acpi_resource
 * @data: A pointer to a &struct int3472_discrete_device
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
 * do not actually correspond to a physical connection. These will be handled
 * by the mapping sub-functions.
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
	struct int3472_discrete_device *int3472 = data;
	u16 pin = ares->data.gpio.pin_table[0];
	union acpi_object *obj;
	char *err_msg;
	int ret = 0;
	u8 type;

	if (ares->type != ACPI_RESOURCE_TYPE_GPIO ||
	    ares->data.gpio.connection_type != ACPI_RESOURCE_GPIO_TYPE_IO)
		return 1; /* Deliberately positive so parsing continues */

	/*
	 * n_gpios + 2 because the index of this _DSM function is 1-based and
	 * the first function is just a count.
	 */
	obj = acpi_evaluate_dsm_typed(int3472->adev->handle,
				      &int3472_gpio_guid, 0x00,
				      int3472->n_gpios + 2,
				      NULL, ACPI_TYPE_INTEGER);

	if (!obj) {
		dev_warn(int3472->dev, "No _DSM entry for GPIO pin %u\n", pin);
		return 1;
	}

	type = obj->integer.value & 0xff;

	switch (type) {
	case INT3472_GPIO_TYPE_RESET:
		ret = skl_int3472_map_gpio_to_sensor(int3472, ares, "reset",
						     GPIO_ACTIVE_LOW);
		if (ret)
			err_msg = "Failed to map reset pin to sensor\n";

		break;
	case INT3472_GPIO_TYPE_POWERDOWN:
		ret = skl_int3472_map_gpio_to_sensor(int3472, ares,
						     "powerdown",
						     GPIO_ACTIVE_LOW);
		if (ret)
			err_msg = "Failed to map powerdown pin to sensor\n";

		break;
	case INT3472_GPIO_TYPE_CLK_ENABLE:
	case INT3472_GPIO_TYPE_PRIVACY_LED:
		ret = skl_int3472_map_gpio_to_clk(int3472, ares, type);
		if (ret)
			err_msg = "Failed to map GPIO to clock\n";

		break;
	case INT3472_GPIO_TYPE_POWER_ENABLE:
		ret = skl_int3472_register_regulator(int3472, ares);
		if (ret)
			err_msg = "Failed to map regulator to sensor\n";

		break;
	default:
		dev_warn(int3472->dev,
			 "GPIO type 0x%02x unknown; the sensor may not work\n",
			 type);
		ret = 1;
		break;
	}

	if (ret < 0 && ret != -EPROBE_DEFER)
		dev_err(int3472->dev, err_msg);

	int3472->n_gpios++;
	ACPI_FREE(obj);

	return ret;
}

static int skl_int3472_parse_crs(struct int3472_discrete_device *int3472)
{
	struct list_head resource_list;
	int ret;

	INIT_LIST_HEAD(&resource_list);

	int3472->sensor_config = skl_int3472_get_sensor_module_config(int3472);

	ret = acpi_dev_get_resources(int3472->adev, &resource_list,
				     skl_int3472_handle_gpio_resources,
				     int3472);
	if (ret)
		goto out_free_res_list;

	if (int3472->clock.ena_gpio) {
		ret = skl_int3472_register_clock(int3472);
		if (ret)
			goto out_free_res_list;
	} else {
		if (int3472->clock.led_gpio)
			dev_warn(int3472->dev,
				 "No clk GPIO. The privacy LED won't work\n");
	}

	int3472->gpios.dev_id = int3472->sensor_name;
	gpiod_add_lookup_table(&int3472->gpios);

out_free_res_list:
	acpi_dev_free_resource_list(&resource_list);

	return ret;
}

int skl_int3472_discrete_probe(struct platform_device *pdev)
{
	struct acpi_device *adev = ACPI_COMPANION(&pdev->dev);
	struct int3472_discrete_device *int3472;
	struct int3472_cldb cldb;
	int ret;

	ret = skl_int3472_fill_cldb(adev, &cldb);
	if (ret) {
		dev_err(&pdev->dev, "Couldn't fill CLDB structure\n");
		return ret;
	}

	if (cldb.control_logic_type != 1) {
		dev_err(&pdev->dev, "Unsupported control logic type %u\n",
			cldb.control_logic_type);
		return -EINVAL;
	}

	/* Max num GPIOs we've seen plus a terminator */
	int3472 = kzalloc(struct_size(int3472, gpios.table,
			  INT3472_MAX_SENSOR_GPIOS + 1), GFP_KERNEL);
	if (!int3472)
		return -ENOMEM;

	int3472->adev = adev;
	int3472->dev = &pdev->dev;
	platform_set_drvdata(pdev, int3472);

	int3472->sensor = acpi_dev_get_dependent_dev(adev);
	if (IS_ERR_OR_NULL(int3472->sensor)) {
		dev_err(&pdev->dev,
			"INT3472 seems to have no dependents.\n");
		ret = -ENODEV;
		goto err_free_int3472;
	}
	get_device(&int3472->sensor->dev);

	int3472->sensor_name = kasprintf(GFP_KERNEL, I2C_DEV_NAME_FORMAT,
					 acpi_dev_name(int3472->sensor));

	ret = skl_int3472_parse_crs(int3472);
	if (ret) {
		skl_int3472_discrete_remove(pdev);
		return ret;
	}

	return 0;

err_free_int3472:
	kfree(int3472);
	return ret;
}

int skl_int3472_discrete_remove(struct platform_device *pdev)
{
	struct int3472_discrete_device *int3472 = platform_get_drvdata(pdev);

	if (int3472->gpios.dev_id)
		gpiod_remove_lookup_table(&int3472->gpios);

	if (!IS_ERR(int3472->regulator.rdev))
		regulator_unregister(int3472->regulator.rdev);

	if (!IS_ERR(int3472->clock.clk))
		clk_unregister(int3472->clock.clk);

	if (int3472->clock.cl)
		clkdev_drop(int3472->clock.cl);

	gpiod_put(int3472->regulator.gpio);
	gpiod_put(int3472->clock.ena_gpio);
	gpiod_put(int3472->clock.led_gpio);

	acpi_dev_put(int3472->sensor);

	kfree(int3472->sensor_name);
	kfree(int3472);

	return 0;
}
