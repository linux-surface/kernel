// SPDX-License-Identifier: GPL-2.0
/* Author: Dan Scally <djrscally@gmail.com> */

#include <linux/i2c.h>
#include <linux/mfd/tps68470.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

#include "intel_skl_int3472_common.h"

static const struct regmap_config tps68470_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	.max_register = TPS68470_REG_MAX,
};

static int tps68470_chip_init(struct device *dev, struct regmap *regmap)
{
	unsigned int version;
	int ret;

	/* Force software reset */
	ret = regmap_write(regmap, TPS68470_REG_RESET, TPS68470_REG_RESET_MASK);
	if (ret)
		return ret;

	ret = regmap_read(regmap, TPS68470_REG_REVID, &version);
	if (ret) {
		dev_err(dev, "Failed to read revision register: %d\n", ret);
		return ret;
	}

	dev_info(dev, "TPS68470 REVID: 0x%x\n", version);

	return 0;
}

static struct platform_device *
skl_int3472_register_pdev(const char *name, struct device *parent)
{
	struct platform_device *pdev;
	int ret;

	pdev = platform_device_alloc(name, PLATFORM_DEVID_NONE);
	if (IS_ERR_OR_NULL(pdev))
		return ERR_PTR(-ENOMEM);

	pdev->dev.parent = parent;
	pdev->driver_override = kstrndup(pdev->name, INT3472_PDEV_MAX_NAME_LEN,
					 GFP_KERNEL);

	ret = platform_device_add(pdev);
	if (ret) {
		platform_device_put(pdev);
		return ERR_PTR(ret);
	}

	return pdev;
}

int skl_int3472_tps68470_probe(struct i2c_client *client)
{
	struct acpi_device *adev = ACPI_COMPANION(&client->dev);
	struct platform_device *regulator_dev;
	struct platform_device *opregion_dev;
	struct platform_device *gpio_dev;
	struct int3472_cldb cldb = { 0 };
	struct platform_device *clk_dev;
	bool cldb_present = true;
	struct regmap *regmap;
	int ret = 0;

	regmap = devm_regmap_init_i2c(client, &tps68470_regmap_config);
	if (IS_ERR(regmap)) {
		dev_err(&client->dev, "devm_regmap_init_i2c Error %ld\n",
			PTR_ERR(regmap));
		return PTR_ERR(regmap);
	}

	i2c_set_clientdata(client, regmap);

	ret = tps68470_chip_init(&client->dev, regmap);
	if (ret < 0) {
		dev_err(&client->dev, "TPS68470 Init Error %d\n", ret);
		return ret;
	}

	/*
	 * Check CLDB buffer against the PMIC's adev. If present, then we check
	 * the value of control_logic_type field and follow one of the
	 * following scenarios:
	 *
	 *	1. No CLDB - likely ACPI tables designed for ChromeOS. We
	 *	create platform devices for the GPIOs and OpRegion drivers.
	 *
	 *	2. CLDB, with control_logic_type = 2 - probably ACPI tables
	 *	made for Windows 2-in-1 platforms. Register pdevs for GPIO,
	 *	Clock and Regulator drivers to bind to.
	 *
	 *	3. Any other value in control_logic_type, we should never have
	 *	gotten to this point; crash and burn.
	 */
	ret = skl_int3472_fill_cldb(adev, &cldb);
	if (!ret && cldb.control_logic_type != 2)
		return -EINVAL;

	if (ret)
		cldb_present = false;

	gpio_dev = skl_int3472_register_pdev("tps68470-gpio", &client->dev);
	if (IS_ERR(gpio_dev))
		return PTR_ERR(gpio_dev);

	if (cldb_present) {
		clk_dev = skl_int3472_register_pdev("tps68470-clk",
						    &client->dev);
		if (IS_ERR(clk_dev)) {
			ret = PTR_ERR(clk_dev);
			goto err_free_gpio;
		}

		regulator_dev = skl_int3472_register_pdev("tps68470-regulator",
							  &client->dev);
		if (IS_ERR(regulator_dev)) {
			ret = PTR_ERR(regulator_dev);
			goto err_free_clk;
		}
	} else {
		opregion_dev = skl_int3472_register_pdev("tps68470_pmic_opregion",
							 &client->dev);
		if (IS_ERR(opregion_dev)) {
			ret = PTR_ERR(opregion_dev);
			goto err_free_gpio;
		}
	}

	return 0;

err_free_clk:
	platform_device_put(clk_dev);
err_free_gpio:
	platform_device_put(gpio_dev);

	return ret;
}
