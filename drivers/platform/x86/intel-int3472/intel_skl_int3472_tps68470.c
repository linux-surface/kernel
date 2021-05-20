// SPDX-License-Identifier: GPL-2.0
/* Author: Dan Scally <djrscally@gmail.com> */

#include <linux/i2c.h>
#include <linux/mfd/core.h>
#include <linux/mfd/tps68470.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>

#include "intel_skl_int3472_common.h"

static const struct mfd_cell tps68470_cros[] = {
	{ .name = "tps68470-gpio" },
	{ .name = "tps68470_pmic_opregion" },
};

static const struct mfd_cell tps68470_win[] = {
	{ .name = "tps68470-gpio" },
	{ .name = "tps68470-clk" },
	{ .name = "tps68470-regulator" },
};

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

	dev_info(dev, "TPS68470 REVID: 0x%02x\n", version);

	return 0;
}

int skl_int3472_tps68470_probe(struct i2c_client *client)
{
	struct acpi_device *adev = ACPI_COMPANION(&client->dev);
	struct int3472_cldb cldb = { 0 };
	struct regmap *regmap;
	int ret;

	regmap = devm_regmap_init_i2c(client, &tps68470_regmap_config);
	if (IS_ERR(regmap)) {
		dev_err(&client->dev, "Failed to create regmap: %ld\n",
			PTR_ERR(regmap));
		return PTR_ERR(regmap);
	}

	i2c_set_clientdata(client, regmap);

	ret = tps68470_chip_init(&client->dev, regmap);
	if (ret < 0) {
		dev_err(&client->dev, "TPS68470 init error %d\n", ret);
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
	 *	gotten to this point; fail probe and return.
	 */
	ret = skl_int3472_fill_cldb(adev, &cldb);
	if (!ret && cldb.control_logic_type != 2) {
		dev_err(&client->dev, "Unsupported control logic type %u\n",
			cldb.control_logic_type);
		return -EINVAL;
	}

	if (ret)
		ret = devm_mfd_add_devices(&client->dev, PLATFORM_DEVID_NONE,
					   tps68470_cros, ARRAY_SIZE(tps68470_cros),
					   NULL, 0, NULL);
	else
		ret = devm_mfd_add_devices(&client->dev, PLATFORM_DEVID_NONE,
					   tps68470_win, ARRAY_SIZE(tps68470_win),
					   NULL, 0, NULL);

	if (ret) {
		dev_err(&client->dev, "Failed to add MFD devices\n");
		return ret;
	}

	return 0;
}
