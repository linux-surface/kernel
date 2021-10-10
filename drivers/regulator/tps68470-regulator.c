// SPDX-License-Identifier: GPL-2.0
/*
 * Regulator driver for TPS68470 PMIC
 *
 * Copyright (C) 2018 Intel Corporation
 *
 * Authors:
 *	Zaikuo Wang <zaikuo.wang@intel.com>
 *	Tianshu Qiu <tian.shu.qiu@intel.com>
 *	Jian Xu Zheng <jian.xu.zheng@intel.com>
 *	Yuning Pu <yuning.pu@intel.com>
 *	Rajmohan Mani <rajmohan.mani@intel.com>
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mfd/tps68470.h>
#include <linux/module.h>
#include <linux/platform_data/tps68470.h>
#include <linux/platform_device.h>
#include <linux/regulator/driver.h>
#include <linux/regulator/machine.h>

#define TPS68470_REGULATOR(_name, _id, _ops, _n, _vr,			\
			   _vm, _er, _em, _t, _lr, _nlr)		\
	[TPS68470_ ## _name] = {					\
		.name			= # _name,			\
		.id			= _id,				\
		.ops			= &_ops,			\
		.n_voltages		= _n,				\
		.type			= REGULATOR_VOLTAGE,		\
		.owner			= THIS_MODULE,			\
		.vsel_reg		= _vr,				\
		.vsel_mask		= _vm,				\
		.enable_reg		= _er,				\
		.enable_mask		= _em,				\
		.volt_table		= _t,				\
		.linear_ranges		= _lr,				\
		.n_linear_ranges	= _nlr,				\
	}

static const struct linear_range tps68470_ldo_ranges[] = {
	REGULATOR_LINEAR_RANGE(875000, 0, 125, 17800),
};

static const struct linear_range tps68470_core_ranges[] = {
	REGULATOR_LINEAR_RANGE(900000, 0, 42, 25000),
};

/* Operations permitted on DCDCx, LDO2, LDO3 and LDO4 */
static const struct regulator_ops tps68470_regulator_ops = {
	.is_enabled		= regulator_is_enabled_regmap,
	.enable			= regulator_enable_regmap,
	.disable		= regulator_disable_regmap,
	.get_voltage_sel	= regulator_get_voltage_sel_regmap,
	.set_voltage_sel	= regulator_set_voltage_sel_regmap,
	.list_voltage		= regulator_list_voltage_linear_range,
	.map_voltage		= regulator_map_voltage_linear_range,
};

static const struct regulator_desc regulators[] = {
	TPS68470_REGULATOR(CORE, TPS68470_CORE,
			   tps68470_regulator_ops, 43, TPS68470_REG_VDVAL,
			   TPS68470_VDVAL_DVOLT_MASK, TPS68470_REG_VDCTL,
			   TPS68470_VDCTL_EN_MASK,
			   NULL, tps68470_core_ranges,
			   ARRAY_SIZE(tps68470_core_ranges)),
	TPS68470_REGULATOR(ANA, TPS68470_ANA,
			   tps68470_regulator_ops, 126, TPS68470_REG_VAVAL,
			   TPS68470_VAVAL_AVOLT_MASK, TPS68470_REG_VACTL,
			   TPS68470_VACTL_EN_MASK,
			   NULL, tps68470_ldo_ranges,
			   ARRAY_SIZE(tps68470_ldo_ranges)),
	TPS68470_REGULATOR(VCM, TPS68470_VCM,
			   tps68470_regulator_ops, 126, TPS68470_REG_VCMVAL,
			   TPS68470_VCMVAL_VCVOLT_MASK, TPS68470_REG_VCMCTL,
			   TPS68470_VCMCTL_EN_MASK,
			   NULL, tps68470_ldo_ranges,
			   ARRAY_SIZE(tps68470_ldo_ranges)),
	TPS68470_REGULATOR(VIO, TPS68470_VIO,
			   tps68470_regulator_ops, 126, TPS68470_REG_VIOVAL,
			   TPS68470_VIOVAL_IOVOLT_MASK, TPS68470_REG_S_I2C_CTL,
			   TPS68470_S_I2C_CTL_EN_MASK,
			   NULL, tps68470_ldo_ranges,
			   ARRAY_SIZE(tps68470_ldo_ranges)),

/*
 * (1) This register must have same setting as VIOVAL if S_IO LDO is used to
 *     power daisy chained IOs in the receive side.
 * (2) If there is no I2C daisy chain it can be set freely.
 *
 */
	TPS68470_REGULATOR(VSIO, TPS68470_VSIO,
			   tps68470_regulator_ops, 126, TPS68470_REG_VSIOVAL,
			   TPS68470_VSIOVAL_IOVOLT_MASK, TPS68470_REG_S_I2C_CTL,
			   TPS68470_S_I2C_CTL_EN_MASK,
			   NULL, tps68470_ldo_ranges,
			   ARRAY_SIZE(tps68470_ldo_ranges)),
	TPS68470_REGULATOR(AUX1, TPS68470_AUX1,
			   tps68470_regulator_ops, 126, TPS68470_REG_VAUX1VAL,
			   TPS68470_VAUX1VAL_AUX1VOLT_MASK,
			   TPS68470_REG_VAUX1CTL,
			   TPS68470_VAUX1CTL_EN_MASK,
			   NULL, tps68470_ldo_ranges,
			   ARRAY_SIZE(tps68470_ldo_ranges)),
	TPS68470_REGULATOR(AUX2, TPS68470_AUX2,
			   tps68470_regulator_ops, 126, TPS68470_REG_VAUX2VAL,
			   TPS68470_VAUX2VAL_AUX2VOLT_MASK,
			   TPS68470_REG_VAUX2CTL,
			   TPS68470_VAUX2CTL_EN_MASK,
			   NULL, tps68470_ldo_ranges,
			   ARRAY_SIZE(tps68470_ldo_ranges)),
};

#define TPS68470_REG_INIT_DATA(_name, _min_uV, _max_uV)			\
	[TPS68470_ ## _name] = {					\
		.constraints = {					\
			.name = # _name,				\
			.valid_ops_mask = REGULATOR_CHANGE_VOLTAGE |	\
					  REGULATOR_CHANGE_STATUS,	\
			.min_uV = _min_uV,				\
			.max_uV = _max_uV,				\
		},							\
	}

struct regulator_init_data tps68470_init[] = {
	TPS68470_REG_INIT_DATA(CORE, 900000, 1950000),
	TPS68470_REG_INIT_DATA(ANA, 875000, 3100000),
	TPS68470_REG_INIT_DATA(VCM, 875000, 3100000),
	TPS68470_REG_INIT_DATA(VIO, 875000, 3100000),
	TPS68470_REG_INIT_DATA(VSIO, 875000, 3100000),
	TPS68470_REG_INIT_DATA(AUX1, 875000, 3100000),
	TPS68470_REG_INIT_DATA(AUX2, 875000, 3100000),
};

static int tps68470_regulator_probe(struct platform_device *pdev)
{
	struct tps68470_regulator_platform_data *pdata = pdev->dev.platform_data;
	struct regulator_config config = { };
	struct regmap *tps68470_regmap;
	struct regulator_dev *rdev;
	int i;

	tps68470_regmap = dev_get_drvdata(pdev->dev.parent);

	for (i = 0; i < TPS68470_NUM_REGULATORS; i++) {
		config.dev = pdev->dev.parent;
		config.regmap = tps68470_regmap;
		if (pdata && pdata->reg_init_data[i])
			config.init_data = pdata->reg_init_data[i];
		else
			config.init_data = &tps68470_init[i];

		rdev = devm_regulator_register(&pdev->dev, &regulators[i], &config);
		if (IS_ERR(rdev)) {
			dev_err(&pdev->dev, "failed to register %s regulator\n",
				regulators[i].name);
			return PTR_ERR(rdev);
		}
	}

	return 0;
}

static struct platform_driver tps68470_regulator_driver = {
	.driver = {
		.name = "tps68470-regulator",
	},
	.probe = tps68470_regulator_probe,
};

/*
 * The ACPI tps68470 probe-ordering depends on the clk/gpio/regulator drivers
 * registering before the drivers for the camera-sensors which use them bind.
 * subsys_initcall() ensures this when the drivers are builtin.
 */
static int __init tps68470_regulator_init(void)
{
	return platform_driver_register(&tps68470_regulator_driver);
}
subsys_initcall(tps68470_regulator_init);

static void __exit tps68470_regulator_exit(void)
{
	platform_driver_unregister(&tps68470_regulator_driver);
}
module_exit(tps68470_regulator_exit);

MODULE_ALIAS("platform:tps68470-regulator");
MODULE_DESCRIPTION("TPS68470 voltage regulator driver");
MODULE_LICENSE("GPL v2");
