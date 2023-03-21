// SPDX-License-Identifier: GPL-2.0
/*
 * LED driver for TPS68470 PMIC
 *
 * Copyright (C) 2023 Red Hat
 *
 * Authors:
 *	Kate Hsuan <hpa@redhat.com>
 */

#include <linux/leds.h>
#include <linux/mfd/tps68470.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/regmap.h>


#define lcdev_to_led(led_cdev) \
	container_of(led_cdev, struct tps68470_led, lcdev)

#define led_to_tps68470(led, index) \
	container_of(led, struct tps68470_device, leds[index])

enum tps68470_led_ids {
	TPS68470_ILED_A,
	TPS68470_ILED_B,
	TPS68470_NUM_LEDS
};

static const char *tps68470_led_names[] = {
	[TPS68470_ILED_A] = "tps68470-iled_a",
	[TPS68470_ILED_B] = "tps68470-iled_b",
};

struct tps68470_led {
	unsigned int led_id;
	struct led_classdev lcdev;
};

struct tps68470_device {
	struct device *dev;
	struct regmap *regmap;
	struct tps68470_led leds[TPS68470_NUM_LEDS];
};

enum ctrlb_current {
	CTRLB_2MA	= 0,
	CTRLB_4MA	= 1,
	CTRLB_8MA	= 2,
	CTRLB_16MA	= 3,
};

static int tps68470_brightness_set(struct led_classdev *led_cdev, enum led_brightness brightness)
{
	struct tps68470_led *led = lcdev_to_led(led_cdev);
	struct tps68470_device *tps68470 = led_to_tps68470(led, led->led_id);
	struct regmap *regmap = tps68470->regmap;

	switch (led->led_id) {
	case TPS68470_ILED_A:
		return regmap_update_bits(regmap, TPS68470_REG_ILEDCTL, TPS68470_ILEDCTL_ENA,
					  brightness ? TPS68470_ILEDCTL_ENA : 0);
	case TPS68470_ILED_B:
		return regmap_update_bits(regmap, TPS68470_REG_ILEDCTL, TPS68470_ILEDCTL_ENB,
					  brightness ? TPS68470_ILEDCTL_ENB : 0);
	}
	return -EINVAL;
}

static enum led_brightness tps68470_brightness_get(struct led_classdev *led_cdev)
{
	struct tps68470_led *led = lcdev_to_led(led_cdev);
	struct tps68470_device *tps68470 = led_to_tps68470(led, led->led_id);
	struct regmap *regmap = tps68470->regmap;
	int ret = 0;
	int value = 0;

	ret =  regmap_read(regmap, TPS68470_REG_ILEDCTL, &value);
	if (ret)
		return dev_err_probe(led_cdev->dev, -EINVAL, "failed on reading register\n");

	switch (led->led_id) {
	case TPS68470_ILED_A:
		value = value & TPS68470_ILEDCTL_ENA;
		break;
	case TPS68470_ILED_B:
		value = value & TPS68470_ILEDCTL_ENB;
		break;
	}

	return value ? LED_ON : LED_OFF;
}


static int tps68470_ledb_current_init(struct platform_device *pdev,
				      struct tps68470_device *tps68470)
{
	int ret = 0;
	unsigned int curr;

	/* configure LEDB current if the properties can be got */
	if (!device_property_read_u32(&pdev->dev, "ti,ledb-current", &curr)) {
		if (curr > CTRLB_16MA) {
			dev_err(&pdev->dev,
				"Invalid LEDB current value: %d\n",
				curr);
			return -EINVAL;
		}
		ret = regmap_update_bits(tps68470->regmap, TPS68470_REG_ILEDCTL,
					 TPS68470_ILEDCTL_CTRLB, curr);
	}
	return ret;
}

static int tps68470_leds_probe(struct platform_device *pdev)
{
	int i = 0;
	int ret = 0;
	struct tps68470_device *tps68470;
	struct tps68470_led *led;
	struct led_classdev *lcdev;

	tps68470 = devm_kzalloc(&pdev->dev, sizeof(struct tps68470_device),
				GFP_KERNEL);
	if (!tps68470)
		return -ENOMEM;

	tps68470->dev = &pdev->dev;
	tps68470->regmap = dev_get_drvdata(pdev->dev.parent);

	for (i = 0; i < TPS68470_NUM_LEDS; i++) {
		led = &tps68470->leds[i];
		lcdev = &led->lcdev;

		led->led_id = i;

		lcdev->name = devm_kasprintf(tps68470->dev, GFP_KERNEL, "%s::%s",
					     tps68470_led_names[i], LED_FUNCTION_INDICATOR);
		if (!lcdev->name)
			return -ENOMEM;

		lcdev->max_brightness = 1;
		lcdev->brightness = 0;
		lcdev->brightness_set_blocking = tps68470_brightness_set;
		lcdev->brightness_get = tps68470_brightness_get;
		lcdev->dev = &pdev->dev;

		ret = devm_led_classdev_register(tps68470->dev, lcdev);
		if (ret) {
			dev_err_probe(tps68470->dev, ret,
				      "error registering led\n");
			goto err_exit;
		}

		if (i == TPS68470_ILED_B) {
			ret = tps68470_ledb_current_init(pdev, tps68470);
			if (ret)
				goto err_exit;
		}
	}

err_exit:
	if (ret) {
		for (i = 0; i < TPS68470_NUM_LEDS; i++) {
			if (tps68470->leds[i].lcdev.name)
				devm_led_classdev_unregister(&pdev->dev,
							     &tps68470->leds[i].lcdev);
		}
	}

	return ret;
}
static struct platform_driver tps68470_led_driver = {
	.driver = {
		   .name = "tps68470-led",
	},
	.probe = tps68470_leds_probe,
};

module_platform_driver(tps68470_led_driver);

MODULE_ALIAS("platform:tps68470-led");
MODULE_DESCRIPTION("LED driver for TPS68470 PMIC");
MODULE_LICENSE("GPL v2");
