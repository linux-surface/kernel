/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TI TPS68470 PMIC platform data definition.
 *
 * Copyright (c) 2021 Red Hat Inc.
 *
 * Red Hat authors:
 * Hans de Goede <hdegoede@redhat.com>
 */

#ifndef _INTEL_SKL_INT3472_TPS68470_H
#define _INTEL_SKL_INT3472_TPS68470_H

#include <linux/leds.h>

struct gpiod_lookup_table;
struct tps68470_regulator_platform_data;
struct tps68470_led_platform_data;

struct tps68470_led_lookups {
	unsigned int n_lookups;
	struct led_lookup_data lookup_table[];
};

struct int3472_tps68470_board_data {
	const char *dev_name;
	const struct tps68470_regulator_platform_data *tps68470_regulator_pdata;
	const struct tps68470_led_platform_data *tps68470_led_pdata;
	struct tps68470_led_lookups *led_lookups;
	unsigned int n_gpiod_lookups;
	struct gpiod_lookup_table *tps68470_gpio_lookup_tables[];
};

const struct int3472_tps68470_board_data *int3472_tps68470_get_board_data(const char *dev_name);

#endif
