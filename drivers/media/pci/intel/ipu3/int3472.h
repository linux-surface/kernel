/* SPDX-License-Identifier: GPL-2.0 */
/* Author: Dan Scally <djrscally@gmail.com> */
#include <linux/regulator/machine.h>

#define INT3472_MAX_SENSOR_GPIOS			3
#define GPIO_REGULATOR_NAME_LENGTH			17
#define GPIO_REGULATOR_SUPPLY_NAME_LENGTH		9

#define INT3472_REGULATOR(_NAME, _SUPPLY, _ID, _OPS)	\
	((const struct regulator_desc) {		\
		.name = _NAME,				\
		.supply_name = _SUPPLY,			\
		.id = _ID,				\
		.type = REGULATOR_VOLTAGE,		\
		.ops = _OPS,				\
		.owner = THIS_MODULE,			\
	})

const guid_t int3472_gpio_guid = GUID_INIT(0x79234640, 0x9e10, 0x4fea,
					     0xa5, 0xc1, 0xb5, 0xaa, 0x8b,
					     0x19, 0x75, 0x6f);

const guid_t cio2_sensor_module_guid = GUID_INIT(0x822ace8f, 0x2814, 0x4174,
						 0xa5, 0x6b, 0x5f, 0x02, 0x9f,
						 0xe0, 0x79, 0xee);

struct int3472_cldb {
	u8 version;
	/*
	 * control logic type
	 * 0: UNKNOWN
	 * 1: DISCRETE(CRD-D)
	 * 2: PMIC TPS68470
	 * 3: PMIC uP6641
	 */
	u8 control_logic_type;
	u8 control_logic_id;
	u8 sensor_card_sku;
	u8 reserved[28];
};

struct int3472_device {
	struct acpi_device *adev;
	struct acpi_device *sensor;

	unsigned int n_gpios; /* how many GPIOs have we seen */

	unsigned int n_regulators;
	struct list_head regulators;

	unsigned int n_sensor_gpios; /* how many have we mapped to sensor */
	struct gpiod_lookup_table gpios;
};

struct int3472_gpio_regulator {
	char regulator_name[GPIO_REGULATOR_NAME_LENGTH];
	char supply_name[GPIO_REGULATOR_SUPPLY_NAME_LENGTH];
	struct gpio_desc *gpio;
	struct regulator_dev *rdev;
	struct regulator_desc rdesc;
	struct list_head list;
};

struct int3472_sensor_regulator_map {
	char *sensor_module_name;
	unsigned int n_supplies;
	struct regulator_consumer_supply *supplies;
};

/*
 * Here follows platform specific mapping information that we can pass to
 * regulator_init_data when we register our regulators. They're just mapped
 * via index, I.E. the first regulator pin that the code finds for the
 * i2c-OVTI2680:00 device is avdd, the second is dovdd and so on.
 */

static struct regulator_consumer_supply miix_510_ov2680[] = {
	{ "i2c-OVTI2680:00", "avdd" },
	{ "i2c-OVTI2680:00", "dovdd" },
};

static struct regulator_consumer_supply surface_go2_ov5693[] = {
	{ "i2c-INT33BE:00", "avdd" },
	{ "i2c-INT33BE:00", "dovdd" },
};

static struct regulator_consumer_supply surface_book_ov5693[] = {
	{ "i2c-INT33BE:00", "avdd" },
	{ "i2c-INT33BE:00", "dovdd" },
};

static struct int3472_sensor_regulator_map int3472_sensor_regulator_maps[] = {
	{ "GNDF140809R", 2, miix_510_ov2680 },
	{ "YHCU", 2, surface_go2_ov5693 },
	{ "MSHW0070", 2, surface_book_ov5693 },
};
