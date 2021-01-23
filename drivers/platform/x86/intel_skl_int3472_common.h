/* SPDX-License-Identifier: GPL-2.0 */
/* Author: Dan Scally <djrscally@gmail.com> */
#include <linux/regulator/machine.h>
#include <linux/clk-provider.h>
#include <linux/gpio/machine.h>
#include <linux/regulator/driver.h>
#include <linux/types.h>

/* PMIC GPIO Types */
#define INT3472_GPIO_TYPE_RESET					0x00
#define INT3472_GPIO_TYPE_POWERDOWN				0x01
#define INT3472_GPIO_TYPE_CLK_ENABLE				0x0c
#define INT3472_GPIO_TYPE_POWER_ENABLE				0x0b
#define INT3472_GPIO_TYPE_PRIVACY_LED				0x0d
#define INT3472_PDEV_MAX_NAME_LEN				23
#define INT3472_MAX_SENSOR_GPIOS				3
#define GPIO_REGULATOR_NAME_LENGTH				27
#define GPIO_REGULATOR_SUPPLY_NAME_LENGTH			9

#define INT3472_REGULATOR(_NAME, _SUPPLY, _OPS)			\
	(const struct regulator_desc) {				\
		.name = _NAME,					\
		.supply_name = _SUPPLY,				\
		.id = 0,					\
		.type = REGULATOR_VOLTAGE,			\
		.ops = _OPS,					\
		.owner = THIS_MODULE,				\
	}

#define INT3472_GPIO_FUNCTION_REMAP(_PIN, _FUNCTION)		\
	(const struct int3472_gpio_function_remap) {		\
		.documented = _PIN,				\
		.actual = _FUNCTION				\
	}

#define to_int3472_clk(hw)					\
	container_of(hw, struct int3472_gpio_clock, clk_hw)

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

struct int3472_gpio_regulator {
	char regulator_name[GPIO_REGULATOR_NAME_LENGTH];
	char supply_name[GPIO_REGULATOR_SUPPLY_NAME_LENGTH];
	struct gpio_desc *gpio;
	struct regulator_dev *rdev;
	struct regulator_desc rdesc;
};

struct int3472_gpio_clock {
	struct clk *clk;
	struct clk_hw clk_hw;
	struct gpio_desc *gpio;
};

struct int3472_device {
	struct acpi_device *adev;
	struct platform_device *pdev;
	struct acpi_device *sensor;
	char *sensor_name;

	unsigned int n_gpios; /* how many GPIOs have we seen */

	struct int3472_gpio_regulator regulator;
	struct int3472_gpio_clock clock;

	unsigned int n_sensor_gpios; /* how many have we mapped to sensor */
	bool gpios_mapped;
	struct gpiod_lookup_table gpios;
};

struct int3472_gpio_function_remap {
	char *documented;
	char *actual;
};

struct int3472_sensor_config {
	char *sensor_module_name;
	struct regulator_consumer_supply supply_map;
	const struct int3472_gpio_function_remap *function_maps;
};

int skl_int3472_discrete_probe(struct platform_device *pdev);
int skl_int3472_discrete_remove(struct platform_device *pdev);
int skl_int3472_tps68470_probe(struct i2c_client *client);
union acpi_object *skl_int3472_get_acpi_buffer(struct acpi_device *adev,
					       char *id);
int skl_int3472_fill_cldb(struct acpi_device *adev, struct int3472_cldb *cldb);
