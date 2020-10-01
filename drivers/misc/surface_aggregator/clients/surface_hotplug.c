// SPDX-License-Identifier: GPL-2.0+
/*
 * Surface Book (gen. 2 and later) discrete GPU (dGPU) hot-plug system driver.
 *
 * Supports explicit setting of the dGPU power-state on the Surface Books via
 * a user-space interface. Properly handles dGPU hot-plugging by detaching the
 * base of the device.
 *
 * Copyright (C) 2019-2020 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/sysfs.h>

#include <linux/surface_aggregator/controller.h>
#include <linux/surface_acpi_notify.h>


// TODO: vgaswitcheroo integration


static void dbg_dump_drvsta(struct platform_device *pdev, const char *prefix);


#define SHPS_DSM_REVISION	1
#define SHPS_DSM_GPU_ADDRS	0x02
#define SHPS_DSM_GPU_POWER	0x05
static const guid_t SHPS_DSM_UUID =
	GUID_INIT(0x5515a847, 0xed55, 0x4b27, 0x83, 0x52, 0xcd,
		  0x32, 0x0e, 0x10, 0x36, 0x0a);


#define SAM_DGPU_TC			0x13
#define SAM_DGPU_CID_POWERON		0x02
#define ACPI_SGCP_NOTIFY_POWER_ON	0x81

#define SHPS_DSM_GPU_ADDRS_RP		"RP5_PCIE"
#define SHPS_DSM_GPU_ADDRS_DGPU		"DGPU_PCIE"
#define SHPS_PCI_GPU_ADDR_RP			"\\_SB.PCI0.RP13._ADR"

static const struct acpi_gpio_params gpio_base_presence_int = { 0, 0, false };
static const struct acpi_gpio_params gpio_base_presence     = { 1, 0, false };
static const struct acpi_gpio_params gpio_dgpu_power_int    = { 2, 0, false };
static const struct acpi_gpio_params gpio_dgpu_power        = { 3, 0, false };
static const struct acpi_gpio_params gpio_dgpu_presence_int = { 4, 0, false };
static const struct acpi_gpio_params gpio_dgpu_presence     = { 5, 0, false };

static const struct acpi_gpio_mapping shps_acpi_gpios[] = {
	{ "base_presence-int-gpio", &gpio_base_presence_int, 1 },
	{ "base_presence-gpio",     &gpio_base_presence,     1 },
	{ "dgpu_power-int-gpio",    &gpio_dgpu_power_int,    1 },
	{ "dgpu_power-gpio",        &gpio_dgpu_power,        1 },
	{ "dgpu_presence-int-gpio", &gpio_dgpu_presence_int, 1 },
	{ "dgpu_presence-gpio",     &gpio_dgpu_presence,     1 },
	{ },
};


enum shps_dgpu_power {
	SHPS_DGPU_POWER_OFF      = 0,
	SHPS_DGPU_POWER_ON       = 1,
	SHPS_DGPU_POWER_UNKNOWN  = 2,
};

static const char *shps_dgpu_power_str(enum shps_dgpu_power power)
{
	if (power == SHPS_DGPU_POWER_OFF)
		return "off";
	else if (power == SHPS_DGPU_POWER_ON)
		return "on";
	else if (power == SHPS_DGPU_POWER_UNKNOWN)
		return "unknown";
	else
		return "<invalid>";
}

enum shps_notification_method {
	SHPS_NOTIFICATION_METHOD_SAN = 1,
	SHPS_NOTIFICATION_METHOD_SGCP = 2
};

struct shps_hardware_traits {
	enum shps_notification_method notification_method;
	const char *dgpu_rp_pci_address;
};

struct shps_driver_data {
	struct ssam_controller *ctrl;
	struct platform_device *pdev;

	struct mutex lock;
	struct pci_dev *dgpu_root_port;
	struct pci_saved_state *dgpu_root_port_state;
	struct gpio_desc *gpio_dgpu_power;
	struct gpio_desc *gpio_dgpu_presence;
	struct gpio_desc *gpio_base_presence;
	unsigned int irq_dgpu_presence;
	unsigned int irq_base_presence;
	unsigned long state;
	acpi_handle sgpc_handle;
	struct shps_hardware_traits hardware_traits;

	struct notifier_block dgpu_nf;
};

struct shps_hardware_probe {
	const char *hardware_id;
	int generation;
	struct shps_hardware_traits *hardware_traits;
};

static struct shps_hardware_traits shps_gen1_hwtraits = {
	.notification_method = SHPS_NOTIFICATION_METHOD_SAN
};

static struct shps_hardware_traits shps_gen2_hwtraits = {
	.notification_method = SHPS_NOTIFICATION_METHOD_SGCP,
	.dgpu_rp_pci_address = SHPS_PCI_GPU_ADDR_RP
};

static const struct shps_hardware_probe shps_hardware_probe_match[] = {
	/* Surface Book 3 */
	{ "MSHW0117", 2, &shps_gen2_hwtraits },

	/* Surface Book 2 (default, must be last entry) */
	{ NULL, 1, &shps_gen1_hwtraits }
};

#define SHPS_STATE_BIT_PWRTGT		0	/* desired power state: 1 for on, 0 for off */
#define SHPS_STATE_BIT_RPPWRON_SYNC	1	/* synchronous/requested power-up in progress  */
#define SHPS_STATE_BIT_WAKE_ENABLED	2	/* wakeup via base-presence GPIO enabled */


#define SHPS_DGPU_PARAM_PERM		0644

enum shps_dgpu_power_mp {
	SHPS_DGPU_MP_POWER_OFF  = SHPS_DGPU_POWER_OFF,
	SHPS_DGPU_MP_POWER_ON   = SHPS_DGPU_POWER_ON,
	SHPS_DGPU_MP_POWER_ASIS = -1,

	__SHPS_DGPU_MP_POWER_START = -1,
	__SHPS_DGPU_MP_POWER_END   = 1,
};

static int param_dgpu_power_set(const char *val, const struct kernel_param *kp)
{
	int power = SHPS_DGPU_MP_POWER_OFF;
	int status;

	status = kstrtoint(val, 0, &power);
	if (status)
		return status;

	if (power < __SHPS_DGPU_MP_POWER_START || power > __SHPS_DGPU_MP_POWER_END)
		return -EINVAL;

	return param_set_int(val, kp);
}

static const struct kernel_param_ops param_dgpu_power_ops = {
	.set = param_dgpu_power_set,
	.get = param_get_int,
};

static int param_dgpu_power_init = SHPS_DGPU_MP_POWER_OFF;
static int param_dgpu_power_exit = SHPS_DGPU_MP_POWER_ON;
static int param_dgpu_power_susp = SHPS_DGPU_MP_POWER_ASIS;
static bool param_dtx_latch = true;

module_param_cb(dgpu_power_init, &param_dgpu_power_ops, &param_dgpu_power_init, SHPS_DGPU_PARAM_PERM);
module_param_cb(dgpu_power_exit, &param_dgpu_power_ops, &param_dgpu_power_exit, SHPS_DGPU_PARAM_PERM);
module_param_cb(dgpu_power_susp, &param_dgpu_power_ops, &param_dgpu_power_susp, SHPS_DGPU_PARAM_PERM);
module_param_named(dtx_latch, param_dtx_latch, bool, SHPS_DGPU_PARAM_PERM);

MODULE_PARM_DESC(dgpu_power_init, "dGPU power state to be set on init (0: off / 1: on / 2: as-is, default: off)");
MODULE_PARM_DESC(dgpu_power_exit, "dGPU power state to be set on exit (0: off / 1: on / 2: as-is, default: on)");
MODULE_PARM_DESC(dgpu_power_susp, "dGPU power state to be set on exit (0: off / 1: on / 2: as-is, default: as-is)");
MODULE_PARM_DESC(dtx_latch, "lock/unlock DTX base latch in accordance to power-state (Y/n)");

static SSAM_DEFINE_SYNC_REQUEST_N(ssam_bas_latch_lock, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x06,
	.instance_id     = 0x00,
});

static SSAM_DEFINE_SYNC_REQUEST_N(ssam_bas_latch_unlock, {
	.target_category = SSAM_SSH_TC_BAS,
	.target_id       = 0x01,
	.command_id      = 0x07,
	.instance_id     = 0x00,
});

static int shps_dgpu_dsm_get_pci_addr_from_adr(struct platform_device *pdev, const char *entry) {
	acpi_handle handle = ACPI_HANDLE(&pdev->dev);
	acpi_status status;
	struct acpi_object_list input;
	union acpi_object input_args[0];
	u64 device_addr;
	u8 bus, dev, fun;

	input.count = 0;
	input.pointer = input_args;


	status = acpi_evaluate_integer(handle, (acpi_string)entry, &input, &device_addr);
	if (ACPI_FAILURE(status))
		return -ENODEV;

	bus = 0;
	dev = (device_addr & 0xFF0000) >> 16;
	fun = device_addr & 0xFF;

	dev_info(&pdev->dev, "found pci device at bus = %d, dev = %x, fun = %x\n",
		 (u32)bus, (u32)dev, (u32)fun);

	return bus << 8 | PCI_DEVFN(dev, fun);
}

static int shps_dgpu_dsm_get_pci_addr_from_dsm(struct platform_device *pdev, const char *entry)
{
	acpi_handle handle = ACPI_HANDLE(&pdev->dev);
	union acpi_object *result;
	union acpi_object *e0;
	union acpi_object *e1;
	union acpi_object *e2;
	u64 device_addr = 0;
	u8 bus, dev, fun;
	int i;


	result = acpi_evaluate_dsm_typed(handle, &SHPS_DSM_UUID, SHPS_DSM_REVISION,
					 SHPS_DSM_GPU_ADDRS, NULL, ACPI_TYPE_PACKAGE);
	if (!result)
		return -EFAULT;

	// three entries per device: name, address, <integer>
	for (i = 0; i + 2 < result->package.count; i += 3) {
		e0 = &result->package.elements[i];
		e1 = &result->package.elements[i + 1];
		e2 = &result->package.elements[i + 2];

		if (e0->type != ACPI_TYPE_STRING) {
			ACPI_FREE(result);
			return -EIO;
		}

		if (e1->type != ACPI_TYPE_INTEGER) {
			ACPI_FREE(result);
			return -EIO;
		}

		if (e2->type != ACPI_TYPE_INTEGER) {
			ACPI_FREE(result);
			return -EIO;
		}

		if (strncmp(e0->string.pointer, entry, 64) == 0)
			device_addr = e1->integer.value;
	}

	ACPI_FREE(result);
	if (device_addr == 0)
		return -ENODEV;


	// convert address
	bus = (device_addr & 0x0FF00000) >> 20;
	dev = (device_addr & 0x000F8000) >> 15;
	fun = (device_addr & 0x00007000) >> 12;

	return bus << 8 | PCI_DEVFN(dev, fun);
}

static struct pci_dev *shps_dgpu_dsm_get_pci_dev(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	struct pci_dev *dev;
	int addr;


	if (drvdata->hardware_traits.dgpu_rp_pci_address) {
		addr = shps_dgpu_dsm_get_pci_addr_from_adr(pdev, drvdata->hardware_traits.dgpu_rp_pci_address);
	} else {
		addr = shps_dgpu_dsm_get_pci_addr_from_dsm(pdev, SHPS_DSM_GPU_ADDRS_RP);
	}

	if (addr < 0)
		return ERR_PTR(addr);

	dev = pci_get_domain_bus_and_slot(0, (addr & 0xFF00) >> 8, addr & 0xFF);
	return dev ? dev : ERR_PTR(-ENODEV);
}


static int shps_dgpu_dsm_get_power_unlocked(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	struct gpio_desc *gpio = drvdata->gpio_dgpu_power;
	int status;

	status = gpiod_get_value_cansleep(gpio);
	if (status < 0)
		return status;

	return status == 0 ? SHPS_DGPU_POWER_OFF : SHPS_DGPU_POWER_ON;
}

static int shps_dgpu_dsm_get_power(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	int status;

	mutex_lock(&drvdata->lock);
	status = shps_dgpu_dsm_get_power_unlocked(pdev);
	mutex_unlock(&drvdata->lock);

	return status;
}

static int __shps_dgpu_dsm_set_power_unlocked(struct platform_device *pdev, enum shps_dgpu_power power)
{
	acpi_handle handle = ACPI_HANDLE(&pdev->dev);
	union acpi_object *result;
	union acpi_object param;

	dev_info(&pdev->dev, "setting dGPU direct power to \'%s\'\n", shps_dgpu_power_str(power));

	param.type = ACPI_TYPE_INTEGER;
	param.integer.value = power == SHPS_DGPU_POWER_ON;

	result = acpi_evaluate_dsm_typed(handle, &SHPS_DSM_UUID, SHPS_DSM_REVISION,
					 SHPS_DSM_GPU_POWER, &param, ACPI_TYPE_BUFFER);
	if (!result)
		return -EFAULT;

	// check for the expected result
	if (result->buffer.length != 1 || result->buffer.pointer[0] != 0) {
		ACPI_FREE(result);
		return -EIO;
	}

	ACPI_FREE(result);
	return 0;
}

static int shps_dgpu_dsm_set_power_unlocked(struct platform_device *pdev, enum shps_dgpu_power power)
{
	int status;

	if (power != SHPS_DGPU_POWER_ON && power != SHPS_DGPU_POWER_OFF)
		return -EINVAL;

	status = shps_dgpu_dsm_get_power_unlocked(pdev);
	if (status < 0)
		return status;
	if (status == power)
		return 0;

	return __shps_dgpu_dsm_set_power_unlocked(pdev, power);
}

static int shps_dgpu_dsm_set_power(struct platform_device *pdev, enum shps_dgpu_power power)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	int status;

	mutex_lock(&drvdata->lock);
	status = shps_dgpu_dsm_set_power_unlocked(pdev, power);
	mutex_unlock(&drvdata->lock);

	return status;
}


static bool shps_rp_link_up(struct pci_dev *rp)
{
	u16 lnksta = 0, sltsta = 0;

	pcie_capability_read_word(rp, PCI_EXP_LNKSTA, &lnksta);
	pcie_capability_read_word(rp, PCI_EXP_SLTSTA, &sltsta);

	return (lnksta & PCI_EXP_LNKSTA_DLLLA) || (sltsta & PCI_EXP_SLTSTA_PDS);
}


static int shps_dgpu_rp_get_power_unlocked(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	struct pci_dev *rp = drvdata->dgpu_root_port;

	if (rp->current_state == PCI_D3hot || rp->current_state == PCI_D3cold)
		return SHPS_DGPU_POWER_OFF;
	else if (rp->current_state == PCI_UNKNOWN || rp->current_state == PCI_POWER_ERROR)
		return SHPS_DGPU_POWER_UNKNOWN;
	else
		return SHPS_DGPU_POWER_ON;
}

static int shps_dgpu_rp_get_power(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	int status;

	mutex_lock(&drvdata->lock);
	status = shps_dgpu_rp_get_power_unlocked(pdev);
	mutex_unlock(&drvdata->lock);

	return status;
}

static int __shps_dgpu_rp_set_power_unlocked(struct platform_device *pdev, enum shps_dgpu_power power)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	struct pci_dev *rp = drvdata->dgpu_root_port;
	int status, i;

	dev_info(&pdev->dev, "setting dGPU power state to \'%s\'\n", shps_dgpu_power_str(power));

	dbg_dump_drvsta(pdev, "__shps_dgpu_rp_set_power_unlocked.1");
	if (power == SHPS_DGPU_POWER_ON) {
		set_bit(SHPS_STATE_BIT_RPPWRON_SYNC, &drvdata->state);
		pci_set_power_state(rp, PCI_D0);

		if (drvdata->dgpu_root_port_state)
			pci_load_and_free_saved_state(rp, &drvdata->dgpu_root_port_state);

		pci_restore_state(rp);

		if (!pci_is_enabled(rp))
			pci_enable_device(rp);

		pci_set_master(rp);
		clear_bit(SHPS_STATE_BIT_RPPWRON_SYNC, &drvdata->state);

		set_bit(SHPS_STATE_BIT_PWRTGT, &drvdata->state);
	} else {
		if (!drvdata->dgpu_root_port_state) {
			pci_save_state(rp);
			drvdata->dgpu_root_port_state = pci_store_saved_state(rp);
		}

		/*
		 * To properly update the hot-plug system we need to "remove" the dGPU
		 * before disabling it and sending it to D3cold. Following this, we
		 * need to wait for the link and slot status to actually change.
		 */
		status = shps_dgpu_dsm_set_power_unlocked(pdev, SHPS_DGPU_POWER_OFF);
		if (status)
			return status;

		for (i = 0; i < 20 && shps_rp_link_up(rp); i++)
			msleep(50);

		if (shps_rp_link_up(rp))
			dev_err(&pdev->dev, "dGPU removal via DSM timed out\n");

		pci_clear_master(rp);

		if (pci_is_enabled(rp))
			pci_disable_device(rp);

		pci_set_power_state(rp, PCI_D3cold);

		clear_bit(SHPS_STATE_BIT_PWRTGT, &drvdata->state);
	}
	dbg_dump_drvsta(pdev, "__shps_dgpu_rp_set_power_unlocked.2");

	return 0;
}

static int shps_dgpu_rp_set_power_unlocked(struct platform_device *pdev, enum shps_dgpu_power power)
{
	int status;

	if (power != SHPS_DGPU_POWER_ON && power != SHPS_DGPU_POWER_OFF)
		return -EINVAL;

	status = shps_dgpu_rp_get_power_unlocked(pdev);
	if (status < 0)
		return status;
	if (status == power)
		return 0;

	return __shps_dgpu_rp_set_power_unlocked(pdev, power);
}

static int shps_dgpu_rp_set_power(struct platform_device *pdev, enum shps_dgpu_power power)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	int status;

	mutex_lock(&drvdata->lock);
	status = shps_dgpu_rp_set_power_unlocked(pdev, power);
	mutex_unlock(&drvdata->lock);

	return status;
}


static int shps_dgpu_set_power(struct platform_device *pdev, enum shps_dgpu_power power)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	int status;

	if (!param_dtx_latch)
		return shps_dgpu_rp_set_power(pdev, power);

	if (power == SHPS_DGPU_POWER_ON) {
		status = ssam_bas_latch_lock(drvdata->ctrl);
		if (status)
			return status;

		status = shps_dgpu_rp_set_power(pdev, power);
		if (status)
			ssam_bas_latch_unlock(drvdata->ctrl);

	} else {
		status = shps_dgpu_rp_set_power(pdev, power);
		if (status)
			return status;

		status = ssam_bas_latch_unlock(drvdata->ctrl);
	}

	return status;
}


static int shps_dgpu_is_present(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata;

	drvdata = platform_get_drvdata(pdev);
	return gpiod_get_value_cansleep(drvdata->gpio_dgpu_presence);
}


static ssize_t dgpu_power_show(struct device *dev, struct device_attribute *attr, char *data)
{
	struct platform_device *pdev = to_platform_device(dev);
	int power = shps_dgpu_rp_get_power(pdev);

	if (power < 0)
		return power;

	return sprintf(data, "%s\n", shps_dgpu_power_str(power));
}

static ssize_t dgpu_power_store(struct device *dev, struct device_attribute *attr,
				const char *data, size_t count)
{
	struct platform_device *pdev = to_platform_device(dev);
	enum shps_dgpu_power power;
	bool b = false;
	int status;

	status = kstrtobool(data, &b);
	if (status)
		return status;

	status = shps_dgpu_is_present(pdev);
	if (status <= 0)
		return status < 0 ? status : -EPERM;

	power = b ? SHPS_DGPU_POWER_ON : SHPS_DGPU_POWER_OFF;
	status = shps_dgpu_set_power(pdev, power);

	return status < 0 ? status : count;
}

static ssize_t dgpu_power_dsm_show(struct device *dev, struct device_attribute *attr, char *data)
{
	struct platform_device *pdev = to_platform_device(dev);
	int power = shps_dgpu_dsm_get_power(pdev);

	if (power < 0)
		return power;

	return sprintf(data, "%s\n", shps_dgpu_power_str(power));
}

static ssize_t dgpu_power_dsm_store(struct device *dev, struct device_attribute *attr,
				    const char *data, size_t count)
{
	struct platform_device *pdev = to_platform_device(dev);
	enum shps_dgpu_power power;
	bool b = false;
	int status;

	status = kstrtobool(data, &b);
	if (status)
		return status;

	status = shps_dgpu_is_present(pdev);
	if (status <= 0)
		return status < 0 ? status : -EPERM;

	power = b ? SHPS_DGPU_POWER_ON : SHPS_DGPU_POWER_OFF;
	status = shps_dgpu_dsm_set_power(pdev, power);

	return status < 0 ? status : count;
}

static DEVICE_ATTR_RW(dgpu_power);
static DEVICE_ATTR_RW(dgpu_power_dsm);

static struct attribute *shps_power_attrs[] = {
	&dev_attr_dgpu_power.attr,
	&dev_attr_dgpu_power_dsm.attr,
	NULL,
};
ATTRIBUTE_GROUPS(shps_power);


static void dbg_dump_power_states(struct platform_device *pdev, const char *prefix)
{
	enum shps_dgpu_power power_dsm;
	enum shps_dgpu_power power_rp;
	int status;

	status = shps_dgpu_rp_get_power_unlocked(pdev);
	if (status < 0)
		dev_err(&pdev->dev, "%s: failed to get root-port power state: %d\n", prefix, status);
	power_rp = status;

	status = shps_dgpu_rp_get_power_unlocked(pdev);
	if (status < 0)
		dev_err(&pdev->dev, "%s: failed to get direct power state: %d\n", prefix, status);
	power_dsm = status;

	dev_dbg(&pdev->dev, "%s: root-port power state: %d\n", prefix, power_rp);
	dev_dbg(&pdev->dev, "%s: direct power state:    %d\n", prefix, power_dsm);
}

static void dbg_dump_pciesta(struct platform_device *pdev, const char *prefix)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	struct pci_dev *rp = drvdata->dgpu_root_port;
	u16 lnksta, lnksta2, sltsta, sltsta2;

	pcie_capability_read_word(rp, PCI_EXP_LNKSTA, &lnksta);
	pcie_capability_read_word(rp, PCI_EXP_LNKSTA2, &lnksta2);
	pcie_capability_read_word(rp, PCI_EXP_SLTSTA, &sltsta);
	pcie_capability_read_word(rp, PCI_EXP_SLTSTA2, &sltsta2);

	dev_dbg(&pdev->dev, "%s: LNKSTA: 0x%04x\n", prefix, lnksta);
	dev_dbg(&pdev->dev, "%s: LNKSTA2: 0x%04x\n", prefix, lnksta2);
	dev_dbg(&pdev->dev, "%s: SLTSTA: 0x%04x\n", prefix, sltsta);
	dev_dbg(&pdev->dev, "%s: SLTSTA2: 0x%04x\n", prefix, sltsta2);
}

static void dbg_dump_drvsta(struct platform_device *pdev, const char *prefix)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	struct pci_dev *rp = drvdata->dgpu_root_port;

	dev_dbg(&pdev->dev, "%s: RP power: %d\n", prefix, rp->current_state);
	dev_dbg(&pdev->dev, "%s: RP state saved: %d\n", prefix, rp->state_saved);
	dev_dbg(&pdev->dev, "%s: RP state stored: %d\n", prefix, !!drvdata->dgpu_root_port_state);
	dev_dbg(&pdev->dev, "%s: RP enabled: %d\n", prefix, atomic_read(&rp->enable_cnt));
	dev_dbg(&pdev->dev, "%s: RP mastered: %d\n", prefix, rp->is_busmaster);
}

static int shps_pm_prepare(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	bool pwrtgt;
	int status = 0;

	dbg_dump_power_states(pdev, "shps_pm_prepare");

	if (param_dgpu_power_susp != SHPS_DGPU_MP_POWER_ASIS) {
		pwrtgt = test_bit(SHPS_STATE_BIT_PWRTGT, &drvdata->state);

		status = shps_dgpu_set_power(pdev, param_dgpu_power_susp);
		if (status) {
			dev_err(&pdev->dev, "failed to power %s dGPU: %d\n",
				param_dgpu_power_susp == SHPS_DGPU_MP_POWER_OFF ? "off" : "on",
				status);
			return status;
		}

		if (pwrtgt)
			set_bit(SHPS_STATE_BIT_PWRTGT, &drvdata->state);
		else
			clear_bit(SHPS_STATE_BIT_PWRTGT, &drvdata->state);
	}

	return 0;
}

static void shps_pm_complete(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	int status;

	dbg_dump_power_states(pdev, "shps_pm_complete");
	dbg_dump_pciesta(pdev, "shps_pm_complete");
	dbg_dump_drvsta(pdev, "shps_pm_complete.1");

	// update power target, dGPU may have been detached while suspended
	status = shps_dgpu_is_present(pdev);
	if (status < 0) {
		dev_err(&pdev->dev, "failed to get dGPU presence: %d\n", status);
		return;
	} else if (status == 0) {
		clear_bit(SHPS_STATE_BIT_PWRTGT, &drvdata->state);
	}

	/*
	 * During resume, the PCIe core will power on the root-port, which in turn
	 * will power on the dGPU. Most of the state synchronization is already
	 * handled via the SAN RQSG handler, so it is in a fully consistent
	 * on-state here. If requested, turn it off here.
	 *
	 * As there seem to be some synchronization issues turning off the dGPU
	 * directly after the power-on SAN RQSG notification during the resume
	 * process, let's do this here.
	 *
	 * TODO/FIXME:
	 *   This does not combat unhandled power-ons when the device is not fully
	 *   resumed, i.e. re-suspended before shps_pm_complete is called. Those
	 *   should normally not be an issue, but the dGPU does get hot even though
	 *   it is suspended, so ideally we want to keep it off.
	 */
	if (!test_bit(SHPS_STATE_BIT_PWRTGT, &drvdata->state)) {
		status = shps_dgpu_set_power(pdev, SHPS_DGPU_POWER_OFF);
		if (status)
			dev_err(&pdev->dev, "failed to power-off dGPU: %d\n", status);
	}

	dbg_dump_drvsta(pdev, "shps_pm_complete.2");
}

static int shps_pm_suspend(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	int status;

	if (device_may_wakeup(dev)) {
		status = enable_irq_wake(drvdata->irq_base_presence);
		if (status)
			return status;

		set_bit(SHPS_STATE_BIT_WAKE_ENABLED, &drvdata->state);
	}

	return 0;
}

static int shps_pm_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	int status = 0;

	if (test_and_clear_bit(SHPS_STATE_BIT_WAKE_ENABLED, &drvdata->state))
		status = disable_irq_wake(drvdata->irq_base_presence);

	return status;
}

static void shps_shutdown(struct platform_device *pdev)
{
	int status;

	/*
	 * Turn on dGPU before shutting down. This allows the core drivers to
	 * properly shut down the device. If we don't do this, the pcieport driver
	 * will complain that the device has already been disabled.
	 */
	status = shps_dgpu_set_power(pdev, SHPS_DGPU_POWER_ON);
	if (status)
		dev_err(&pdev->dev, "failed to turn on dGPU: %d\n", status);
}

static int shps_dgpu_detached(struct platform_device *pdev)
{
	dbg_dump_power_states(pdev, "shps_dgpu_detached");
	return shps_dgpu_set_power(pdev, SHPS_DGPU_POWER_OFF);
}

static int shps_dgpu_attached(struct platform_device *pdev)
{
	dbg_dump_power_states(pdev, "shps_dgpu_attached");
	return 0;
}

static int shps_dgpu_powered_on(struct platform_device *pdev)
{
	/*
	 * This function gets called directly after a power-state transition of
	 * the dGPU root port out of D3cold state, indicating a power-on of the
	 * dGPU. Specifically, this function is called from the RQSG handler of
	 * SAN, invoked by the ACPI _ON method of the dGPU root port. This means
	 * that this function is run inside `pci_set_power_state(rp, ...)`
	 * synchronously and thus returns before the `pci_set_power_state` call
	 * does.
	 *
	 * `pci_set_power_state` may either be called by us or when the PCI
	 * subsystem decides to power up the root port (e.g. during resume). Thus
	 * we should use this function to ensure that the dGPU and root port
	 * states are consistent when an unexpected power-up is encountered.
	 */

	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	struct pci_dev *rp = drvdata->dgpu_root_port;
	int status;

	dbg_dump_drvsta(pdev, "shps_dgpu_powered_on.1");

	// if we caused the root port to power-on, return
	if (test_bit(SHPS_STATE_BIT_RPPWRON_SYNC, &drvdata->state))
		return 0;

	// if dGPU is not present, force power-target to off and return
	status = shps_dgpu_is_present(pdev);
	if (status == 0)
		clear_bit(SHPS_STATE_BIT_PWRTGT, &drvdata->state);
	if (status <= 0)
		return status;

	mutex_lock(&drvdata->lock);

	dbg_dump_power_states(pdev, "shps_dgpu_powered_on.1");
	dbg_dump_pciesta(pdev, "shps_dgpu_powered_on.1");
	if (drvdata->dgpu_root_port_state)
		pci_load_and_free_saved_state(rp, &drvdata->dgpu_root_port_state);
	pci_restore_state(rp);
	if (!pci_is_enabled(rp))
		pci_enable_device(rp);
	pci_set_master(rp);
	dbg_dump_drvsta(pdev, "shps_dgpu_powered_on.2");
	dbg_dump_power_states(pdev, "shps_dgpu_powered_on.2");
	dbg_dump_pciesta(pdev, "shps_dgpu_powered_on.2");

	mutex_unlock(&drvdata->lock);

	if (!test_bit(SHPS_STATE_BIT_PWRTGT, &drvdata->state)) {
		dev_warn(&pdev->dev, "unexpected dGPU power-on detected\n");
		// TODO: schedule state re-check and update
	}

	return 0;
}

static int shps_dgpu_handle_rqsg(struct notifier_block *nb, unsigned long action, void *data)
{
	struct shps_driver_data *drvdata = container_of(nb, struct shps_driver_data, dgpu_nf);
	struct platform_device *pdev = drvdata->pdev;
	struct san_dgpu_event *evt = data;

	if (evt->category == SAM_DGPU_TC && evt->command == SAM_DGPU_CID_POWERON)
		return shps_dgpu_powered_on(pdev);

	dev_warn(&pdev->dev, "unimplemented dGPU request: RQSG(0x%02x, 0x%02x, 0x%02x)\n",
		 evt->category, evt->command, evt->instance);
	return 0;
}

static irqreturn_t shps_dgpu_presence_irq(int irq, void *data)
{
	struct platform_device *pdev = data;
	bool dgpu_present;
	int status;

	status = shps_dgpu_is_present(pdev);
	if (status < 0) {
		dev_err(&pdev->dev, "failed to check physical dGPU presence: %d\n", status);
		return IRQ_HANDLED;
	}

	dgpu_present = status != 0;
	dev_info(&pdev->dev, "dGPU physically %s\n", dgpu_present ? "attached" : "detached");

	if (dgpu_present)
		status = shps_dgpu_attached(pdev);
	else
		status = shps_dgpu_detached(pdev);

	if (status)
		dev_err(&pdev->dev, "error handling dGPU interrupt: %d\n", status);

	return IRQ_HANDLED;
}

static irqreturn_t shps_base_presence_irq(int irq, void *data)
{
	return IRQ_HANDLED;	// nothing to do, just wake
}


static int shps_gpios_setup(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	struct gpio_desc *gpio_dgpu_power;
	struct gpio_desc *gpio_dgpu_presence;
	struct gpio_desc *gpio_base_presence;
	int status;

	// get GPIOs
	gpio_dgpu_power = devm_gpiod_get(&pdev->dev, "dgpu_power", GPIOD_IN);
	if (IS_ERR(gpio_dgpu_power)) {
		status = PTR_ERR(gpio_dgpu_power);
		goto err_out;
	}

	gpio_dgpu_presence = devm_gpiod_get(&pdev->dev, "dgpu_presence", GPIOD_IN);
	if (IS_ERR(gpio_dgpu_presence)) {
		status = PTR_ERR(gpio_dgpu_presence);
		goto err_out;
	}

	gpio_base_presence = devm_gpiod_get(&pdev->dev, "base_presence", GPIOD_IN);
	if (IS_ERR(gpio_base_presence)) {
		status = PTR_ERR(gpio_base_presence);
		goto err_out;
	}

	// export GPIOs
	status = gpiod_export(gpio_dgpu_power, false);
	if (status)
		goto err_out;

	status = gpiod_export(gpio_dgpu_presence, false);
	if (status)
		goto err_export_dgpu_presence;

	status = gpiod_export(gpio_base_presence, false);
	if (status)
		goto err_export_base_presence;

	// create sysfs links
	status = gpiod_export_link(&pdev->dev, "gpio-dgpu_power", gpio_dgpu_power);
	if (status)
		goto err_link_dgpu_power;

	status = gpiod_export_link(&pdev->dev, "gpio-dgpu_presence", gpio_dgpu_presence);
	if (status)
		goto err_link_dgpu_presence;

	status = gpiod_export_link(&pdev->dev, "gpio-base_presence", gpio_base_presence);
	if (status)
		goto err_link_base_presence;

	drvdata->gpio_dgpu_power = gpio_dgpu_power;
	drvdata->gpio_dgpu_presence = gpio_dgpu_presence;
	drvdata->gpio_base_presence = gpio_base_presence;
	return 0;

err_link_base_presence:
	sysfs_remove_link(&pdev->dev.kobj, "gpio-dgpu_presence");
err_link_dgpu_presence:
	sysfs_remove_link(&pdev->dev.kobj, "gpio-dgpu_power");
err_link_dgpu_power:
	gpiod_unexport(gpio_base_presence);
err_export_base_presence:
	gpiod_unexport(gpio_dgpu_presence);
err_export_dgpu_presence:
	gpiod_unexport(gpio_dgpu_power);
err_out:
	return status;
}

static void shps_gpios_remove(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);

	sysfs_remove_link(&pdev->dev.kobj, "gpio-base_presence");
	sysfs_remove_link(&pdev->dev.kobj, "gpio-dgpu_presence");
	sysfs_remove_link(&pdev->dev.kobj, "gpio-dgpu_power");
	gpiod_unexport(drvdata->gpio_base_presence);
	gpiod_unexport(drvdata->gpio_dgpu_presence);
	gpiod_unexport(drvdata->gpio_dgpu_power);
}

static int shps_gpios_setup_irq(struct platform_device *pdev)
{
	const int irqf_dgpu = IRQF_SHARED | IRQF_ONESHOT | IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING;
	const int irqf_base = IRQF_SHARED;
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	int status;

	status = gpiod_to_irq(drvdata->gpio_base_presence);
	if (status < 0)
		return status;
	drvdata->irq_base_presence = status;

	status = gpiod_to_irq(drvdata->gpio_dgpu_presence);
	if (status < 0)
		return status;
	drvdata->irq_dgpu_presence = status;

	status = request_irq(drvdata->irq_base_presence,
			     shps_base_presence_irq, irqf_base,
			     "shps_base_presence_irq", pdev);
	if (status) {
		dev_err(&pdev->dev, "base irq failed: %d\n", status);
		return status;
	}

	status = request_threaded_irq(drvdata->irq_dgpu_presence,
				      NULL, shps_dgpu_presence_irq, irqf_dgpu,
				      "shps_dgpu_presence_irq", pdev);
	if (status) {
		free_irq(drvdata->irq_base_presence, pdev);
		return status;
	}

	return 0;
}

static void shps_gpios_remove_irq(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);

	free_irq(drvdata->irq_base_presence, pdev);
	free_irq(drvdata->irq_dgpu_presence, pdev);
}

static void shps_sgcp_notify(acpi_handle device, u32 value, void *context) {
	struct platform_device *pdev = context;
	switch (value) {
		case ACPI_SGCP_NOTIFY_POWER_ON:
			shps_dgpu_powered_on(pdev);
	}
}

static int shps_start_sgcp_notification(struct platform_device *pdev, acpi_handle *sgpc_handle) {
	acpi_handle handle;
	acpi_status status;

	status = acpi_get_handle(NULL, "\\_SB.SGPC", &handle);
	if (ACPI_FAILURE(status)) {
		dev_err(&pdev->dev, "error in get_handle %x\n", status);
		return -ENXIO;
	}

	status = acpi_install_notify_handler(handle, ACPI_DEVICE_NOTIFY, shps_sgcp_notify, pdev);
	if (ACPI_FAILURE(status)) {
		dev_err(&pdev->dev, "error in install notify %x\n", status);
		*sgpc_handle = NULL;
		return -EFAULT;
	}

	*sgpc_handle = handle;
	return 0;
}

static void shps_remove_sgcp_notification(struct platform_device *pdev) {
	acpi_status status;
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);

	if (drvdata->sgpc_handle) {
		status = acpi_remove_notify_handler(drvdata->sgpc_handle, ACPI_DEVICE_NOTIFY, shps_sgcp_notify);
		if (ACPI_FAILURE(status))
			dev_err(&pdev->dev, "failed to remove notify handler: %x\n", status);
	}
}

static struct shps_hardware_traits shps_detect_hardware_traits(struct platform_device *pdev) {
	const struct shps_hardware_probe *p;

	for (p = shps_hardware_probe_match; p->hardware_id; ++p) {
		if (acpi_dev_present(p->hardware_id, NULL, -1)) {
			break;
		}
	}

	dev_info(&pdev->dev,
		"shps_detect_hardware_traits found device %s, generation %d\n",
		p->hardware_id ? p->hardware_id : "SAN (default)",
		p->generation);

	return *p->hardware_traits;
}

static int shps_probe(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata;
	struct ssam_controller *ctrl;
	struct device_link *link;
	int power, status;
	struct shps_hardware_traits detected_traits;

	if (gpiod_count(&pdev->dev, NULL) < 0) {
		dev_err(&pdev->dev, "gpiod_count returned < 0\n");
		return -ENODEV;
	}

	// link to SSH
	status = ssam_client_bind(&pdev->dev, &ctrl);
	if (status) {
		return status == -ENXIO ? -EPROBE_DEFER : status;
	}

	// detect what kind of hardware we're running
	detected_traits = shps_detect_hardware_traits(pdev);

	if (detected_traits.notification_method == SHPS_NOTIFICATION_METHOD_SAN) {
		// link to SAN
		status = san_client_link(&pdev->dev);
		if (status) {
			dev_err(&pdev->dev, "failed to register as SAN client: %d\n", status);
			return status == -ENXIO ? -EPROBE_DEFER : status;
		}
	}

	status = devm_acpi_dev_add_driver_gpios(&pdev->dev, shps_acpi_gpios);
	if (status) {
		dev_err(&pdev->dev, "failed to add gpios: %d\n", status);
		return status;
	}

	drvdata = devm_kzalloc(&pdev->dev, sizeof(*drvdata), GFP_KERNEL);
	if (!drvdata)
		return -ENOMEM;

	mutex_init(&drvdata->lock);
	platform_set_drvdata(pdev, drvdata);

	drvdata->ctrl = ctrl;
	drvdata->pdev = pdev;
	drvdata->hardware_traits = detected_traits;

	drvdata->dgpu_root_port = shps_dgpu_dsm_get_pci_dev(pdev);
	if (IS_ERR(drvdata->dgpu_root_port)) {
		status = PTR_ERR(drvdata->dgpu_root_port);
		dev_err(&pdev->dev, "failed to get pci dev: %d\n", status);
		return status;
	}

	status = shps_gpios_setup(pdev);
	if (status) {
		dev_err(&pdev->dev, "unable to set up gpios, %d\n", status);
		goto err_gpio;
	}

	status = shps_gpios_setup_irq(pdev);
	if (status) {
		dev_err(&pdev->dev, "unable to set up irqs %d\n", status);
		goto err_gpio_irqs;
	}

	status = device_add_groups(&pdev->dev, shps_power_groups);
	if (status)
		goto err_devattr;

	link = device_link_add(&pdev->dev, &drvdata->dgpu_root_port->dev,
			       DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_CONSUMER);
	if (!link)
		goto err_devlink;

	if (detected_traits.notification_method == SHPS_NOTIFICATION_METHOD_SAN) {
		drvdata->dgpu_nf.priority = 1;
		drvdata->dgpu_nf.notifier_call = shps_dgpu_handle_rqsg;

		status = san_dgpu_notifier_register(&drvdata->dgpu_nf);
		if (status) {
			dev_err(&pdev->dev, "unable to register SAN notification handler (%d)\n", status);
			goto err_devlink;
		}
	} else if (detected_traits.notification_method == SHPS_NOTIFICATION_METHOD_SGCP) {
		status = shps_start_sgcp_notification(pdev, &drvdata->sgpc_handle);
		if (status) {
			dev_err(&pdev->dev, "unable to install SGCP notification handler (%d)\n", status);
			goto err_devlink;
		}
	}

	// if dGPU is not present turn-off root-port, else obey module param
	status = shps_dgpu_is_present(pdev);
	if (status < 0)
		goto err_post_notification;

	power = status == 0 ? SHPS_DGPU_POWER_OFF : param_dgpu_power_init;
	if (power != SHPS_DGPU_MP_POWER_ASIS) {
		status = shps_dgpu_set_power(pdev, power);
		if (status)
			goto err_post_notification;
	}

	// initialize power target
	status = shps_dgpu_rp_get_power(pdev);
	if (status < 0)
		goto err_pwrtgt;

	if (status)
		set_bit(SHPS_STATE_BIT_PWRTGT, &drvdata->state);
	else
		clear_bit(SHPS_STATE_BIT_PWRTGT, &drvdata->state);

	device_init_wakeup(&pdev->dev, true);
	return 0;

err_pwrtgt:
	if (param_dgpu_power_exit != SHPS_DGPU_MP_POWER_ASIS) {
		status = shps_dgpu_set_power(pdev, param_dgpu_power_exit);
		if (status)
			dev_err(&pdev->dev, "failed to set dGPU power state: %d\n", status);
	}
err_post_notification:
	if (detected_traits.notification_method == SHPS_NOTIFICATION_METHOD_SGCP) {
		shps_remove_sgcp_notification(pdev);
	} else if (detected_traits.notification_method == SHPS_NOTIFICATION_METHOD_SAN) {
		san_dgpu_notifier_unregister(&drvdata->dgpu_nf);
	}
err_devlink:
	device_remove_groups(&pdev->dev, shps_power_groups);
err_devattr:
	shps_gpios_remove_irq(pdev);
err_gpio_irqs:
	shps_gpios_remove(pdev);
err_gpio:
	pci_dev_put(drvdata->dgpu_root_port);
	return status;
}

static int shps_remove(struct platform_device *pdev)
{
	struct shps_driver_data *drvdata = platform_get_drvdata(pdev);
	int status;

	if (param_dgpu_power_exit != SHPS_DGPU_MP_POWER_ASIS) {
		status = shps_dgpu_set_power(pdev, param_dgpu_power_exit);
		if (status)
			dev_err(&pdev->dev, "failed to set dGPU power state: %d\n", status);
	}

	device_set_wakeup_capable(&pdev->dev, false);

	if (drvdata->hardware_traits.notification_method == SHPS_NOTIFICATION_METHOD_SGCP) {
		shps_remove_sgcp_notification(pdev);
	} else if (drvdata->hardware_traits.notification_method == SHPS_NOTIFICATION_METHOD_SAN) {
		san_dgpu_notifier_unregister(&drvdata->dgpu_nf);
	}
	device_remove_groups(&pdev->dev, shps_power_groups);
	shps_gpios_remove_irq(pdev);
	shps_gpios_remove(pdev);
	pci_dev_put(drvdata->dgpu_root_port);

	return 0;
}


static const struct dev_pm_ops shps_pm_ops = {
	.prepare = shps_pm_prepare,
	.complete = shps_pm_complete,
	.suspend = shps_pm_suspend,
	.resume = shps_pm_resume,
};

static const struct acpi_device_id shps_acpi_match[] = {
	{ "MSHW0153", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, shps_acpi_match);

static struct platform_driver surface_sam_hps = {
	.probe = shps_probe,
	.remove = shps_remove,
	.shutdown = shps_shutdown,
	.driver = {
		.name = "surface_dgpu_hotplug",
		.acpi_match_table = shps_acpi_match,
		.pm = &shps_pm_ops,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(surface_sam_hps);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("DGPU hot-plug system driver for Surface System Aggregator Module");
MODULE_LICENSE("GPL");
