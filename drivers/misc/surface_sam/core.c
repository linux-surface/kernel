// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface Serial Hub (SSH) driver for communication with the Surface/System
 * Aggregator Module.
 */

#include <linux/acpi.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/gpio/consumer.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/pm.h>
#include <linux/serdev.h>

#include <linux/surface_aggregator_module.h>

#include "bus.h"
#include "controller.h"

#define CREATE_TRACE_POINTS
#include "ssam_trace.h"


/* -- Glue layer (serdev_device -> ssam_controller). ------------------------ */

static int ssam_receive_buf(struct serdev_device *dev, const unsigned char *buf,
			    size_t n)
{
	struct ssam_controller *ctrl = serdev_device_get_drvdata(dev);
	return ssam_controller_receive_buf(ctrl, buf, n);
}

static void ssam_write_wakeup(struct serdev_device *dev)
{
	struct ssam_controller *ctrl = serdev_device_get_drvdata(dev);
	ssam_controller_write_wakeup(ctrl);
}

static const struct serdev_device_ops ssam_serdev_ops = {
	.receive_buf = ssam_receive_buf,
	.write_wakeup = ssam_write_wakeup,
};


/* -- ACPI based device setup. ---------------------------------------------- */

static acpi_status ssam_serdev_setup_via_acpi_crs(struct acpi_resource *rsc,
						  void *ctx)
{
	struct serdev_device *serdev = ctx;
	struct acpi_resource_common_serialbus *serial;
	struct acpi_resource_uart_serialbus *uart;
	bool flow_control;
	int status = 0;

	if (rsc->type != ACPI_RESOURCE_TYPE_SERIAL_BUS)
		return AE_OK;

	serial = &rsc->data.common_serial_bus;
	if (serial->type != ACPI_RESOURCE_SERIAL_TYPE_UART)
		return AE_OK;

	uart = &rsc->data.uart_serial_bus;

	// set up serdev device
	serdev_device_set_baudrate(serdev, uart->default_baud_rate);

	// serdev currently only supports RTSCTS flow control
	if (uart->flow_control & (~((u8) ACPI_UART_FLOW_CONTROL_HW))) {
		dev_warn(&serdev->dev, "setup: unsupported flow control"
			 " (value: 0x%02x)\n", uart->flow_control);
	}

	// set RTSCTS flow control
	flow_control = uart->flow_control & ACPI_UART_FLOW_CONTROL_HW;
	serdev_device_set_flow_control(serdev, flow_control);

	// serdev currently only supports EVEN/ODD parity
	switch (uart->parity) {
	case ACPI_UART_PARITY_NONE:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_NONE);
		break;
	case ACPI_UART_PARITY_EVEN:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_EVEN);
		break;
	case ACPI_UART_PARITY_ODD:
		status = serdev_device_set_parity(serdev, SERDEV_PARITY_ODD);
		break;
	default:
		dev_warn(&serdev->dev, "setup: unsupported parity"
			 " (value: 0x%02x)\n", uart->parity);
		break;
	}

	if (status) {
		dev_err(&serdev->dev, "setup: failed to set parity"
			" (value: 0x%02x)\n", uart->parity);
		return status;
	}

	return AE_CTRL_TERMINATE;       // we've found the resource and are done
}

static acpi_status ssam_serdev_setup_via_acpi(acpi_handle handle,
					      struct serdev_device *serdev)
{
	return acpi_walk_resources(handle, METHOD_NAME__CRS,
				   ssam_serdev_setup_via_acpi_crs, serdev);
}


/* -- Power management. ----------------------------------------------------- */

static void surface_sam_ssh_shutdown(struct device *dev)
{
	struct ssam_controller *c = dev_get_drvdata(dev);
	int status;

	/*
	 * Try to signal display-off and D0-exit, ignore any errors.
	 *
	 * Note: It has not been established yet if this is actually
	 * necessary/useful for shutdown.
	 */

	status = ssam_ctrl_notif_display_off(c);
	if (status)
		ssam_err(c, "pm: display-off notification failed: %d\n", status);

	status = ssam_ctrl_notif_d0_exit(c);
	if (status)
		ssam_err(c, "pm: D0-exit notification failed: %d\n", status);
}

static int surface_sam_ssh_suspend(struct device *dev)
{
	struct ssam_controller *c = dev_get_drvdata(dev);
	int status;

	/*
	 * Try to signal display-off and D0-exit, enable IRQ wakeup if
	 * specified. Abort on error.
	 *
	 * Note: Signalling display-off/display-on should normally be done from
	 * some sort of display state notifier. As that is not available, signal
	 * it here.
	 */

	status = ssam_ctrl_notif_display_off(c);
	if (status) {
		ssam_err(c, "pm: display-off notification failed: %d\n", status);
		return status;
	}

	status = ssam_ctrl_notif_d0_exit(c);
	if (status) {
		ssam_err(c, "pm: D0-exit notification failed: %d\n", status);
		goto err_notif;
	}

	if (device_may_wakeup(dev)) {
		status = enable_irq_wake(c->irq.num);
		if (status) {
			ssam_err(c, "failed to disable wake IRQ: %d\n", status);
			goto err_irq;
		}

		c->irq.wakeup_enabled = true;
	} else {
		c->irq.wakeup_enabled = false;
	}

	WARN_ON(ssam_controller_suspend(c));
	return 0;

err_irq:
	ssam_ctrl_notif_d0_entry(c);
err_notif:
	ssam_ctrl_notif_display_on(c);
	return status;
}

static int surface_sam_ssh_resume(struct device *dev)
{
	struct ssam_controller *c = dev_get_drvdata(dev);
	int status;

	WARN_ON(ssam_controller_resume(c));

	/*
	 * Try to disable IRQ wakeup (if specified), signal display-on and
	 * D0-entry. In case of errors, log them and try to restore normal
	 * operation state as far as possible.
	 *
	 * Note: Signalling display-off/display-on should normally be done from
	 * some sort of display state notifier. As that is not available, signal
	 * it here.
	 */

	if (c->irq.wakeup_enabled) {
		status = disable_irq_wake(c->irq.num);
		if (status)
			ssam_err(c, "failed to disable wake IRQ: %d\n", status);

		c->irq.wakeup_enabled = false;
	}

	status = ssam_ctrl_notif_d0_entry(c);
	if (status)
		ssam_err(c, "pm: display-on notification failed: %d\n", status);

	status = ssam_ctrl_notif_display_on(c);
	if (status)
		ssam_err(c, "pm: D0-entry notification failed: %d\n", status);

	return 0;
}

static SIMPLE_DEV_PM_OPS(surface_sam_ssh_pm_ops, surface_sam_ssh_suspend,
			 surface_sam_ssh_resume);


/* -- Static controller reference. ------------------------------------------ */

static struct ssam_controller *__ssam_controller = NULL;
static DEFINE_SPINLOCK(__ssam_controller_lock);

struct ssam_controller *ssam_get_controller(void)
{
	struct ssam_controller *ctrl;

	spin_lock(&__ssam_controller_lock);

	ctrl = __ssam_controller;
	if (!ctrl)
		goto out;

	if (WARN_ON(!kref_get_unless_zero(&ctrl->kref)))
		ctrl = NULL;

out:
	spin_unlock(&__ssam_controller_lock);
	return ctrl;
}
EXPORT_SYMBOL_GPL(ssam_get_controller);

static int ssam_try_set_controller(struct ssam_controller *ctrl)
{
	int status = 0;

	spin_lock(&__ssam_controller_lock);
	if (!__ssam_controller)
		__ssam_controller = ctrl;
	else
		status = -EBUSY;
	spin_unlock(&__ssam_controller_lock);

	return status;
}

static void ssam_clear_controller(void)
{
	spin_lock(&__ssam_controller_lock);
	__ssam_controller = NULL;
	spin_unlock(&__ssam_controller_lock);
}


static int __ssam_client_link(struct ssam_controller *c, struct device *client)
{
	const u32 flags = DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_CONSUMER;
	struct device_link *link;
	struct device *ctrldev;

	if (smp_load_acquire(&c->state) != SSAM_CONTROLLER_STARTED)
		return -ENXIO;

	if ((ctrldev = ssam_controller_device(c)) == NULL)
		return -ENXIO;

	if ((link = device_link_add(client, ctrldev, flags)) == NULL)
		return -ENOMEM;

	/*
	 * Return -ENXIO if supplier driver is on its way to be removed. In this
	 * case, the controller won't be around for much longer and the device
	 * link is not going to save us any more, as unbinding is already in
	 * progress.
	 */
	if (link->status == DL_STATE_SUPPLIER_UNBIND)
		return -ENXIO;

	return 0;
}

int ssam_client_link(struct ssam_controller *ctrl, struct device *client)
{
	int status;

	ssam_controller_statelock(ctrl);
	status = __ssam_client_link(ctrl, client);
	ssam_controller_stateunlock(ctrl);

	return status;
}
EXPORT_SYMBOL_GPL(ssam_client_link);

int ssam_client_bind(struct device *client, struct ssam_controller **ctrl)
{
	struct ssam_controller *c;
	int status;

	c = ssam_get_controller();
	if (!c)
		return -ENXIO;

	status = ssam_client_link(c, client);

	/*
	 * Note that we can drop our controller reference in both success and
	 * failure cases: On success, we have bound the controller lifetime
	 * inherently to the client driver lifetime, i.e. it the controller is
	 * now guaranteed to outlive the client driver. On failure, we're not
	 * going to use the controller any more.
	 */
	ssam_controller_put(c);

	*ctrl = status == 0 ? c : NULL;
	return status;
}
EXPORT_SYMBOL_GPL(ssam_client_bind);


/* -- Device/driver setup. -------------------------------------------------- */

static const struct acpi_gpio_params gpio_ssam_wakeup_int = { 0, 0, false };
static const struct acpi_gpio_params gpio_ssam_wakeup     = { 1, 0, false };

static const struct acpi_gpio_mapping ssam_acpi_gpios[] = {
	{ "ssam_wakeup-int-gpio", &gpio_ssam_wakeup_int, 1 },
	{ "ssam_wakeup-gpio",     &gpio_ssam_wakeup,     1 },
	{ },
};

static int surface_sam_ssh_probe(struct serdev_device *serdev)
{
	struct ssam_controller *ctrl;
	acpi_handle *ssh = ACPI_HANDLE(&serdev->dev);
	int status;

	if (gpiod_count(&serdev->dev, NULL) < 0)
		return -ENODEV;

	status = devm_acpi_dev_add_driver_gpios(&serdev->dev, ssam_acpi_gpios);
	if (status)
		return status;

	// allocate controller
	ctrl = kzalloc(sizeof(struct ssam_controller), GFP_KERNEL);
	if (!ctrl)
		return -ENOMEM;

	// initialize controller
	status = ssam_controller_init(ctrl, serdev);
	if (status)
		goto err_ctrl_init;

	// set up serdev device
	serdev_device_set_drvdata(serdev, ctrl);
	serdev_device_set_client_ops(serdev, &ssam_serdev_ops);
	status = serdev_device_open(serdev);
	if (status)
		goto err_devopen;

	status = ssam_serdev_setup_via_acpi(ssh, serdev);
	if (ACPI_FAILURE(status))
		goto err_devinit;

	// start controller
	status = ssam_controller_start(ctrl);
	if (status)
		goto err_devinit;

	// initial SAM requests: log version, notify default/init power states
	status = ssam_log_firmware_version(ctrl);
	if (status)
		goto err_initrq;

	status = ssam_ctrl_notif_d0_entry(ctrl);
	if (status)
		goto err_initrq;

	status = ssam_ctrl_notif_display_on(ctrl);
	if (status)
		goto err_initrq;

	// setup IRQ
	status = ssam_irq_setup(ctrl);
	if (status)
		goto err_initrq;

	// finally, set main controller reference
	status = ssam_try_set_controller(ctrl);
	if (status)
		goto err_initrq;

	/*
	 * TODO: The EC can wake up the system via the associated GPIO interrupt
	 *       in multiple situations. One of which is the remaining battery
	 *       capacity falling below a certain threshold. Normally, we should
	 *       use the device_init_wakeup function, however, the EC also seems
	 *       to have other reasons for waking up the system and it seems
	 *       that Windows has additional checks whether the system should be
	 *       resumed. In short, this causes some spurious unwanted wake-ups.
	 *       For now let's thus default power/wakeup to false.
	 */
	device_set_wakeup_capable(&serdev->dev, true);
	acpi_walk_dep_device_list(ssh);

	return 0;

err_initrq:
	ssam_controller_shutdown(ctrl);
err_devinit:
	serdev_device_close(serdev);
err_devopen:
	ssam_controller_destroy(ctrl);
	serdev_device_set_drvdata(serdev, NULL);
err_ctrl_init:
	kfree(ctrl);
	return status;
}

static void surface_sam_ssh_remove(struct serdev_device *serdev)
{
	struct ssam_controller *ctrl = serdev_device_get_drvdata(serdev);
	int status;

	// clear static reference, so that no one else can get a new one
	ssam_clear_controller();

	ssam_irq_free(ctrl);
	ssam_controller_lock(ctrl);

	// remove all client devices
	ssam_controller_remove_clients(ctrl);

	// act as if suspending to disable events
	status = ssam_ctrl_notif_display_off(ctrl);
	if (status) {
		dev_err(&serdev->dev, "display-off notification failed: %d\n",
			status);
	}

	status = ssam_ctrl_notif_d0_exit(ctrl);
	if (status) {
		dev_err(&serdev->dev, "D0-exit notification failed: %d\n",
			status);
	}

	// shut down controller and remove serdev device reference from it
	ssam_controller_shutdown(ctrl);

	// shut down actual transport
	serdev_device_wait_until_sent(serdev, 0);
	serdev_device_close(serdev);

	// drop our controller reference
	ssam_controller_unlock(ctrl);
	ssam_controller_put(ctrl);

	device_set_wakeup_capable(&serdev->dev, false);
	serdev_device_set_drvdata(serdev, NULL);
}


static const struct acpi_device_id surface_sam_ssh_match[] = {
	{ "MSHW0084", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_sam_ssh_match);

static struct serdev_device_driver surface_sam_ssh = {
	.probe = surface_sam_ssh_probe,
	.remove = surface_sam_ssh_remove,
	.driver = {
		.name = "surface_sam_ssh",
		.acpi_match_table = surface_sam_ssh_match,
		.pm = &surface_sam_ssh_pm_ops,
		.shutdown = surface_sam_ssh_shutdown,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};


/* -- Module setup. --------------------------------------------------------- */

static int __init surface_sam_ssh_init(void)
{
	int status;

	status = ssam_bus_register();
	if (status)
		goto err_bus;

	status = ssh_ctrl_packet_cache_init();
	if (status)
		goto err_cpkg;

	status = ssam_event_item_cache_init();
	if (status)
		goto err_evitem;

	status = serdev_device_driver_register(&surface_sam_ssh);
	if (status)
		goto err_register;

	return 0;

err_register:
	ssam_event_item_cache_destroy();
err_evitem:
	ssh_ctrl_packet_cache_destroy();
err_cpkg:
	ssam_bus_unregister();
err_bus:
	return status;
}

static void __exit surface_sam_ssh_exit(void)
{
	serdev_device_driver_unregister(&surface_sam_ssh);
	ssam_event_item_cache_destroy();
	ssh_ctrl_packet_cache_destroy();
	ssam_bus_unregister();
}

/*
 * Ensure that the driver is loaded late due to some issues with the UART
 * communication. Specifically, we want to ensure that DMA is ready and being
 * used. Not using DMA can result in spurious communication failures,
 * especially during boot, which among other things will result in wrong
 * battery information (via ACPI _BIX) being displayed. Using a late init_call
 * instead of the normal module_init gives the DMA subsystem time to
 * initialize and via that results in a more stable communication, avoiding
 * such failures.
 */
late_initcall(surface_sam_ssh_init);
module_exit(surface_sam_ssh_exit);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface Serial Hub Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL");
