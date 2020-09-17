// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface performance-mode driver.
 *
 * Proides a user-space interface for the performance mode control provided by
 * the Surface System Aggregator Module (SSAM), influencing cooling behavior
 * of the device and potentially managing power limits.
 */

#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <linux/types.h>

#include <linux/surface_aggregator/device.h>


#define SID_PARAM_PERM		0644

enum sam_perf_mode {
	SAM_PERF_MODE_NORMAL   = 1,
	SAM_PERF_MODE_BATTERY  = 2,
	SAM_PERF_MODE_PERF1    = 3,
	SAM_PERF_MODE_PERF2    = 4,

	__SAM_PERF_MODE__START = 1,
	__SAM_PERF_MODE__END   = 4,
};

enum sid_param_perf_mode {
	SID_PARAM_PERF_MODE_AS_IS    = 0,
	SID_PARAM_PERF_MODE_NORMAL   = SAM_PERF_MODE_NORMAL,
	SID_PARAM_PERF_MODE_BATTERY  = SAM_PERF_MODE_BATTERY,
	SID_PARAM_PERF_MODE_PERF1    = SAM_PERF_MODE_PERF1,
	SID_PARAM_PERF_MODE_PERF2    = SAM_PERF_MODE_PERF2,

	__SID_PARAM_PERF_MODE__START = 0,
	__SID_PARAM_PERF_MODE__END   = 4,
};


struct ssam_perf_info {
	__le32 mode;
	__le16 unknown1;
	__le16 unknown2;
} __packed;

static SSAM_DEFINE_SYNC_REQUEST_CL_R(ssam_tmp_perf_mode_get, struct ssam_perf_info, {
	.target_category = SSAM_SSH_TC_TMP,
	.command_id      = 0x02,
});

static SSAM_DEFINE_SYNC_REQUEST_CL_W(__ssam_tmp_perf_mode_set, __le32, {
	.target_category = SSAM_SSH_TC_TMP,
	.command_id      = 0x03,
});

static int ssam_tmp_perf_mode_set(struct ssam_device *sdev, u32 mode)
{
	__le32 mode_le = cpu_to_le32(mode);

	if (mode < __SAM_PERF_MODE__START || mode > __SAM_PERF_MODE__END)
		return -EINVAL;

	return __ssam_tmp_perf_mode_set(sdev, &mode_le);
}


static int param_perf_mode_set(const char *val, const struct kernel_param *kp)
{
	int perf_mode;
	int status;

	status = kstrtoint(val, 0, &perf_mode);
	if (status)
		return status;

	if (perf_mode < __SID_PARAM_PERF_MODE__START || perf_mode > __SID_PARAM_PERF_MODE__END)
		return -EINVAL;

	return param_set_int(val, kp);
}

static const struct kernel_param_ops param_perf_mode_ops = {
	.set = param_perf_mode_set,
	.get = param_get_int,
};

static int param_perf_mode_init = SID_PARAM_PERF_MODE_AS_IS;
static int param_perf_mode_exit = SID_PARAM_PERF_MODE_AS_IS;

module_param_cb(perf_mode_init, &param_perf_mode_ops, &param_perf_mode_init, SID_PARAM_PERM);
module_param_cb(perf_mode_exit, &param_perf_mode_ops, &param_perf_mode_exit, SID_PARAM_PERM);

MODULE_PARM_DESC(perf_mode_init, "Performance-mode to be set on module initialization");
MODULE_PARM_DESC(perf_mode_exit, "Performance-mode to be set on module exit");


static ssize_t perf_mode_show(struct device *dev, struct device_attribute *attr, char *data)
{
	struct ssam_device *sdev = to_ssam_device(dev);
	struct ssam_perf_info info;
	int status;

	status = ssam_tmp_perf_mode_get(sdev, &info);
	if (status) {
		dev_err(dev, "failed to get current performance mode: %d\n", status);
		return -EIO;
	}

	return sprintf(data, "%d\n", le32_to_cpu(info.mode));
}

static ssize_t perf_mode_store(struct device *dev, struct device_attribute *attr,
			       const char *data, size_t count)
{
	struct ssam_device *sdev = to_ssam_device(dev);
	int perf_mode;
	int status;

	status = kstrtoint(data, 0, &perf_mode);
	if (status)
		return status;

	status = ssam_tmp_perf_mode_set(sdev, perf_mode);
	if (status)
		return status;

	// TODO: Should we notify ACPI here?
	//
	//       There is a _DSM call described as
	//           WSID._DSM: Notify DPTF on Slider State change
	//       which calls
	//           ODV3 = ToInteger (Arg3)
	//           Notify(IETM, 0x88)
	//       IETM is an INT3400 Intel Dynamic Power Performance Management
	//       device, part of the DPTF framework. From the corresponding
	//       kernel driver, it looks like event 0x88 is being ignored. Also
	//       it is currently unknown what the consequecnes of setting ODV3
	//       are.

	return count;
}

static const DEVICE_ATTR_RW(perf_mode);


static int surface_sam_sid_perfmode_probe(struct ssam_device *sdev)
{
	int status;

	// set initial perf_mode
	if (param_perf_mode_init != SID_PARAM_PERF_MODE_AS_IS) {
		status = ssam_tmp_perf_mode_set(sdev, param_perf_mode_init);
		if (status)
			return status;
	}

	// register perf_mode attribute
	status = sysfs_create_file(&sdev->dev.kobj, &dev_attr_perf_mode.attr);
	if (status)
		ssam_tmp_perf_mode_set(sdev, param_perf_mode_exit);

	return status;
}

static void surface_sam_sid_perfmode_remove(struct ssam_device *sdev)
{
	sysfs_remove_file(&sdev->dev.kobj, &dev_attr_perf_mode.attr);
	ssam_tmp_perf_mode_set(sdev, param_perf_mode_exit);
}


static const struct ssam_device_id ssam_perfmode_match[] = {
	{ SSAM_SDEV(TMP, 0x01, 0x00, 0x01) },
	{ },
};
MODULE_DEVICE_TABLE(ssam, ssam_perfmode_match);

static struct ssam_device_driver surface_sam_sid_perfmode = {
	.probe = surface_sam_sid_perfmode_probe,
	.remove = surface_sam_sid_perfmode_remove,
	.match_table = ssam_perfmode_match,
	.driver = {
		.name = "surface_performance_mode",
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_ssam_device_driver(surface_sam_sid_perfmode);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Performance mode interface for Surface System Aggregator Module");
MODULE_LICENSE("GPL");
