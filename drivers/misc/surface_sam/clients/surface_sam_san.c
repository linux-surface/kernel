// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Surface ACPI Notify (SAN) and ACPI integration driver for SAM.
 * Translates communication from ACPI to SSH and back.
 */

#include <asm/unaligned.h>
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>

#include <linux/surface_aggregator_module.h>
#include "surface_sam_san.h"


#define SAN_RQST_RETRY				5

#define SAN_DSM_REVISION			0
#define SAN_DSM_FN_NOTIFY_SENSOR_TRIP_POINT	0x09

static const guid_t SAN_DSM_UUID =
	GUID_INIT(0x93b666c5, 0x70c6, 0x469f, 0xa2, 0x15, 0x3d,
		  0x48, 0x7c, 0x91, 0xab, 0x3c);

#define SAM_EVENT_DELAY_PWR_ADAPTER	msecs_to_jiffies(5000)
#define SAM_EVENT_DELAY_PWR_BST		msecs_to_jiffies(2500)

#define SAM_EVENT_PWR_CID_BIX		0x15
#define SAM_EVENT_PWR_CID_BST		0x16
#define SAM_EVENT_PWR_CID_ADAPTER	0x17
#define SAM_EVENT_PWR_CID_DPTF		0x4f

#define SAM_EVENT_TEMP_CID_NOTIFY_SENSOR_TRIP_POINT	0x0b


struct san_acpi_consumer {
	char *path;
	bool  required;
	u32   flags;
};

struct san_handler_data {
	struct acpi_connection_info info;		// must be first
};

struct san_consumer_link {
	const struct san_acpi_consumer *properties;
	struct device_link *link;
};

struct san_consumers {
	u32 num;
	struct san_consumer_link *links;
};

struct san_data {
	struct device *dev;
	struct ssam_controller *ctrl;

	struct san_handler_data context;
	struct san_consumers consumers;

	struct ssam_event_notifier nf_bat;
	struct ssam_event_notifier nf_tmp;
};

#define to_san_data(ptr, member) \
	container_of(ptr, struct san_data, member)

struct san_event_work {
	struct delayed_work work;
	struct device *dev;
	struct ssam_event event;		// must be last
};

struct gsb_data_in {
	u8 cv;
} __packed;

struct gsb_data_rqsx {
	u8 cv;				// command value (should be 0x01 or 0x03)
	u8 tc;				// target controller
	u8 tid;				// transport channnel ID
	u8 iid;				// target sub-controller (e.g. primary vs. secondary battery)
	u8 snc;				// expect-response-flag
	u8 cid;				// command ID
	u16 cdl;			// payload length
	u8 pld[0];			// payload
} __packed;

struct gsb_data_etwl {
	u8 cv;				// command value (should be 0x02)
	u8 etw3;			// ?
	u8 etw4;			// ?
	u8 msg[0];			// error message (ASCIIZ)
} __packed;

struct gsb_data_out {
	u8 status;			// _SSH communication status
	u8 len;				// _SSH payload length
	u8 pld[0];			// _SSH payload
} __packed;

union gsb_buffer_data {
	struct gsb_data_in   in;	// common input
	struct gsb_data_rqsx rqsx;	// RQSX input
	struct gsb_data_etwl etwl;	// ETWL input
	struct gsb_data_out  out;	// output
};

struct gsb_buffer {
	u8 status;			// GSB AttribRawProcess status
	u8 len;				// GSB AttribRawProcess length
	union gsb_buffer_data data;
} __packed;

#define SAN_GSB_MAX_RQSX_PAYLOAD  (U8_MAX - 2 - sizeof(struct gsb_data_rqsx))
#define SAN_GSB_MAX_RESPONSE	  (U8_MAX - 2 - sizeof(struct gsb_data_out))

#define san_request_sync_onstack(ctrl, rqst, rsp) \
	ssam_request_sync_onstack(ctrl, rqst, rsp, SAN_GSB_MAX_RQSX_PAYLOAD)


enum san_pwr_event {
	SAN_PWR_EVENT_BAT1_STAT	= 0x03,
	SAN_PWR_EVENT_BAT1_INFO	= 0x04,
	SAN_PWR_EVENT_ADP1_STAT	= 0x05,
	SAN_PWR_EVENT_ADP1_INFO	= 0x06,
	SAN_PWR_EVENT_BAT2_STAT	= 0x07,
	SAN_PWR_EVENT_BAT2_INFO	= 0x08,
	SAN_PWR_EVENT_DPTF      = 0x0A,
};


static int sam_san_default_rqsg_handler(struct surface_sam_san_rqsg *rqsg, void *data);

struct sam_san_rqsg_if {
	struct mutex lock;
	struct device *san_dev;
	surface_sam_san_rqsg_handler_fn handler;
	void *handler_data;
};

static struct sam_san_rqsg_if rqsg_if = {
	.lock = __MUTEX_INITIALIZER(rqsg_if.lock),
	.san_dev = NULL,
	.handler = sam_san_default_rqsg_handler,
	.handler_data = NULL,
};

int surface_sam_san_consumer_register(struct device *consumer, u32 flags)
{
	const u32 valid = DL_FLAG_PM_RUNTIME | DL_FLAG_RPM_ACTIVE;
	int status;

	if ((flags | valid) != valid)
		return -EINVAL;

	flags |= DL_FLAG_AUTOREMOVE_CONSUMER;

	mutex_lock(&rqsg_if.lock);
	if (rqsg_if.san_dev)
		status = device_link_add(consumer, rqsg_if.san_dev, flags) ? 0 : -EINVAL;
	else
		status = -ENXIO;
	mutex_unlock(&rqsg_if.lock);
	return status;
}
EXPORT_SYMBOL_GPL(surface_sam_san_consumer_register);

int surface_sam_san_set_rqsg_handler(surface_sam_san_rqsg_handler_fn fn, void *data)
{
	int status = -EBUSY;

	mutex_lock(&rqsg_if.lock);

	if (rqsg_if.handler == sam_san_default_rqsg_handler || !fn) {
		rqsg_if.handler = fn ? fn : sam_san_default_rqsg_handler;
		rqsg_if.handler_data = fn ? data : NULL;
		status = 0;
	}

	mutex_unlock(&rqsg_if.lock);
	return status;
}
EXPORT_SYMBOL_GPL(surface_sam_san_set_rqsg_handler);

int san_call_rqsg_handler(struct surface_sam_san_rqsg *rqsg)
{
	int status;

	mutex_lock(&rqsg_if.lock);
	status = rqsg_if.handler(rqsg, rqsg_if.handler_data);
	mutex_unlock(&rqsg_if.lock);

	return status;
}

static int sam_san_default_rqsg_handler(struct surface_sam_san_rqsg *rqsg, void *data)
{
	struct device *dev = rqsg_if.san_dev;

	dev_warn(dev, "unhandled request: RQSG(0x%02x, 0x%02x, 0x%02x)\n",
		 rqsg->tc, rqsg->cid, rqsg->iid);

	return 0;
}


static bool san_acpi_can_notify(struct device *dev, u64 func)
{
	acpi_handle san = ACPI_HANDLE(dev);
	return acpi_check_dsm(san, &SAN_DSM_UUID, SAN_DSM_REVISION, 1 << func);
}

static int san_acpi_notify_power_event(struct device *dev, enum san_pwr_event event)
{
	acpi_handle san = ACPI_HANDLE(dev);
	union acpi_object *obj;

	if (!san_acpi_can_notify(dev, event))
		return 0;

	dev_dbg(dev, "notify power event 0x%02x\n", event);
	obj = acpi_evaluate_dsm_typed(san, &SAN_DSM_UUID, SAN_DSM_REVISION,
				      event, NULL, ACPI_TYPE_BUFFER);

	if (IS_ERR_OR_NULL(obj))
		return obj ? PTR_ERR(obj) : -ENXIO;

	if (obj->buffer.length != 1 || obj->buffer.pointer[0] != 0) {
		dev_err(dev, "got unexpected result from _DSM\n");
		return -EFAULT;
	}

	ACPI_FREE(obj);
	return 0;
}

static int san_acpi_notify_sensor_trip_point(struct device *dev, u8 iid)
{
	acpi_handle san = ACPI_HANDLE(dev);
	union acpi_object *obj;
	union acpi_object param;

	if (!san_acpi_can_notify(dev, SAN_DSM_FN_NOTIFY_SENSOR_TRIP_POINT))
		return 0;

	param.type = ACPI_TYPE_INTEGER;
	param.integer.value = iid;

	obj = acpi_evaluate_dsm_typed(san, &SAN_DSM_UUID, SAN_DSM_REVISION,
				      SAN_DSM_FN_NOTIFY_SENSOR_TRIP_POINT,
				      &param, ACPI_TYPE_BUFFER);

	if (IS_ERR_OR_NULL(obj))
		return obj ? PTR_ERR(obj) : -ENXIO;

	if (obj->buffer.length != 1 || obj->buffer.pointer[0] != 0) {
		dev_err(dev, "got unexpected result from _DSM\n");
		return -EFAULT;
	}

	ACPI_FREE(obj);
	return 0;
}


static inline int san_evt_power_adapter(struct device *dev, const struct ssam_event *event)
{
	int status;

	status = san_acpi_notify_power_event(dev, SAN_PWR_EVENT_ADP1_STAT);
	if (status)
		return status;

	/*
	 * Enusre that the battery states get updated correctly.
	 * When the battery is fully charged and an adapter is plugged in, it
	 * sometimes is not updated correctly, instead showing it as charging.
	 * Explicitly trigger battery updates to fix this.
	 */

	status = san_acpi_notify_power_event(dev, SAN_PWR_EVENT_BAT1_STAT);
	if (status)
		return status;

	return san_acpi_notify_power_event(dev, SAN_PWR_EVENT_BAT2_STAT);
}

static inline int san_evt_power_bix(struct device *dev, const struct ssam_event *event)
{
	enum san_pwr_event evcode;

	if (event->instance_id == 0x02)
		evcode = SAN_PWR_EVENT_BAT2_INFO;
	else
		evcode = SAN_PWR_EVENT_BAT1_INFO;

	return san_acpi_notify_power_event(dev, evcode);
}

static inline int san_evt_power_bst(struct device *dev, const struct ssam_event *event)
{
	enum san_pwr_event evcode;

	if (event->instance_id == 0x02)
		evcode = SAN_PWR_EVENT_BAT2_STAT;
	else
		evcode = SAN_PWR_EVENT_BAT1_STAT;

	return san_acpi_notify_power_event(dev, evcode);
}

static inline int san_evt_power_dptf(struct device *dev, const struct ssam_event *event)
{
	union acpi_object payload;
	acpi_handle san = ACPI_HANDLE(dev);
	union acpi_object *obj;

	if (!san_acpi_can_notify(dev, SAN_PWR_EVENT_DPTF))
		return 0;

	/*
	 * The Surface ACPI expects a buffer and not a package. It specifically
	 * checks for ObjectType (Arg3) == 0x03. This will cause a warning in
	 * acpica/nsarguments.c, but this can safely be ignored.
	 */
	payload.type = ACPI_TYPE_BUFFER;
	payload.buffer.length = event->length;
	payload.buffer.pointer = (u8 *)&event->data[0];

	dev_dbg(dev, "notify power event 0x%02x\n", event->command_id);
	obj = acpi_evaluate_dsm_typed(san, &SAN_DSM_UUID, SAN_DSM_REVISION,
				      SAN_PWR_EVENT_DPTF, &payload,
				      ACPI_TYPE_BUFFER);

	if (IS_ERR_OR_NULL(obj))
		return obj ? PTR_ERR(obj) : -ENXIO;

	if (obj->buffer.length != 1 || obj->buffer.pointer[0] != 0) {
		dev_err(dev, "got unexpected result from _DSM\n");
		return -EFAULT;
	}

	ACPI_FREE(obj);
	return 0;
}

static unsigned long san_evt_power_delay(u8 cid)
{
	switch (cid) {
	case SAM_EVENT_PWR_CID_ADAPTER:
		/*
		 * Wait for battery state to update before signalling adapter change.
		 */
		return SAM_EVENT_DELAY_PWR_ADAPTER;

	case SAM_EVENT_PWR_CID_BST:
		/*
		 * Ensure we do not miss anything important due to caching.
		 */
		return SAM_EVENT_DELAY_PWR_BST;

	case SAM_EVENT_PWR_CID_BIX:
	case SAM_EVENT_PWR_CID_DPTF:
	default:
		return 0;
	}
}

static bool san_evt_power(const struct ssam_event *event, struct device *dev)
{
	int status;

	switch (event->command_id) {
	case SAM_EVENT_PWR_CID_BIX:
		status = san_evt_power_bix(dev, event);
		break;

	case SAM_EVENT_PWR_CID_BST:
		status = san_evt_power_bst(dev, event);
		break;

	case SAM_EVENT_PWR_CID_ADAPTER:
		status = san_evt_power_adapter(dev, event);
		break;

	case SAM_EVENT_PWR_CID_DPTF:
		status = san_evt_power_dptf(dev, event);
		break;

	default:
		return false;
	}

	if (status)
		dev_err(dev, "error handling power event (cid = %x)\n",
			event->command_id);

	return true;
}

static void san_evt_power_workfn(struct work_struct *work)
{
	struct san_event_work *ev = container_of(work, struct san_event_work, work.work);

	san_evt_power(&ev->event, ev->dev);
	kfree(ev);
}


static u32 san_evt_power_nb(struct ssam_notifier_block *nb, const struct ssam_event *event)
{
	struct san_data *d = to_san_data(nb, nf_bat.base);
	struct san_event_work *work;
	unsigned long delay = san_evt_power_delay(event->command_id);

	if (delay == 0) {
		if (san_evt_power(event, d->dev))
			return SSAM_NOTIF_HANDLED;
		else
			return 0;
	}

	work = kzalloc(sizeof(struct san_event_work) + event->length, GFP_KERNEL);
	if (!work)
		return ssam_notifier_from_errno(-ENOMEM);

	INIT_DELAYED_WORK(&work->work, san_evt_power_workfn);
	work->dev = d->dev;

	memcpy(&work->event, event, sizeof(struct ssam_event) + event->length);

	schedule_delayed_work(&work->work, delay);
	return SSAM_NOTIF_HANDLED;
}


static inline int san_evt_thermal_notify(struct device *dev, const struct ssam_event *event)
{
	return san_acpi_notify_sensor_trip_point(dev, event->instance_id);
}

static bool san_evt_thermal(const struct ssam_event *event, struct device *dev)
{
	int status;

	switch (event->command_id) {
	case SAM_EVENT_TEMP_CID_NOTIFY_SENSOR_TRIP_POINT:
		status = san_evt_thermal_notify(dev, event);
		break;

	default:
		return false;
	}

	if (status) {
		dev_err(dev, "error handling thermal event (cid = %x)\n",
			event->command_id);
	}

	return true;
}

static u32 san_evt_thermal_nb(struct ssam_notifier_block *nb, const struct ssam_event *event)
{
	if (san_evt_thermal(event, to_san_data(nb, nf_tmp.base)->dev))
		return SSAM_NOTIF_HANDLED;
	else
		return 0;
}


static struct gsb_data_rqsx
*san_validate_rqsx(struct device *dev, const char *type, struct gsb_buffer *buffer)
{
	struct gsb_data_rqsx *rqsx = &buffer->data.rqsx;

	if (buffer->len < 8) {
		dev_err(dev, "invalid %s package (len = %d)\n",
			type, buffer->len);
		return NULL;
	}

	if (get_unaligned(&rqsx->cdl) != buffer->len - sizeof(struct gsb_data_rqsx)) {
		dev_err(dev, "bogus %s package (len = %d, cdl = %d)\n",
			type, buffer->len, get_unaligned(&rqsx->cdl));
		return NULL;
	}

	if (get_unaligned(&rqsx->cdl) > SAN_GSB_MAX_RQSX_PAYLOAD) {
		dev_err(dev, "payload for %s package too large (cdl = %d)\n",
			type, get_unaligned(&rqsx->cdl));
		return NULL;
	}

	if (rqsx->tid != 0x01) {
		dev_warn(dev, "unsupported %s package (tid = 0x%02x)\n",
			 type, rqsx->tid);
		return NULL;
	}

	return rqsx;
}

static acpi_status san_etwl(struct san_data *d, struct gsb_buffer *buffer)
{
	struct gsb_data_etwl *etwl = &buffer->data.etwl;

	if (buffer->len < 3) {
		dev_err(d->dev, "invalid ETWL package (len = %d)\n", buffer->len);
		return AE_OK;
	}

	dev_err(d->dev, "ETWL(0x%02x, 0x%02x): %.*s\n",
		etwl->etw3, etwl->etw4,
		buffer->len - 3, (char *)etwl->msg);

	// indicate success
	buffer->status = 0x00;
	buffer->len = 0x00;

	return AE_OK;
}

static void gsb_response_error(struct gsb_buffer *gsb, int status)
{
	gsb->status          = 0x00;
	gsb->len             = 0x02;
	gsb->data.out.status = (u8)(-status);
	gsb->data.out.len    = 0x00;
}

static void gsb_response_success(struct gsb_buffer *gsb, u8 *ptr, size_t len)
{
	gsb->status          = 0x00;
	gsb->len             = len + 2;
	gsb->data.out.status = 0x00;
	gsb->data.out.len    = len;

	if (len)
		memcpy(&gsb->data.out.pld[0], ptr, len);
}

static acpi_status san_rqst_fixup_suspended(struct ssam_request *rqst,
					    struct gsb_buffer *gsb)
{
	if (rqst->target_category == 0x11 && rqst->command_id == 0x0D) {
		/* Base state quirk:
		 * The base state may be queried from ACPI when the EC is still
		 * suspended. In this case it will return '-EPERM'. This query
		 * will only be triggered from the ACPI lid GPE interrupt, thus
		 * we are either in laptop or studio mode (base status 0x01 or
		 * 0x02). Furthermore, we will only get here if the device (and
		 * EC) have been suspended.
		 *
		 * We now assume that the device is in laptop mode (0x01). This
		 * has the drawback that it will wake the device when unfolding
		 * it in studio mode, but it also allows us to avoid actively
		 * waiting for the EC to wake up, which may incur a notable
		 * delay.
		 */

		u8 base_state = 1;
		gsb_response_success(gsb, &base_state, 1);
		return AE_OK;
	}

	gsb_response_error(gsb, -ENXIO);
	return AE_OK;
}

static acpi_status san_rqst(struct san_data *d, struct gsb_buffer *buffer)
{
	u8 rspbuf[SAN_GSB_MAX_RESPONSE];
	struct gsb_data_rqsx *gsb_rqst;
	struct ssam_request rqst;
	struct ssam_response rsp;
	int status = 0;
	int try;

 	gsb_rqst = san_validate_rqsx(d->dev, "RQST", buffer);
	if (!gsb_rqst)
		return AE_OK;

	rqst.target_category  = gsb_rqst->tc;
	rqst.command_id = gsb_rqst->cid;
	rqst.instance_id = gsb_rqst->iid;
	rqst.channel = gsb_rqst->tid;
	rqst.flags = gsb_rqst->snc ? SSAM_REQUEST_HAS_RESPONSE : 0;
	rqst.length = get_unaligned(&gsb_rqst->cdl);
	rqst.payload = &gsb_rqst->pld[0];

	rsp.capacity = ARRAY_SIZE(rspbuf);
	rsp.length  = 0;
	rsp.pointer = &rspbuf[0];

	// handle suspended device
	if (d->dev->power.is_suspended) {
		dev_warn(d->dev, "rqst: device is suspended, not executing\n");
		return san_rqst_fixup_suspended(&rqst, buffer);
	}

	for (try = 0; try < SAN_RQST_RETRY; try++) {
		if (try)
			dev_warn(d->dev, "rqst: IO error, trying again\n");

		status = san_request_sync_onstack(d->ctrl, &rqst, &rsp);
		if (status != -ETIMEDOUT && status != -EREMOTEIO)
			break;
	}

	if (!status) {
		gsb_response_success(buffer, rsp.pointer, rsp.length);
	} else {
		dev_err(d->dev, "rqst: failed with error %d\n", status);
		gsb_response_error(buffer, status);
	}

	return AE_OK;
}

static acpi_status san_rqsg(struct san_data *d, struct gsb_buffer *buffer)
{
	struct gsb_data_rqsx *gsb_rqsg;
	struct surface_sam_san_rqsg rqsg;
	int status;

	gsb_rqsg = san_validate_rqsx(d->dev, "RQSG", buffer);
	if (!gsb_rqsg)
		return AE_OK;

	rqsg.tc  = gsb_rqsg->tc;
	rqsg.cid = gsb_rqsg->cid;
	rqsg.iid = gsb_rqsg->iid;
	rqsg.cdl = get_unaligned(&gsb_rqsg->cdl);
	rqsg.pld = &gsb_rqsg->pld[0];

	status = san_call_rqsg_handler(&rqsg);
	if (!status) {
		gsb_response_success(buffer, NULL, 0);
	} else {
		dev_err(d->dev, "rqsg: failed with error %d\n", status);
		gsb_response_error(buffer, status);
	}

	return AE_OK;
}


static acpi_status
san_opreg_handler(u32 function, acpi_physical_address command,
		  u32 bits, u64 *value64,
		  void *opreg_context, void *region_context)
{
	struct san_data *d = to_san_data(opreg_context, context);
	struct gsb_buffer *buffer = (struct gsb_buffer *)value64;
	int accessor_type = (0xFFFF0000 & function) >> 16;

	if (command != 0) {
		dev_warn(d->dev, "unsupported command: 0x%02llx\n", command);
		return AE_OK;
	}

	if (accessor_type != ACPI_GSB_ACCESS_ATTRIB_RAW_PROCESS) {
		dev_err(d->dev, "invalid access type: 0x%02x\n", accessor_type);
		return AE_OK;
	}

	// buffer must have at least contain the command-value
	if (buffer->len == 0) {
		dev_err(d->dev, "request-package too small\n");
		return AE_OK;
	}

	switch (buffer->data.in.cv) {
	case 0x01:  return san_rqst(d, buffer);
	case 0x02:  return san_etwl(d, buffer);
	case 0x03:  return san_rqsg(d, buffer);
	}

	dev_warn(d->dev, "unsupported SAN0 request (cv: 0x%02x)\n", buffer->data.in.cv);
	return AE_OK;
}

static int san_events_register(struct platform_device *pdev)
{
	struct san_data *d = platform_get_drvdata(pdev);
	int status;

	d->nf_bat.base.priority = 1;
	d->nf_bat.base.fn = san_evt_power_nb;
	d->nf_bat.event.reg = SSAM_EVENT_REGISTRY_SAM;
	d->nf_bat.event.id.target_category = SSAM_SSH_TC_BAT;
	d->nf_bat.event.id.instance = 0;
	d->nf_bat.event.flags = SSAM_EVENT_SEQUENCED;

	d->nf_tmp.base.priority = 1;
	d->nf_tmp.base.fn = san_evt_thermal_nb;
	d->nf_tmp.event.reg = SSAM_EVENT_REGISTRY_SAM;
	d->nf_tmp.event.id.target_category = SSAM_SSH_TC_TMP;
	d->nf_tmp.event.id.instance = 0;
	d->nf_tmp.event.flags = SSAM_EVENT_SEQUENCED;

	status = ssam_notifier_register(d->ctrl, &d->nf_bat);
	if (status)
		return status;

	status = ssam_notifier_register(d->ctrl, &d->nf_tmp);
	if (status)
		ssam_notifier_unregister(d->ctrl, &d->nf_bat);

	return status;
}

static void san_events_unregister(struct platform_device *pdev)
{
	struct san_data *d = platform_get_drvdata(pdev);

	ssam_notifier_unregister(d->ctrl, &d->nf_bat);
	ssam_notifier_unregister(d->ctrl, &d->nf_tmp);
}


static int san_consumers_link(struct platform_device *pdev,
			      const struct san_acpi_consumer *cons,
			      struct san_consumers *out)
{
	const struct san_acpi_consumer *con;
	struct san_consumer_link *links, *link;
	struct acpi_device *adev;
	acpi_handle handle;
	u32 max_links = 0;
	int status;

	if (!cons)
		return 0;

	// count links
	for (con = cons; con->path; ++con)
		max_links += 1;

	// allocate
	links = kcalloc(max_links, sizeof(struct san_consumer_link), GFP_KERNEL);
	link = &links[0];

	if (!links)
		return -ENOMEM;

	// create links
	for (con = cons; con->path; ++con) {
		status = acpi_get_handle(NULL, con->path, &handle);
		if (status) {
			if (con->required || status != AE_NOT_FOUND) {
				status = -ENXIO;
				goto cleanup;
			} else {
				continue;
			}
		}

		status = acpi_bus_get_device(handle, &adev);
		if (status)
			goto cleanup;

		link->link = device_link_add(&adev->dev, &pdev->dev, con->flags);
		if (!(link->link)) {
			status = -EFAULT;
			goto cleanup;
		}
		link->properties = con;

		link += 1;
	}

	out->num = link - links;
	out->links = links;

	return 0;

cleanup:
	for (link = link - 1; link >= links; --link) {
		if (link->properties->flags & DL_FLAG_STATELESS)
			device_link_del(link->link);
	}

	return status;
}

static void san_consumers_unlink(struct san_consumers *consumers)
{
	u32 i;

	if (!consumers)
		return;

	for (i = 0; i < consumers->num; ++i) {
		if (consumers->links[i].properties->flags & DL_FLAG_STATELESS)
			device_link_del(consumers->links[i].link);
	}

	kfree(consumers->links);

	consumers->num = 0;
	consumers->links = NULL;
}

static int surface_sam_san_probe(struct platform_device *pdev)
{
	const struct san_acpi_consumer *cons;
	acpi_handle san = ACPI_HANDLE(&pdev->dev);	// _SAN device node
	struct ssam_controller *ctrl;
	struct san_data *data;
	int status;

	status = ssam_client_bind(&pdev->dev, &ctrl);
	if (status)
		return status == -ENXIO ? -EPROBE_DEFER : status;

	data = kzalloc(sizeof(struct san_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->dev = &pdev->dev;
	data->ctrl = ctrl;

	cons = acpi_device_get_match_data(&pdev->dev);
	status = san_consumers_link(pdev, cons, &data->consumers);
	if (status)
		goto err_consumers;

	platform_set_drvdata(pdev, data);

	status = acpi_install_address_space_handler(san,
			ACPI_ADR_SPACE_GSBUS,
			&san_opreg_handler,
			NULL, &data->context);

	if (ACPI_FAILURE(status)) {
		status = -ENODEV;
		goto err_install_handler;
	}

	status = san_events_register(pdev);
	if (status)
		goto err_enable_events;

	mutex_lock(&rqsg_if.lock);
	if (!rqsg_if.san_dev)
		rqsg_if.san_dev = &pdev->dev;
	else
		status = -EBUSY;
	mutex_unlock(&rqsg_if.lock);

	if (status)
		goto err_install_dev;

	acpi_walk_dep_device_list(san);
	return 0;

err_install_dev:
	san_events_unregister(pdev);
err_enable_events:
	acpi_remove_address_space_handler(san, ACPI_ADR_SPACE_GSBUS, &san_opreg_handler);
err_install_handler:
	platform_set_drvdata(san, NULL);
	san_consumers_unlink(&data->consumers);
err_consumers:
	kfree(data);
	return status;
}

static int surface_sam_san_remove(struct platform_device *pdev)
{
	struct san_data *data = platform_get_drvdata(pdev);
	acpi_handle san = ACPI_HANDLE(&pdev->dev);	// _SAN device node
	acpi_status status = AE_OK;

	mutex_lock(&rqsg_if.lock);
	rqsg_if.san_dev = NULL;
	mutex_unlock(&rqsg_if.lock);

	acpi_remove_address_space_handler(san, ACPI_ADR_SPACE_GSBUS, &san_opreg_handler);
	san_events_unregister(pdev);

	/*
	 * We have unregistered our event sources. Now we need to ensure that
	 * all delayed works they may have spawned are run to completion.
	 */
	flush_scheduled_work();

	san_consumers_unlink(&data->consumers);
	kfree(data);

	platform_set_drvdata(pdev, NULL);
	return status;
}


static const struct san_acpi_consumer san_mshw0091_consumers[] = {
	{ "\\_SB.SRTC", true,  DL_FLAG_PM_RUNTIME | DL_FLAG_STATELESS },
	{ "\\ADP1",     true,  DL_FLAG_PM_RUNTIME | DL_FLAG_STATELESS },
	{ "\\_SB.BAT1", true,  DL_FLAG_PM_RUNTIME | DL_FLAG_STATELESS },
	{ "\\_SB.BAT2", false, DL_FLAG_PM_RUNTIME | DL_FLAG_STATELESS },
	{ },
};

static const struct acpi_device_id surface_sam_san_match[] = {
	{ "MSHW0091", (unsigned long) san_mshw0091_consumers },
	{ },
};
MODULE_DEVICE_TABLE(acpi, surface_sam_san_match);

static struct platform_driver surface_sam_san = {
	.probe = surface_sam_san_probe,
	.remove = surface_sam_san_remove,
	.driver = {
		.name = "surface_sam_san",
		.acpi_match_table = surface_sam_san_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(surface_sam_san);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Surface ACPI Notify Driver for 5th Generation Surface Devices");
MODULE_LICENSE("GPL");
