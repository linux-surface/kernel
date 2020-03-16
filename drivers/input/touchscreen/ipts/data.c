// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/ktime.h>

#include "context.h"
#include "control.h"
#include "hid.h"
#include "params.h"
#include "payload.h"
#include "protocol/data.h"

static void ipts_data_handle_input(struct ipts_context *ipts, int buffer_id)
{
	struct ipts_buffer_info buffer;
	struct ipts_data *data;

	buffer = ipts->data[buffer_id];
	data = (struct ipts_data *)buffer.address;

	if (ipts_params.debug) {
		dev_info(ipts->dev, "Buffer %d\n", buffer_id);
		print_hex_dump(KERN_INFO, "", DUMP_PREFIX_NONE, 32, 1,
				data->data, data->size, false);
	}

	switch (data->type) {
	case IPTS_DATA_TYPE_PAYLOAD:
		ipts_payload_handle_input(ipts, data);
		break;
	case IPTS_DATA_TYPE_HID_REPORT:
		ipts_hid_handle_input(ipts, data);
		break;
	default:
		// ignore
		break;
	}

	ipts_control_send_feedback(ipts, buffer_id, data->transaction);
}

int ipts_data_loop(void *data)
{
	time64_t timeout;
	u32 doorbell;
	u32 last_doorbell;
	struct ipts_context *ipts;

	timeout = ktime_get_seconds() + 5;
	ipts = (struct ipts_context *)data;
	last_doorbell = 0;
	doorbell = 0;

	dev_info(ipts->dev, "Starting data loop\n");

	while (!kthread_should_stop()) {
		if (ipts->status != IPTS_HOST_STATUS_STARTED) {
			msleep(1000);
			continue;
		}

		// IPTS will increment the doorbell after if filled up one of
		// the data buffers. If the doorbell didn't change, there is
		// no work for us to do. Otherwise, the value of the doorbell
		// will stand for the *next* buffer thats going to be filled.
		doorbell = *(u32 *)ipts->doorbell.address;
		if (doorbell == last_doorbell)
			goto sleep;

		timeout = ktime_get_seconds() + 5;

		while (last_doorbell != doorbell) {
			ipts_data_handle_input(ipts, last_doorbell % 16);
			last_doorbell++;
		}
sleep:
		if (timeout > ktime_get_seconds())
			usleep_range(5000, 30000);
		else
			msleep(200);
	}

	dev_info(ipts->dev, "Stopping data loop\n");
	return 0;
}

int ipts_data_init(struct ipts_context *ipts)
{
	int ret;

	ret = ipts_payload_init(ipts);
	if (ret)
		return ret;

	ret = ipts_hid_init(ipts);
	if (ret)
		return ret;

	return 0;
}

void ipts_data_free(struct ipts_context *ipts)
{
	ipts_payload_free(ipts);
	ipts_hid_free(ipts);
}
