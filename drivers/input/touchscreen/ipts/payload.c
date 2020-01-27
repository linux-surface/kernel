// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/types.h>

#include "context.h"
#include "protocol/data.h"
#include "protocol/payload.h"
#include "stylus.h"

void ipts_payload_handle_input(struct ipts_context *ipts,
		struct ipts_data *data)
{
	u32 i, offset;
	struct ipts_payload *payload;
	struct ipts_payload_frame *frame;

	payload = (struct ipts_payload *)data->data;
	offset = 0;

	for (i = 0; i < payload->num_frames; i++) {
		frame = (struct ipts_payload_frame *)&payload->data[offset];
		offset += sizeof(struct ipts_payload_frame) + frame->size;

		switch (frame->type) {
		case IPTS_PAYLOAD_FRAME_TYPE_STYLUS:
			ipts_stylus_handle_input(ipts, frame);
			break;
		case IPTS_PAYLOAD_FRAME_TYPE_TOUCH:
			// ignored (for the moment)
			break;
		default:
			// ignored
			break;
		}
	}
}

int ipts_payload_init(struct ipts_context *ipts)
{
	int ret;

	ret = ipts_stylus_init(ipts);
	if (ret)
		return ret;

	return 0;
}

void ipts_payload_free(struct ipts_context *ipts)
{
	ipts_stylus_free(ipts);
}
