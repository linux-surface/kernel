// SPDX-License-Identifier: GPL-2.0
/*
 * Support for OmniVision OV5693 1080p HD camera sensor.
 *
 * Copyright (c) 2013 Intel Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *
 */

#include <linux/acpi.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/regulator/consumer.h>
#include <linux/slab.h>
#include <media/v4l2-device.h>
#include <media/v4l2-fwnode.h>

#include "ov5693.h"
#include "ad5823.h"

/* Exposure/gain */

#define OV5693_EXPOSURE_CTRL_HH_REG		0x3500
#define OV5693_EXPOSURE_CTRL_HH(v)		(((v) & GENMASK(14, 12)) >> 12)
#define OV5693_EXPOSURE_CTRL_H_REG		0x3501
#define OV5693_EXPOSURE_CTRL_H(v)		(((v) & GENMASK(11, 4)) >> 4)
#define OV5693_EXPOSURE_CTRL_L_REG		0x3502
#define OV5693_EXPOSURE_CTRL_L(v)		(((v) & GENMASK(3, 0)) << 4)
#define OV5693_EXPOSURE_GAIN_MANUAL_REG		0x3509

#define OV5693_GAIN_CTRL_H_REG			0x3504
#define OV5693_GAIN_CTRL_H(v)			((v >> 4) & GENMASK(2, 0))
#define OV5693_GAIN_CTRL_L_REG			0x3505
#define OV5693_GAIN_CTRL_L(v)			((v << 4) & GENMASK(7, 4))

#define OV5693_FORMAT1_REG			0x3820
#define OV5693_FORMAT1_FLIP_VERT_ISP_EN		BIT(2)
#define OV5693_FORMAT1_FLIP_VERT_SENSOR_EN	BIT(1)
#define OV5693_FORMAT2_REG			0x3821
#define OV5693_FORMAT2_HSYNC_EN			BIT(6)
#define OV5693_FORMAT2_FST_VBIN_EN		BIT(5)
#define OV5693_FORMAT2_FST_HBIN_EN		BIT(4)
#define OV5693_FORMAT2_ISP_HORZ_VAR2_EN		BIT(3)
#define OV5693_FORMAT2_FLIP_HORZ_ISP_EN		BIT(2)
#define OV5693_FORMAT2_FLIP_HORZ_SENSOR_EN	BIT(1)
#define OV5693_FORMAT2_SYNC_HBIN_EN		BIT(0)

/* ISP */

#define OV5693_ISP_CTRL0_REG			0x5000
#define OV5693_ISP_CTRL0_LENC_EN		BIT(7)
#define OV5693_ISP_CTRL0_WHITE_BALANCE_EN	BIT(4)
#define OV5693_ISP_CTRL0_DPC_BLACK_EN		BIT(2)
#define OV5693_ISP_CTRL0_DPC_WHITE_EN		BIT(1)
#define OV5693_ISP_CTRL1_REG			0x5001
#define OV5693_ISP_CTRL1_BLC_EN			BIT(0)

/* native and active pixel array size. */
#define OV5693_NATIVE_WIDTH		2688U
#define OV5693_NATIVE_HEIGHT		1984U
#define OV5693_PIXEL_ARRAY_LEFT		48U
#define OV5693_PIXEL_ARRAY_TOP		20U
#define OV5693_PIXEL_ARRAY_WIDTH	2592U
#define OV5693_PIXEL_ARRAY_HEIGHT	1944U

/* i2c read/write stuff */
static int ov5693_read_reg(struct i2c_client *client,
			   u16 data_length, u16 reg, u16 *val)
{
	int err;
	struct i2c_msg msg[2];
	unsigned char data[6];

	if (!client->adapter) {
		dev_err(&client->dev, "%s error, no client->adapter\n",
			__func__);
		return -ENODEV;
	}

	if (data_length != OV5693_8BIT && data_length != OV5693_16BIT
	    && data_length != OV5693_32BIT) {
		dev_err(&client->dev, "%s error, invalid data length\n",
			__func__);
		return -EINVAL;
	}

	memset(msg, 0, sizeof(msg));

	msg[0].addr = client->addr;
	msg[0].flags = 0;
	msg[0].len = I2C_MSG_LENGTH;
	msg[0].buf = data;

	/* high byte goes out first */
	data[0] = (u8)(reg >> 8);
	data[1] = (u8)(reg & 0xff);

	msg[1].addr = client->addr;
	msg[1].len = data_length;
	msg[1].flags = I2C_M_RD;
	msg[1].buf = data;

	err = i2c_transfer(client->adapter, msg, 2);
	if (err != 2) {
		if (err >= 0)
			err = -EIO;
		dev_err(&client->dev,
			"read from offset 0x%x error %d", reg, err);
		return err;
	}

	*val = 0;
	/* high byte comes first */
	if (data_length == OV5693_8BIT)
		*val = (u8)data[0];
	else if (data_length == OV5693_16BIT)
		*val = be16_to_cpu(*(__be16 *)&data[0]);
	else
		*val = be32_to_cpu(*(__be32 *)&data[0]);

	return 0;
}

static int ov5693_i2c_write(struct i2c_client *client, u16 len, u8 *data)
{
	struct i2c_msg msg;
	const int num_msg = 1;
	int ret;

	msg.addr = client->addr;
	msg.flags = 0;
	msg.len = len;
	msg.buf = data;
	ret = i2c_transfer(client->adapter, &msg, 1);

	return ret == num_msg ? 0 : -EIO;
}

static int ov5693_write_reg(struct i2c_client *client, u16 data_length,
			    u16 reg, u16 val)
{
	int ret;
	unsigned char data[4] = {0};
	__be16 *wreg = (void *)data;
	const u16 len = data_length + sizeof(u16); /* 16-bit address + data */

	if (data_length != OV5693_8BIT && data_length != OV5693_16BIT) {
		dev_err(&client->dev,
			"%s error, invalid data_length\n", __func__);
		return -EINVAL;
	}

	/* high byte goes out first */
	*wreg = cpu_to_be16(reg);

	if (data_length == OV5693_8BIT) {
		data[2] = (u8)(val);
	} else {
		/* OV5693_16BIT */
		__be16 *wdata = (void *)&data[2];

		*wdata = cpu_to_be16(val);
	}

	ret = ov5693_i2c_write(client, len, data);
	if (ret)
		dev_err(&client->dev,
			"write error: wrote 0x%x to offset 0x%x error %d",
			val, reg, ret);

	return ret;
}

/*
 * ov5693_write_reg_array - Initializes a list of OV5693 registers
 * @client: i2c driver client structure
 * @reglist: list of registers to be written
 *
 * This function initializes a list of registers. When consecutive addresses
 * are found in a row on the list, this function creates a buffer and sends
 * consecutive data in a single i2c_transfer().
 *
 * __ov5693_flush_reg_array, __ov5693_buf_reg_array() and
 * __ov5693_write_reg_is_consecutive() are internal functions to
 * ov5693_write_reg_array_fast() and should be not used anywhere else.
 *
 */

static int __ov5693_flush_reg_array(struct i2c_client *client,
				    struct ov5693_write_ctrl *ctrl)
{
	u16 size;
	__be16 *reg = (void *)&ctrl->buffer.addr;

	if (ctrl->index == 0)
		return 0;

	size = sizeof(u16) + ctrl->index; /* 16-bit address + data */

	*reg = cpu_to_be16(ctrl->buffer.addr);
	ctrl->index = 0;

	return ov5693_i2c_write(client, size, (u8 *)reg);
}

static int __ov5693_buf_reg_array(struct i2c_client *client,
				  struct ov5693_write_ctrl *ctrl,
				  const struct ov5693_reg *next)
{
	int size;
	__be16 *data16;

	switch (next->type) {
	case OV5693_8BIT:
		size = 1;
		ctrl->buffer.data[ctrl->index] = (u8)next->val;
		break;
	case OV5693_16BIT:
		size = 2;

		data16 = (void *)&ctrl->buffer.data[ctrl->index];
		*data16 = cpu_to_be16((u16)next->val);
		break;
	default:
		return -EINVAL;
	}

	/* When first item is added, we need to store its starting address */
	if (ctrl->index == 0)
		ctrl->buffer.addr = next->reg;

	ctrl->index += size;

	/*
	 * Buffer cannot guarantee free space for u32? Better flush it to avoid
	 * possible lack of memory for next item.
	 */
	if (ctrl->index + sizeof(u16) >= OV5693_MAX_WRITE_BUF_SIZE)
		return __ov5693_flush_reg_array(client, ctrl);

	return 0;
}

static int __ov5693_write_reg_is_consecutive(struct i2c_client *client,
	struct ov5693_write_ctrl *ctrl,
	const struct ov5693_reg *next)
{
	if (ctrl->index == 0)
		return 1;

	return ctrl->buffer.addr + ctrl->index == next->reg;
}

static int ov5693_write_reg_array(struct i2c_client *client,
				  const struct ov5693_reg *reglist)
{
	const struct ov5693_reg *next = reglist;
	struct ov5693_write_ctrl ctrl;
	int err;

	ctrl.index = 0;
	for (; next->type != OV5693_TOK_TERM; next++) {
		switch (next->type & OV5693_TOK_MASK) {
		case OV5693_TOK_DELAY:
			err = __ov5693_flush_reg_array(client, &ctrl);
			if (err)
				return err;
			msleep(next->val);
			break;
		default:
			/*
			 * If next address is not consecutive, data needs to be
			 * flushed before proceed.
			 */
			if (!__ov5693_write_reg_is_consecutive(client, &ctrl,
							       next)) {
				err = __ov5693_flush_reg_array(client, &ctrl);
				if (err)
					return err;
			}
			err = __ov5693_buf_reg_array(client, &ctrl, next);
			if (err) {
				dev_err(&client->dev,
					"%s: write error, aborted\n",
					__func__);
				return err;
			}
			break;
		}
	}

	return __ov5693_flush_reg_array(client, &ctrl);
}

static int ov5693_read_otp_reg_array(struct i2c_client *client, u16 size,
				     u16 addr, u8 *buf)
{
	u16 index;
	int ret;
	u16 *pVal = NULL;

	for (index = 0; index <= size; index++) {
		pVal = (u16 *)(buf + index);
		ret =
		    ov5693_read_reg(client, OV5693_8BIT, addr + index,
				    pVal);
		if (ret)
			return ret;
	}

	return 0;
}

static int __ov5693_otp_read(struct v4l2_subdev *sd, u8 *buf)
{
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	struct ov5693_device *ov5693 = to_ov5693_sensor(sd);
	int ret;
	int i;
	u8 *b = buf;

	ov5693->otp_size = 0;
	for (i = 1; i < OV5693_OTP_BANK_MAX; i++) {
		/*set bank NO and OTP read mode. */
		ret = ov5693_write_reg(client, OV5693_8BIT, OV5693_OTP_BANK_REG,
				       (i | 0xc0));	//[7:6] 2'b11 [5:0] bank no
		if (ret) {
			dev_err(&client->dev, "failed to prepare OTP page\n");
			return ret;
		}
		//dev_dbg(&client->dev, "write 0x%x->0x%x\n",OV5693_OTP_BANK_REG,(i|0xc0));

		/*enable read */
		ret = ov5693_write_reg(client, OV5693_8BIT, OV5693_OTP_READ_REG,
				       OV5693_OTP_MODE_READ);	// enable :1
		if (ret) {
			dev_err(&client->dev,
				"failed to set OTP reading mode page");
			return ret;
		}
		//dev_dbg(&client->dev, "write 0x%x->0x%x\n",
		//	OV5693_OTP_READ_REG,OV5693_OTP_MODE_READ);

		/* Reading the OTP data array */
		ret = ov5693_read_otp_reg_array(client, OV5693_OTP_BANK_SIZE,
						OV5693_OTP_START_ADDR,
						b);
		if (ret) {
			dev_err(&client->dev, "failed to read OTP data\n");
			return ret;
		}

		//dev_dbg(&client->dev,
		//	"BANK[%2d] %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		//	i, *b, *(b+1), *(b+2), *(b+3), *(b+4), *(b+5), *(b+6), *(b+7),
		//	*(b+8), *(b+9), *(b+10), *(b+11), *(b+12), *(b+13), *(b+14), *(b+15));

		//Intel OTP map, try to read 320byts first.
		if (i == 21) {
			if ((*b) == 0) {
				ov5693->otp_size = 320;
				break;
			}
			/* (*b) != 0 */
			b = buf;
			continue;
		} else if (i ==
			   24) {		//if the first 320bytes data doesn't not exist, try to read the next 32bytes data.
			if ((*b) == 0) {
				ov5693->otp_size = 32;
				break;
			}
			/* (*b) != 0 */
			b = buf;
			continue;
		} else if (i ==
			   27) {		//if the prvious 32bytes data doesn't exist, try to read the next 32bytes data again.
			if ((*b) == 0) {
				ov5693->otp_size = 32;
				break;
			}
			/* (*b) != 0 */
			ov5693->otp_size = 0;	// no OTP data.
			break;
		}

		b = b + OV5693_OTP_BANK_SIZE;
	}
	return 0;
}

/*
 * Read otp data and store it into a kmalloced buffer.
 * The caller must kfree the buffer when no more needed.
 * @size: set to the size of the returned otp data.
 */
static void *ov5693_otp_read(struct v4l2_subdev *sd)
{
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	u8 *buf;
	int ret;

	buf = devm_kzalloc(&client->dev, (OV5693_OTP_DATA_SIZE + 16), GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	//otp valid after mipi on and sw stream on
	ret = ov5693_write_reg(client, OV5693_8BIT, OV5693_FRAME_OFF_NUM, 0x00);

	ret = ov5693_write_reg(client, OV5693_8BIT,
			       OV5693_SW_STREAM, OV5693_START_STREAMING);

	ret = __ov5693_otp_read(sd, buf);

	//mipi off and sw stream off after otp read
	ret = ov5693_write_reg(client, OV5693_8BIT, OV5693_FRAME_OFF_NUM, 0x0f);

	ret = ov5693_write_reg(client, OV5693_8BIT,
			       OV5693_SW_STREAM, OV5693_STOP_STREAMING);

	/* Driver has failed to find valid data */
	if (ret) {
		dev_err(&client->dev, "sensor found no valid OTP data\n");
		return ERR_PTR(ret);
	}

	return buf;
}

static int ov5693_update_bits(struct ov5693_device *ov5693, u16 address,
			      u16 mask, u16 bits)
{
	u16 value = 0;
	int ret;

	ret = ov5693_read_reg(ov5693->client, OV5693_8BIT, address, &value);
	if (ret)
		return ret;

	value &= ~mask;
	value |= bits;

	ret = ov5693_write_reg(ov5693->client, OV5693_8BIT, address, value);
	if (ret)
		return ret;

	return 0;
}

/* Flip */

static int ov5693_flip_vert_configure(struct ov5693_device *ov5693, bool enable)
{
	u8 bits = OV5693_FORMAT1_FLIP_VERT_ISP_EN |
		  OV5693_FORMAT1_FLIP_VERT_SENSOR_EN;
	int ret;

	ret = ov5693_update_bits(ov5693, OV5693_FORMAT1_REG, bits,
				 enable ? bits : 0);
	if (ret)
		return ret;

	return 0;
}

static int ov5693_flip_horz_configure(struct ov5693_device *ov5693, bool enable)
{
	u8 bits = OV5693_FORMAT2_FLIP_HORZ_ISP_EN |
		  OV5693_FORMAT2_FLIP_HORZ_SENSOR_EN;
	int ret;

	ret = ov5693_update_bits(ov5693, OV5693_FORMAT2_REG, bits,
				 enable ? bits : 0);
	if (ret)
		return ret;

	return 0;
}

/*
 * This returns the exposure time being used. This should only be used
 * for filling in EXIF data, not for actual image processing.
 */
static int ov5693_q_exposure(struct v4l2_subdev *sd, s32 *value)
{
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	u16 reg_v, reg_v2;
	int ret;

	/* get exposure */
	ret = ov5693_read_reg(client, OV5693_8BIT,
			      OV5693_EXPOSURE_L,
			      &reg_v);
	if (ret)
		goto err;

	ret = ov5693_read_reg(client, OV5693_8BIT,
			      OV5693_EXPOSURE_M,
			      &reg_v2);
	if (ret)
		goto err;

	reg_v += reg_v2 << 8;
	ret = ov5693_read_reg(client, OV5693_8BIT,
			      OV5693_EXPOSURE_H,
			      &reg_v2);
	if (ret)
		goto err;

	*value = reg_v + (((u32)reg_v2 << 16));
err:
	return ret;
}

/* Exposure */

static int ov5693_get_exposure(struct ov5693_device *ov5693)
{
	u32 exposure = 0;
	u16 tmp;
	int ret = 0;

	/* get exposure */
	ret = ov5693_read_reg(ov5693->client, OV5693_8BIT,
			      OV5693_EXPOSURE_L,
			      &tmp);
	if (ret)
		return ret;

	exposure |= ((tmp >> 4) & 0b1111);

	ret = ov5693_read_reg(ov5693->client, OV5693_8BIT,
			      OV5693_EXPOSURE_M,
			      &tmp);
	if (ret)
		return ret;

	exposure |= (tmp << 4);
	ret = ov5693_read_reg(ov5693->client, OV5693_8BIT,
			      OV5693_EXPOSURE_H,
			      &tmp);
	if (ret)
		return ret;

	exposure |= (tmp << 12);

	printk("exposure set to: %u\n", exposure);
	return ret;
}

static int ov5693_exposure_configure(struct ov5693_device *ov5693, u32 exposure)
{
	int ret;

	/*
	 * The control for exposure seems to be in units of lines, but the chip
	 * datasheet specifies exposure is in units of 1/16th of a line.
	 */
	exposure = exposure * 16;

	ov5693_get_exposure(ov5693);
	ret = ov5693_write_reg(ov5693->client, OV5693_8BIT,
			OV5693_EXPOSURE_CTRL_HH_REG, OV5693_EXPOSURE_CTRL_HH(exposure));
	if (ret)
		return ret;

	ret = ov5693_write_reg(ov5693->client, OV5693_8BIT,
			OV5693_EXPOSURE_CTRL_H_REG, OV5693_EXPOSURE_CTRL_H(exposure));
	if (ret)
		return ret;

	ret = ov5693_write_reg(ov5693->client, OV5693_8BIT,
			OV5693_EXPOSURE_CTRL_L_REG, OV5693_EXPOSURE_CTRL_L(exposure));
	if (ret)
		return ret;
	ov5693_get_exposure(ov5693);

	return 0;
}

/* Gain */

static int ov5693_get_gain(struct ov5693_device *ov5693, u32 *gain)
{
	u16 gain_l, gain_h;
	int ret = 0;

	ret = ov5693_read_reg(ov5693->client, OV5693_8BIT,
			      OV5693_GAIN_CTRL_L_REG,
			      &gain_l);
	if (ret)
		return ret;

	ret = ov5693_read_reg(ov5693->client, OV5693_8BIT,
			      OV5693_GAIN_CTRL_H_REG,
			      &gain_h);
	if (ret)
		return ret;

	*gain = (u32)(((gain_h >> 8) & 0x03) |
		(gain_l & 0xff));

	return ret;
}
static int ov5693_gain_configure(struct ov5693_device *ov5693, u32 gain)
{
	int ret;

	/* A 1.0 gain is 0x400 */
	gain = (gain * 1024)/1000;

	ret = ov5693_write_reg(ov5693->client, OV5693_16BIT,
			OV5693_MWB_RED_GAIN_H, gain);
	if (ret) {
		dev_err(&ov5693->client->dev, "%s: write %x error, aborted\n",
			__func__, OV5693_MWB_RED_GAIN_H);
		return ret;
	}

	ret = ov5693_write_reg(ov5693->client, OV5693_16BIT,
			OV5693_MWB_GREEN_GAIN_H, gain);
	if (ret) {
		dev_err(&ov5693->client->dev, "%s: write %x error, aborted\n",
			__func__, OV5693_MWB_RED_GAIN_H);
		return ret;
	}

	ret = ov5693_write_reg(ov5693->client, OV5693_16BIT,
			OV5693_MWB_BLUE_GAIN_H, gain);
	if (ret) {
		dev_err(&ov5693->client->dev, "%s: write %x error, aborted\n",
			__func__, OV5693_MWB_RED_GAIN_H);
		return ret;
	}

	return 0;
}

static int ov5693_analog_gain_configure(struct ov5693_device *ov5693, u32 gain)
{
	int ret;

	/*
	 * As with exposure, the lowest 4 bits are fractional bits. Setting
	 * those is not supported, so we have a tiny bit of bit shifting to
	 * do.
	 */
	ret = ov5693_write_reg(ov5693->client, OV5693_8BIT,
				OV5693_AGC_L, OV5693_GAIN_CTRL_L(gain));
	if (ret) {
		dev_err(&ov5693->client->dev, "%s: write %x error, aborted\n",
			__func__, OV5693_AGC_L);
		return ret;
	}

	ret = ov5693_write_reg(ov5693->client, OV5693_8BIT,
				OV5693_AGC_H, OV5693_GAIN_CTRL_H(gain));
	if (ret) {
		dev_err(&ov5693->client->dev, "%s: write %x error, aborted\n",
			__func__, OV5693_AGC_H);
		return ret;
	}

	return 0;
}

static int ov5693_s_ctrl(struct v4l2_ctrl *ctrl)
{
	struct ov5693_device *ov5693 =
	    container_of(ctrl->handler, struct ov5693_device, ctrl_handler);
	struct i2c_client *client = v4l2_get_subdevdata(&ov5693->sd);
	int ret = 0;

	/* If VBLANK is altered we need to update exposure to compensate */
	if (ctrl->id == V4L2_CID_VBLANK) {
		int exposure_max;
		exposure_max = ov5693->mode->lines_per_frame - 8;
		__v4l2_ctrl_modify_range(ov5693->ctrls.exposure, ov5693->ctrls.exposure->minimum,
					 exposure_max, ov5693->ctrls.exposure->step,
					 ov5693->ctrls.exposure->val < exposure_max ?
					 ov5693->ctrls.exposure->val : exposure_max);
	}

	/* Only apply changes to the controls if the device is powered up */
	if (!pm_runtime_get_if_in_use(&ov5693->client->dev))
		return 0;

	switch (ctrl->id) {
	case V4L2_CID_EXPOSURE:
		dev_dbg(&client->dev, "%s: CID_EXPOSURE:%d.\n",
			__func__, ctrl->val);
		ret = ov5693_exposure_configure(ov5693, ctrl->val);
		break;
	case V4L2_CID_ANALOGUE_GAIN:
		dev_dbg(&client->dev, "%s: CID_ANALOGUE_GAIN:%d.\n",
			__func__, ctrl->val);
		ret = ov5693_analog_gain_configure(ov5693, ctrl->val);
		break;
	case V4L2_CID_DIGITAL_GAIN:
		dev_dbg(&client->dev, "%s: CID_DIGITAL_GAIN:%d.\n",
			__func__, ctrl->val);
		ret = ov5693_gain_configure(ov5693, ctrl->val);
		break;
	case V4L2_CID_HFLIP:
		ret = ov5693_flip_horz_configure(ov5693, !!ctrl->val);
		break;
	case V4L2_CID_VFLIP:
		ret = ov5693_flip_vert_configure(ov5693, !!ctrl->val);
		break;
	case V4L2_CID_VBLANK:
		ret = ov5693_write_reg(client, OV5693_16BIT, OV5693_TIMING_VTS_H,
				       ov5693->mode->height + ctrl->val);
		break;
	default:
		ret = -EINVAL;
	}

	pm_runtime_put(&ov5693->client->dev);

	return ret;
}

static int ov5693_g_volatile_ctrl(struct v4l2_ctrl *ctrl)
{
	struct ov5693_device *ov5693 =
	    container_of(ctrl->handler, struct ov5693_device, ctrl_handler);
	int ret = 0;

	switch (ctrl->id) {
	case V4L2_CID_EXPOSURE_ABSOLUTE:
		ret = ov5693_q_exposure(&ov5693->sd, &ctrl->val);
		break;
	case V4L2_CID_AUTOGAIN:
		ret = ov5693_get_gain(ov5693, &ctrl->val);
		break;
	case V4L2_CID_FOCUS_ABSOLUTE:
		/* NOTE: there was atomisp-specific function ov5693_q_focus_abs() */
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

static const struct v4l2_ctrl_ops ov5693_ctrl_ops = {
	.s_ctrl = ov5693_s_ctrl,
	.g_volatile_ctrl = ov5693_g_volatile_ctrl
};

static int ov5693_sw_standby(struct ov5693_device *ov5693, bool standby)
{
	return ov5693_write_reg(ov5693->client, OV5693_8BIT, OV5693_SW_STREAM,
			       standby ? OV5693_STOP_STREAMING : OV5693_START_STREAMING);
}

static int ov5693_sw_reset(struct ov5693_device *ov5693)
{
	return ov5693_write_reg(ov5693->client, OV5693_8BIT, OV5693_SW_RESET,
				0x01);
}

static int ov5693_sensor_init(struct ov5693_device *ov5693)
{
	struct i2c_client *client = ov5693->client;
	int ret = 0;

	ret = ov5693_sw_reset(ov5693);
	if (ret) {
		dev_err(&client->dev, "ov5693 reset err.\n");
		return ret;
	}

	ret = ov5693_write_reg_array(client, ov5693_global_setting);
	if (ret) {
		dev_err(&client->dev, "ov5693 write register err.\n");
		return ret;
	}

	ret = ov5693_write_reg_array(client, ov5693_res[ov5693->fmt_idx].regs);
	if (ret) {
		dev_err(&client->dev, "ov5693 write register err.\n");
		return ret;
	}

	ret = ov5693_sw_standby(ov5693, true);
	if (ret)
		dev_err(&client->dev, "ov5693 stream off error\n");

	return ret;
}

static void ov5693_sensor_powerdown(struct ov5693_device *ov5693)
{
	gpiod_set_value_cansleep(ov5693->reset, 1);
	gpiod_set_value_cansleep(ov5693->powerdown, 1);

	regulator_bulk_disable(OV5693_NUM_SUPPLIES, ov5693->supplies);

	clk_disable_unprepare(ov5693->clk);
	gpiod_set_value_cansleep(ov5693->indicator_led, 0);
}


static int ov5693_sensor_powerup(struct ov5693_device *ov5693)
{
	int ret = 0;

	gpiod_set_value_cansleep(ov5693->reset, 1);
	gpiod_set_value_cansleep(ov5693->powerdown, 1);

	ret = clk_prepare_enable(ov5693->clk);
	if (ret) {
		dev_err(&ov5693->client->dev, "Failed to enable clk\n");
		goto fail_power;
	}

	ret = regulator_bulk_enable(OV5693_NUM_SUPPLIES, ov5693->supplies);
	if (ret) {
		dev_err(&ov5693->client->dev, "Failed to enable regulators\n");
		goto fail_power;
	}

	gpiod_set_value_cansleep(ov5693->reset, 0);
	gpiod_set_value_cansleep(ov5693->powerdown, 0);
	gpiod_set_value_cansleep(ov5693->indicator_led, 1);

	usleep_range(20000, 25000);

	return 0;

fail_power:
	ov5693_sensor_powerdown(ov5693);
	return ret;
}

static int __maybe_unused ov5693_sensor_suspend(struct device *dev)
{
	struct i2c_client *client = i2c_verify_client(dev);
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct ov5693_device *ov5693 = to_ov5693_sensor(sd);
	int ret;

	mutex_lock(&ov5693->lock);

	if (ov5693->streaming) {
		ret = ov5693_sw_standby(ov5693, true);
		if (ret)
			goto out_unlock;
	}

	ov5693_sensor_powerdown(ov5693);

out_unlock:
	mutex_unlock(&ov5693->lock);
	return ret;
}

static int __maybe_unused ov5693_sensor_resume(struct device *dev)
{
	struct i2c_client *client = i2c_verify_client(dev);
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct ov5693_device *ov5693 = to_ov5693_sensor(sd);
	int ret;

	mutex_lock(&ov5693->lock);

	ret = ov5693_sensor_powerup(ov5693);
	if (ret)
		goto out_unlock;

	ret = ov5693_sensor_init(ov5693);
	if (ret) {
		dev_err(&client->dev, "ov5693 sensor init failure\n");
		goto err_power;
	}

	if (ov5693->streaming) {
		ret = ov5693_sw_standby(ov5693, false);
		if (ret)
			goto err_power;
	}

	goto out_unlock;

err_power:
	ov5693_sensor_powerdown(ov5693);
out_unlock:
	mutex_unlock(&ov5693->lock);
	return ret;
}

/*
 * distance - calculate the distance
 * @res: resolution
 * @w: width
 * @h: height
 *
 * Get the gap between res_w/res_h and w/h.
 * distance = (res_w/res_h - w/h) / (w/h) * 8192
 * res->width/height smaller than w/h wouldn't be considered.
 * The gap of ratio larger than 1/8 wouldn't be considered.
 * Returns the value of gap or -1 if fail.
 */
#define LARGEST_ALLOWED_RATIO_MISMATCH 1024
static int distance(struct ov5693_resolution *res, u32 w, u32 h)
{
	int ratio;
	int distance;

	if (w == 0 || h == 0 ||
	    res->width < w || res->height < h)
		return -1;

	ratio = res->width << 13;
	ratio /= w;
	ratio *= h;
	ratio /= res->height;

	distance = abs(ratio - 8192);

	if (distance > LARGEST_ALLOWED_RATIO_MISMATCH)
		return -1;

	return distance;
}

/* Return the nearest higher resolution index
 * Firstly try to find the approximate aspect ratio resolution
 * If we find multiple same AR resolutions, choose the
 * minimal size.
 */
static int nearest_resolution_index(int w, int h)
{
	int i;
	int idx = -1;
	int dist;
	int min_dist = INT_MAX;
	int min_res_w = INT_MAX;
	struct ov5693_resolution *tmp_res = NULL;

	for (i = 0; i < N_RES; i++) {
		tmp_res = &ov5693_res[i];
		dist = distance(tmp_res, w, h);
		if (dist == -1)
			continue;
		if (dist < min_dist) {
			min_dist = dist;
			idx = i;
			min_res_w = ov5693_res[i].width;
			continue;
		}
		if (dist == min_dist && ov5693_res[i].width < min_res_w)
			idx = i;
	}

	return idx;
}

static int get_resolution_index(int w, int h)
{
	int i;

	for (i = 0; i < N_RES; i++) {
		if (w != ov5693_res[i].width)
			continue;
		if (h != ov5693_res[i].height)
			continue;

		return i;
	}

	return -1;
}

static int ov5693_set_fmt(struct v4l2_subdev *sd,
			  struct v4l2_subdev_pad_config *cfg,
			  struct v4l2_subdev_format *format)
{
	struct v4l2_mbus_framefmt *fmt = &format->format;
	struct ov5693_device *ov5693 = to_ov5693_sensor(sd);
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	int ret = 0;
	int idx;

	if (format->pad)
		return -EINVAL;
	if (!fmt)
		return -EINVAL;

	mutex_lock(&ov5693->lock);
	idx = nearest_resolution_index(fmt->width, fmt->height);
	if (idx == -1) {
		/* return the largest resolution */
		fmt->width = ov5693_res[N_RES - 1].width;
		fmt->height = ov5693_res[N_RES - 1].height;
	} else {
		fmt->width = ov5693_res[idx].width;
		fmt->height = ov5693_res[idx].height;
	}

	fmt->code = MEDIA_BUS_FMT_SBGGR10_1X10;
	if (format->which == V4L2_SUBDEV_FORMAT_TRY) {
		cfg->try_fmt = *fmt;
		ret = 0;
		goto mutex_unlock;
	}

	ov5693->fmt_idx = get_resolution_index(fmt->width, fmt->height);
	if (ov5693->fmt_idx == -1) {
		dev_err(&client->dev, "get resolution fail\n");
		ret = -EINVAL;
		goto mutex_unlock;
	}

mutex_unlock:
	mutex_unlock(&ov5693->lock);
	return ret;
}

static const struct v4l2_rect *
__ov5693_get_pad_crop(struct ov5693_device *ov5693, struct v4l2_subdev_pad_config *cfg,
		      unsigned int pad, enum v4l2_subdev_format_whence which)
{
	switch (which) {
	case V4L2_SUBDEV_FORMAT_TRY:
		return v4l2_subdev_get_try_crop(&ov5693->sd, cfg, pad);
	case V4L2_SUBDEV_FORMAT_ACTIVE:
		return &ov5693->mode->crop;
	}

	return NULL;
}
static int ov5693_get_selection(struct v4l2_subdev *sd,
				struct v4l2_subdev_pad_config *cfg,
				struct v4l2_subdev_selection *sel)
{
	switch (sel->target) {
	case V4L2_SEL_TGT_CROP: {
		struct ov5693_device *ov5693 = to_ov5693_sensor(sd);

		mutex_lock(&ov5693->lock);
		sel->r = *__ov5693_get_pad_crop(ov5693, cfg, sel->pad,
						sel->which);
		mutex_unlock(&ov5693->lock);

		return 0;
	}

	case V4L2_SEL_TGT_NATIVE_SIZE:
		sel->r.top = 0;
		sel->r.left = 0;
		sel->r.width = OV5693_NATIVE_WIDTH;
		sel->r.height = OV5693_NATIVE_HEIGHT;

		return 0;

	case V4L2_SEL_TGT_CROP_DEFAULT:
		sel->r.top = OV5693_PIXEL_ARRAY_TOP;
		sel->r.left = OV5693_PIXEL_ARRAY_LEFT;
		sel->r.width = OV5693_PIXEL_ARRAY_WIDTH;
		sel->r.height = OV5693_PIXEL_ARRAY_HEIGHT;

		return 0;
	}

	return -EINVAL;
}

static int ov5693_get_fmt(struct v4l2_subdev *sd,
			  struct v4l2_subdev_pad_config *cfg,
			  struct v4l2_subdev_format *format)
{
	struct v4l2_mbus_framefmt *fmt = &format->format;
	struct ov5693_device *ov5693 = to_ov5693_sensor(sd);

	if (format->pad)
		return -EINVAL;

	if (!fmt)
		return -EINVAL;

	fmt->width = ov5693_res[ov5693->fmt_idx].width;
	fmt->height = ov5693_res[ov5693->fmt_idx].height;
	fmt->code = MEDIA_BUS_FMT_SBGGR10_1X10;

	return 0;
}

static int ov5693_detect(struct i2c_client *client)
{
	struct i2c_adapter *adapter = client->adapter;
	u16 high, low;
	int ret;
	u16 id;
	u8 revision;

	if (!i2c_check_functionality(adapter, I2C_FUNC_I2C))
		return -ENODEV;

	ret = ov5693_read_reg(client, OV5693_8BIT,
			      OV5693_SC_CMMN_CHIP_ID_H, &high);
	if (ret) {
		dev_err(&client->dev, "sensor_id_high = 0x%x\n", high);
		return -ENODEV;
	}
	ret = ov5693_read_reg(client, OV5693_8BIT,
			      OV5693_SC_CMMN_CHIP_ID_L, &low);
	id = ((((u16)high) << 8) | (u16)low);

	if (id != OV5693_ID) {
		dev_err(&client->dev, "sensor ID error 0x%x\n", id);
		return -ENODEV;
	}

	ret = ov5693_read_reg(client, OV5693_8BIT,
			      OV5693_SC_CMMN_SUB_ID, &high);
	revision = (u8)high & 0x0f;

	dev_info(&client->dev, "sensor_revision = 0x%x\n", revision);
	dev_info(&client->dev, "sensor_address = 0x%02x\n", client->addr);
	dev_info(&client->dev, "detect ov5693 success\n");
	return 0;
}

static int ov5693_s_stream(struct v4l2_subdev *sd, int enable)
{
	struct ov5693_device *ov5693 = to_ov5693_sensor(sd);
	int ret;

	if (enable) {
		ret = pm_runtime_get_sync(&ov5693->client->dev);
		if (ret < 0)
			goto err_power_down;
	}

	ret = __v4l2_ctrl_handler_setup(&ov5693->ctrl_handler);
	if (ret)
		goto err_power_down;

	mutex_lock(&ov5693->lock);
	ret = ov5693_sw_standby(ov5693, !enable);
	mutex_unlock(&ov5693->lock);

	if (ret)
		goto err_power_down;
	ov5693->streaming = !!enable;

	/* power_off() here after streaming for regular PCs. */
	if (!enable)
		pm_runtime_put(&ov5693->client->dev);

	return 0;
err_power_down:
	pm_runtime_put_noidle(&ov5693->client->dev);
	return ret;
}

static int ov5693_s_config(struct v4l2_subdev *sd, int irq)
{
	struct ov5693_device *ov5693 = to_ov5693_sensor(sd);
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	int ret = 0;

	mutex_lock(&ov5693->lock);
	ret = ov5693_sensor_powerup(ov5693);
	if (ret) {
		dev_err(&client->dev, "ov5693 power-up err.\n");
		goto fail_power_on;
	}

	/* config & detect sensor */
	ret = ov5693_detect(client);
	if (ret) {
		dev_err(&client->dev, "ov5693_detect err s_config.\n");
		goto fail_power_on;
	}

	ov5693->otp_data = ov5693_otp_read(sd);

	/* turn off sensor, after probed */
	ov5693_sensor_powerdown(ov5693);

	mutex_unlock(&ov5693->lock);

	return ret;

fail_power_on:
	ov5693_sensor_powerdown(ov5693);
	dev_err(&client->dev, "sensor power-gating failed\n");
	mutex_unlock(&ov5693->lock);
	return ret;
}

static int ov5693_g_frame_interval(struct v4l2_subdev *sd,
				   struct v4l2_subdev_frame_interval *interval)
{
	struct ov5693_device *ov5693 = to_ov5693_sensor(sd);

	interval->interval.numerator = 1;
	interval->interval.denominator = ov5693_res[ov5693->fmt_idx].fps;

	return 0;
}

static int ov5693_enum_mbus_code(struct v4l2_subdev *sd,
				 struct v4l2_subdev_pad_config *cfg,
				 struct v4l2_subdev_mbus_code_enum *code)
{
	if (code->index >= MAX_FMTS)
		return -EINVAL;

	code->code = MEDIA_BUS_FMT_SBGGR10_1X10;
	return 0;
}

static int ov5693_enum_frame_size(struct v4l2_subdev *sd,
				  struct v4l2_subdev_pad_config *cfg,
				  struct v4l2_subdev_frame_size_enum *fse)
{
	int index = fse->index;

	if (index >= N_RES)
		return -EINVAL;

	fse->min_width = ov5693_res[index].width;
	fse->min_height = ov5693_res[index].height;
	fse->max_width = ov5693_res[index].width;
	fse->max_height = ov5693_res[index].height;

	return 0;
}

static const struct v4l2_subdev_video_ops ov5693_video_ops = {
	.s_stream = ov5693_s_stream,
	.g_frame_interval = ov5693_g_frame_interval,
};

static const struct v4l2_subdev_pad_ops ov5693_pad_ops = {
	.enum_mbus_code = ov5693_enum_mbus_code,
	.enum_frame_size = ov5693_enum_frame_size,
	.get_fmt = ov5693_get_fmt,
	.set_fmt = ov5693_set_fmt,
	.get_selection = ov5693_get_selection,
};

static const struct v4l2_subdev_ops ov5693_ops = {
	.video = &ov5693_video_ops,
	.pad = &ov5693_pad_ops,
};

static int ov5693_remove(struct i2c_client *client)
{
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct ov5693_device *ov5693 = to_ov5693_sensor(sd);
	unsigned int i = OV5693_NUM_SUPPLIES;

	dev_info(&client->dev, "%s...\n", __func__);

	gpiod_put(ov5693->reset);
	gpiod_put(ov5693->indicator_led);
	while (i--)
		regulator_put(ov5693->supplies[i].consumer);

	v4l2_async_unregister_subdev(sd);

	media_entity_cleanup(&ov5693->sd.entity);
	v4l2_ctrl_handler_free(&ov5693->ctrl_handler);
	kfree(ov5693);

	return 0;
}

static int ov5693_init_controls(struct ov5693_device *ov5693)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov5693->sd);
	const struct v4l2_ctrl_ops *ops = &ov5693_ctrl_ops;
	struct v4l2_fwnode_device_properties props;
	int ret;
	int hblank;
	int vblank_max, vblank_min, vblank_def;
	int exposure_max;

	ret = v4l2_ctrl_handler_init(&ov5693->ctrl_handler, 8);
	if (ret) {
		ov5693_remove(client);
		return ret;
	}

	/* link freq */
	ov5693->ctrls.link_freq = v4l2_ctrl_new_int_menu(&ov5693->ctrl_handler,
							 NULL, V4L2_CID_LINK_FREQ,
							 0, 0, link_freq_menu_items);
	if (ov5693->ctrls.link_freq)
		ov5693->ctrls.link_freq->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	/* pixel rate */
	ov5693->ctrls.pixel_rate = v4l2_ctrl_new_std(&ov5693->ctrl_handler, NULL,
						     V4L2_CID_PIXEL_RATE, 0,
						     OV5693_PIXEL_RATE, 1,
						     OV5693_PIXEL_RATE);

	if (ov5693->ctrl_handler.error) {
		ov5693_remove(client);
		return ov5693->ctrl_handler.error;
	}

	/* Exposure */
	exposure_max = ov5693->mode->lines_per_frame - 8;
	ov5693->ctrls.exposure = v4l2_ctrl_new_std(&ov5693->ctrl_handler, ops,
						   V4L2_CID_EXPOSURE, 1,
						   exposure_max, 1, 123);

	/* Gain */

	ov5693->ctrls.analogue_gain = v4l2_ctrl_new_std(&ov5693->ctrl_handler,
							ops, V4L2_CID_ANALOGUE_GAIN,
							1, 127, 1, 8);
	ov5693->ctrls.digital_gain = v4l2_ctrl_new_std(&ov5693->ctrl_handler, ops,
						       V4L2_CID_DIGITAL_GAIN, 1,
						       4095, 1, 1024);

	/* Flip */

	ov5693->ctrls.hflip = v4l2_ctrl_new_std(&ov5693->ctrl_handler, ops,
						V4L2_CID_HFLIP, 0, 1, 1, 0);
	ov5693->ctrls.vflip = v4l2_ctrl_new_std(&ov5693->ctrl_handler, ops,
						V4L2_CID_VFLIP, 0, 1, 1, 0);

	hblank = ov5693->mode->pixels_per_line - ov5693->mode->width;
	ov5693->ctrls.hblank = v4l2_ctrl_new_std(&ov5693->ctrl_handler, ops,
						 V4L2_CID_HBLANK, hblank, hblank,
						 1, hblank);
	if (ov5693->ctrls.hblank)
		ov5693->ctrls.hblank->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	vblank_max = OV5693_TIMING_MAX_VTS - ov5693->mode->height;
	vblank_def = ov5693->mode->lines_per_frame - ov5693->mode->height;
	vblank_min = ov5693->mode->lines_per_frame - ov5693->mode->height;
	ov5693->ctrls.vblank = v4l2_ctrl_new_std(&ov5693->ctrl_handler, ops,
						 V4L2_CID_VBLANK, vblank_min,
						 vblank_max, 1, vblank_def);

	/* set properties from fwnode (e.g. rotation, orientation) */
	ret = v4l2_fwnode_device_parse(&client->dev, &props);
	if (ret)
		return ret;

	ret = v4l2_ctrl_new_fwnode_properties(&ov5693->ctrl_handler, ops, &props);
	if (ret)
		return ret;

	/* Use same lock for controls as for everything else. */
	ov5693->ctrl_handler.lock = &ov5693->lock;
	ov5693->sd.ctrl_handler = &ov5693->ctrl_handler;

	return 0;
}

static int ov5693_configure_gpios(struct ov5693_device *ov5693)
{
	int ret;

	ov5693->reset = gpiod_get_optional(&ov5693->client->dev, "reset",
                                        GPIOD_OUT_HIGH);
        if (IS_ERR(ov5693->reset)) {
                dev_err(&ov5693->client->dev, "Couldn't find reset GPIO\n");
                return PTR_ERR(ov5693->reset);
        }

	ov5693->powerdown = gpiod_get_optional(&ov5693->client->dev, "powerdown",
                                        GPIOD_OUT_HIGH);
        if (IS_ERR(ov5693->powerdown)) {
                dev_err(&ov5693->client->dev, "Couldn't find powerdown GPIO\n");
                ret = PTR_ERR(ov5693->powerdown);
		goto err_put_reset;
        }

        ov5693->indicator_led = gpiod_get_optional(&ov5693->client->dev, "indicator-led",
                                        GPIOD_OUT_HIGH);
        if (IS_ERR(ov5693->indicator_led)) {
                dev_err(&ov5693->client->dev, "Couldn't find indicator-led GPIO\n");
                ret = PTR_ERR(ov5693->indicator_led);
		goto err_put_powerdown;
        }

        return 0;
err_put_reset:
	gpiod_put(ov5693->reset);
err_put_powerdown:
	gpiod_put(ov5693->powerdown);

	return ret;
}

static int ov5693_get_regulators(struct ov5693_device *ov5693)
{
	unsigned int i;

	for (i = 0; i < OV5693_NUM_SUPPLIES; i++)
		ov5693->supplies[i].supply = ov5693_supply_names[i];

	return regulator_bulk_get(&ov5693->client->dev,
				       OV5693_NUM_SUPPLIES,
				       ov5693->supplies);
}

static int ov5693_probe(struct i2c_client *client)
{
	struct ov5693_device *ov5693;
	int ret = 0;

	dev_info(&client->dev, "%s() called", __func__);

	ov5693 = devm_kzalloc(&client->dev, sizeof(*ov5693), GFP_KERNEL);
	if (!ov5693)
		return -ENOMEM;

	ov5693->client = client;

	mutex_init(&ov5693->lock);

	v4l2_i2c_subdev_init(&ov5693->sd, client, &ov5693_ops);

	ov5693->clk = devm_clk_get(&client->dev, "xvclk");
	if (IS_ERR(ov5693->clk)) {
		dev_err(&client->dev, "Error getting clock\n");
		return -EINVAL;
	}

	ret = ov5693_configure_gpios(ov5693);
        if (ret)
                goto out_free;

	ret = ov5693_get_regulators(ov5693);
        if (ret)
                goto out_put_reset;

	ret = ov5693_s_config(&ov5693->sd, client->irq);
	if (ret)
		goto out_put_reset;

	ov5693->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	ov5693->pad.flags = MEDIA_PAD_FL_SOURCE;
	ov5693->format.code = MEDIA_BUS_FMT_SBGGR10_1X10;
	ov5693->sd.entity.function = MEDIA_ENT_F_CAM_SENSOR;
	ov5693->mode = &ov5693_res_video[N_RES_VIDEO-1];

	ret = ov5693_init_controls(ov5693);
	if (ret)
		ov5693_remove(client);

	ret = media_entity_pads_init(&ov5693->sd.entity, 1, &ov5693->pad);
	if (ret)
		ov5693_remove(client);

	pm_runtime_enable(&client->dev);
	pm_runtime_set_suspended(&client->dev);

	ret = v4l2_async_register_subdev_sensor_common(&ov5693->sd);
	if (ret) {
		dev_err(&client->dev, "failed to register V4L2 subdev: %d", ret);
		goto media_entity_cleanup;
	}

	return ret;

media_entity_cleanup:
	pm_runtime_disable(&client->dev);
	media_entity_cleanup(&ov5693->sd.entity);
out_put_reset:
        gpiod_put(ov5693->reset);
out_free:
	v4l2_device_unregister_subdev(&ov5693->sd);
	kfree(ov5693);
	return ret;
}

static const struct dev_pm_ops ov5693_pm_ops = {
	SET_RUNTIME_PM_OPS(ov5693_sensor_suspend, ov5693_sensor_resume, NULL)
};

static const struct acpi_device_id ov5693_acpi_match[] = {
	{"INT33BE"},
	{},
};
MODULE_DEVICE_TABLE(acpi, ov5693_acpi_match);

static struct i2c_driver ov5693_driver = {
	.driver = {
		.name = "ov5693",
		.acpi_match_table = ov5693_acpi_match,
		.pm = &ov5693_pm_ops,
	},
	.probe_new = ov5693_probe,
	.remove = ov5693_remove,
};
module_i2c_driver(ov5693_driver);

MODULE_DESCRIPTION("A low-level driver for OmniVision 5693 sensors");
MODULE_LICENSE("GPL");
