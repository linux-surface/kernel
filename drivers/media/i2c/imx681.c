// SPDX-License-Identifier: GPL-2.0
/*
 * Sony IMX681 CMOS Image Sensor Driver
 *
 * Based on Surface Pro 11 Intel camera work by Andre Gilerson.
 * Register sequences are based on archived Windows I2C trace evidence.
 *
 * Copyright (C) 2025
 */

#include <linux/acpi.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/regulator/consumer.h>

#include <media/v4l2-cci.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <media/v4l2-fwnode.h>
#include <media/v4l2-mediabus.h>

/* Chip ID register and expected value */
#define IMX681_REG_CHIP_ID		CCI_REG16(0x0016)
#define IMX681_CHIP_ID			0x0681

/* Mode select */
#define IMX681_REG_MODE_SELECT		CCI_REG8(0x0100)
#define IMX681_MODE_STANDBY		0x00
#define IMX681_MODE_STREAMING		0x01

/* Group parameter hold */
#define IMX681_REG_GROUP_HOLD		CCI_REG8(0x0104)

/* Exposure (coarse integration time, 24-bit) */
#define IMX681_REG_EXPOSURE		CCI_REG24(0x0229)
#define IMX681_EXPOSURE_MIN		4
#define IMX681_EXPOSURE_MAX		3173	/* frame_length - 4 */
#define IMX681_EXPOSURE_DEFAULT		1907	/* from Windows trace */

/*
 * Raw analogue-gain register code. Its optical meaning is intentionally not
 * encoded in this driver. SP12 gainprobe evidence establishes the relation;
 * a libcamera CameraSensorHelper owns raw-code-to-physical-gain mapping.
 */
#define IMX681_REG_ANALOG_GAIN		CCI_REG16(0x0204)
#define IMX681_ANALOG_GAIN_MIN		0
#define IMX681_ANALOG_GAIN_MAX		960
#define IMX681_ANALOG_GAIN_DEFAULT	0

/* Image dimensions — native sensor output */
#define IMX681_WIDTH			3844
#define IMX681_HEIGHT			2640
#define IMX681_LINE_LENGTH_PCK		7552	/* 0x1D80 */
#define IMX681_FRAME_LENGTH_LINES	3177	/* 0x0C69 */

/* MIPI lanes */
#define IMX681_NUM_LANES		2

/*
 * Link frequency derived from PLL settings in Windows trace:
 * EXCK=19.2MHz, PLL2_MUL=303, PLL2_PRE_DIV=3
 * OP output = 19.2 * 303 / 3 = 1939.2 MHz (MIPI bit rate)
 * Link freq = 1939.2 / 2 (DDR) = 969.6 MHz
 */
#define IMX681_LINK_FREQ		969600000LL

/* Pixel rate = link_freq * 2 (DDR) * num_lanes / bpp */
#define IMX681_PIXEL_RATE		(IMX681_LINK_FREQ * 2 * IMX681_NUM_LANES / 10)

/* Power-on delay after reset deassert */
#define IMX681_RESET_DELAY_US		1000
#define IMX681_RESET_DELAY_RANGE_US	1000

/* Post-standby-cancel stabilisation delays */
#define IMX681_INIT_DELAY_US		10000

#define IMAGE_PAD			0

static const s64 imx681_link_frequencies[] = {
	IMX681_LINK_FREQ,
};

/*
 * Sensor init register sequence, captured from Windows I2C traces.
 * This configures the sensor for 3844x2640 RAW10 output at a nominal 16.16fps
 * (387.84 MHz / (7552 * 3177)),
 * with 2-lane MIPI CSI-2, 19.2MHz input clock.
 */
static const struct cci_reg_sequence imx681_init_regs[] = {
	/* Software standby */
	{ CCI_REG8(0x0100),  0x00 },
	/* External clock frequency = 19.2 MHz (encoded as MHz * 256) */
	{ CCI_REG16(0x0136), 0x1333 },
	/* Vendor specific configuration */
	{ CCI_REG16(0x002C), 0x0505 },
	/* CSI-2 signaling mode */
	{ CCI_REG8(0x0111),  0x02 },
	/* Image orientation: H-flip to match Windows AIQB (RGGB native → GRBG) */
	{ CCI_REG8(0x0101),  0x01 },
	/* Vendor access unlock sequence */
	{ CCI_REG8(0x30EB),  0x05 },
	{ CCI_REG8(0x30EB),  0x0C },
	/* Vendor specific */
	{ CCI_REG16(0x300A), 0xFFFF },
	{ CCI_REG16(0x3532), 0xFFFF },
	/* LINE_LENGTH_PCK = 7552 */
	{ CCI_REG16(0x0342), 0x1D80 },
	/* Frame length = 3177 */
	{ CCI_REG16(0x033E), 0x0C69 },
	/* Crop window start: X_ADD_STA[7:0]=100, Y_ADD_STA=256 */
	{ CCI_REG24(0x0345), 0x640100 },
	/* Crop window end: X_ADD_END[7:0]=103, Y_ADD_END=2895 */
	{ CCI_REG24(0x0349), 0x670B4F },
	/* Digital crop / vendor config */
	{ CCI_REG24(0x040D), 0x040A50 },
	/* X_OUTPUT_SIZE=3844, Y_OUTPUT_SIZE=2640 */
	{ CCI_REG32(0x034C), 0x0F040A50 },
	/* PLL multiplier = 225 */
	{ CCI_REG8(0x0307),  0xE1 },
	/* PLL2: pre_div=3, multiplier=303 (0x012F) */
	{ CCI_REG24(0x030D), 0x03012F },
	/* Frame duration initial */
	{ CCI_REG16(0x022A), 0x0C61 },
	/* Vendor specific registers */
	{ CCI_REG8(0x7E9B),  0x02 },
	{ CCI_REG8(0x0368),  0x00 },
	{ CCI_REG8(0xD383),  0x01 },
};

/*
 * First exposure settings applied before stream-on.
 * Uses group parameter hold to ensure atomic update.
 */
static const struct cci_reg_sequence imx681_first_exposure[] = {
	{ CCI_REG8(0x0104),  0x01 },		/* Group hold ON */
	{ CCI_REG24(0x033D), 0x000C69 },	/* Frame length = 3177 */
	{ CCI_REG24(0x0229), 0x000773 },	/* Exposure = 1907 lines */
	{ IMX681_REG_ANALOG_GAIN, 0x0000 },	/* Raw analogue-gain code */
	{ CCI_REG16(0x020E), 0x0100 },		/* Digital gain = 1.0x */
	{ CCI_REG8(0x0104),  0x00 },		/* Group hold OFF */
};

static const u32 imx681_mbus_codes[] = {
	MEDIA_BUS_FMT_SGRBG10_1X10,
};

struct imx681 {
	struct device *dev;
	struct regmap *cci;

	struct v4l2_subdev sd;
	struct media_pad pad;

	struct clk *xclk;
	struct gpio_desc *reset_gpio;
	struct regulator *avdd;

	/* V4L2 Controls */
	struct v4l2_ctrl_handler ctrl_handler;
	struct v4l2_ctrl *exposure;
	struct v4l2_ctrl *analogue_gain;
	struct v4l2_ctrl *vblank;
	struct v4l2_ctrl *hblank;

	unsigned long link_freq_bitmap;
};

static inline struct imx681 *to_imx681(struct v4l2_subdev *sd)
{
	return container_of_const(sd, struct imx681, sd);
}

static int imx681_set_ctrl(struct v4l2_ctrl *ctrl)
{
	struct imx681 *imx681 = container_of(ctrl->handler, struct imx681,
					     ctrl_handler);
	int ret = 0;

	/* Only apply controls to hardware when streaming */
	if (!pm_runtime_get_if_in_use(imx681->dev))
		return 0;

	switch (ctrl->id) {
	case V4L2_CID_EXPOSURE:
		cci_write(imx681->cci, IMX681_REG_GROUP_HOLD, 0x01, &ret);
		cci_write(imx681->cci, IMX681_REG_EXPOSURE, ctrl->val, &ret);
		cci_write(imx681->cci, IMX681_REG_GROUP_HOLD, 0x00, &ret);
		dev_dbg(imx681->dev, "set exposure: %d, ret=%d\n",
			ctrl->val, ret);
		break;
	case V4L2_CID_ANALOGUE_GAIN:
		/* V4L2 exposes the unmodified IMX681 register code. */
		cci_write(imx681->cci, IMX681_REG_GROUP_HOLD, 0x01, &ret);
		cci_write(imx681->cci, IMX681_REG_ANALOG_GAIN, ctrl->val, &ret);
		cci_write(imx681->cci, IMX681_REG_GROUP_HOLD, 0x00, &ret);
		dev_dbg(imx681->dev, "set raw analogue gain code: %d, ret=%d\n",
			ctrl->val, ret);
		break;

	default:
		break;
	}

	pm_runtime_put(imx681->dev);
	return ret;
}

static const struct v4l2_ctrl_ops imx681_ctrl_ops = {
	.s_ctrl = imx681_set_ctrl,
};

static int imx681_enum_mbus_code(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *state,
				 struct v4l2_subdev_mbus_code_enum *code)
{
	if (code->index >= ARRAY_SIZE(imx681_mbus_codes))
		return -EINVAL;

	code->code = imx681_mbus_codes[code->index];
	return 0;
}

static bool imx681_is_valid_mbus_code(u32 code)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(imx681_mbus_codes); i++)
		if (imx681_mbus_codes[i] == code)
			return true;
	return false;
}

static int imx681_enum_frame_size(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *state,
				  struct v4l2_subdev_frame_size_enum *fse)
{
	if (fse->index > 0)
		return -EINVAL;

	if (!imx681_is_valid_mbus_code(fse->code))
		return -EINVAL;

	fse->min_width = IMX681_WIDTH;
	fse->max_width = IMX681_WIDTH;
	fse->min_height = IMX681_HEIGHT;
	fse->max_height = IMX681_HEIGHT;

	return 0;
}

static int imx681_init_state(struct v4l2_subdev *sd,
			     struct v4l2_subdev_state *state)
{
	struct v4l2_mbus_framefmt *format;

	format = v4l2_subdev_state_get_format(state, IMAGE_PAD);
	format->width = IMX681_WIDTH;
	format->height = IMX681_HEIGHT;
	format->code = MEDIA_BUS_FMT_SGRBG10_1X10;
	format->field = V4L2_FIELD_NONE;
	format->colorspace = V4L2_COLORSPACE_RAW;
	format->ycbcr_enc = V4L2_YCBCR_ENC_601;
	format->quantization = V4L2_QUANTIZATION_FULL_RANGE;
	format->xfer_func = V4L2_XFER_FUNC_NONE;

	return 0;
}

static int imx681_set_pad_format(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *state,
				 struct v4l2_subdev_format *fmt)
{
	struct v4l2_mbus_framefmt *format;

	/* Fixed resolution, fixed Bayer order */
	fmt->format.width = IMX681_WIDTH;
	fmt->format.height = IMX681_HEIGHT;
	if (!imx681_is_valid_mbus_code(fmt->format.code))
		fmt->format.code = imx681_mbus_codes[0];
	fmt->format.field = V4L2_FIELD_NONE;
	fmt->format.colorspace = V4L2_COLORSPACE_RAW;
	fmt->format.ycbcr_enc = V4L2_YCBCR_ENC_601;
	fmt->format.quantization = V4L2_QUANTIZATION_FULL_RANGE;
	fmt->format.xfer_func = V4L2_XFER_FUNC_NONE;

	format = v4l2_subdev_state_get_format(state, fmt->pad);
	*format = fmt->format;

	return 0;
}

static int imx681_get_selection(struct v4l2_subdev *sd,
				struct v4l2_subdev_state *state,
				struct v4l2_subdev_selection *sel)
{
	switch (sel->target) {
	case V4L2_SEL_TGT_CROP:
	case V4L2_SEL_TGT_CROP_DEFAULT:
	case V4L2_SEL_TGT_CROP_BOUNDS:
	case V4L2_SEL_TGT_NATIVE_SIZE:
		sel->r.top = 0;
		sel->r.left = 0;
		sel->r.width = IMX681_WIDTH;
		sel->r.height = IMX681_HEIGHT;
		return 0;
	default:
		return -EINVAL;
	}
}

static int imx681_identify_module(struct imx681 *imx681);

static int imx681_start_streaming(struct imx681 *imx681)
{
	int ret, cleanup_ret;

	/* Do not write the mode table unless the expected sensor is present. */
	ret = imx681_identify_module(imx681);
	if (ret)
		return ret;

	dev_dbg(imx681->dev, "starting stream: %dx%d RAW10 2-lane\n",
		IMX681_WIDTH, IMX681_HEIGHT);

	/* Write init register sequence */
	ret = cci_multi_reg_write(imx681->cci, imx681_init_regs,
				  ARRAY_SIZE(imx681_init_regs), NULL);
	if (ret) {
		dev_err(imx681->dev, "failed to write init regs: %d\n", ret);
		goto error_stop;
	}

	dev_dbg(imx681->dev, "init registers written successfully\n");

	/* Wait for sensor to stabilise after configuration */
	usleep_range(IMX681_INIT_DELAY_US, IMX681_INIT_DELAY_US + 1000);

	/* Apply first exposure settings with group hold */
	ret = cci_multi_reg_write(imx681->cci, imx681_first_exposure,
				  ARRAY_SIZE(imx681_first_exposure), NULL);
	if (ret) {
		dev_err(imx681->dev, "failed to write exposure: %d\n", ret);
		goto error_stop;
	}

	/* Apply any pending V4L2 control values */
	ret = __v4l2_ctrl_handler_setup(imx681->sd.ctrl_handler);
	if (ret) {
		dev_err(imx681->dev, "failed to apply controls: %d\n", ret);
		goto error_stop;
	}

	/* Start streaming */
	ret = cci_write(imx681->cci, IMX681_REG_MODE_SELECT,
			IMX681_MODE_STREAMING, NULL);
	if (ret) {
		dev_err(imx681->dev, "failed to start streaming: %d\n", ret);
		goto error_stop;
	}

	dev_dbg(imx681->dev, "streaming started\n");
	return 0;

error_stop:
	/* Leave the sensor in standby before the runtime-PM reference is dropped. */
	cleanup_ret = cci_write(imx681->cci, IMX681_REG_GROUP_HOLD, 0x00,
				NULL);
	if (cleanup_ret)
		dev_err(imx681->dev, "failed to clear group hold: %d\n",
			cleanup_ret);

	cleanup_ret = cci_write(imx681->cci, IMX681_REG_MODE_SELECT,
				IMX681_MODE_STANDBY, NULL);
	if (cleanup_ret)
		dev_err(imx681->dev, "failed to enter standby: %d\n",
			cleanup_ret);

	return ret;
}

static int imx681_stop_streaming(struct imx681 *imx681)
{
	int ret;

	ret = cci_write(imx681->cci, IMX681_REG_MODE_SELECT,
			IMX681_MODE_STANDBY, NULL);
	if (ret)
		dev_err(imx681->dev, "failed to stop streaming: %d\n", ret);

	return ret;
}

static int imx681_enable_streams(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *state,
				 u32 pad, u64 streams_mask)
{
	struct imx681 *imx681 = to_imx681(sd);
	int ret;

	if (pad != IMAGE_PAD)
		return -EINVAL;

	ret = pm_runtime_resume_and_get(imx681->dev);
	if (ret < 0)
		return ret;

	ret = imx681_start_streaming(imx681);
	if (ret)
		pm_runtime_put(imx681->dev);

	return ret;
}

static int imx681_disable_streams(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *state,
				  u32 pad, u64 streams_mask)
{
	struct imx681 *imx681 = to_imx681(sd);
	int ret;

	if (pad != IMAGE_PAD)
		return -EINVAL;

	ret = imx681_stop_streaming(imx681);
	pm_runtime_put(imx681->dev);

	return ret;
}

static const struct v4l2_subdev_video_ops imx681_video_ops = {
	.s_stream = v4l2_subdev_s_stream_helper,
};

static const struct v4l2_subdev_pad_ops imx681_pad_ops = {
	.enum_mbus_code = imx681_enum_mbus_code,
	.get_fmt = v4l2_subdev_get_fmt,
	.set_fmt = imx681_set_pad_format,
	.get_selection = imx681_get_selection,
	.enum_frame_size = imx681_enum_frame_size,
	.enable_streams = imx681_enable_streams,
	.disable_streams = imx681_disable_streams,
};

static const struct v4l2_subdev_ops imx681_subdev_ops = {
	.video = &imx681_video_ops,
	.pad = &imx681_pad_ops,
};

static const struct v4l2_subdev_internal_ops imx681_internal_ops = {
	.init_state = imx681_init_state,
};

/* Power management */
static int imx681_power_on(struct device *dev)
{
	struct v4l2_subdev *sd = dev_get_drvdata(dev);
	struct imx681 *imx681 = to_imx681(sd);
	int ret;

	ret = regulator_enable(imx681->avdd);
	if (ret)
		return ret;

	ret = clk_prepare_enable(imx681->xclk);
	if (ret) {
		regulator_disable(imx681->avdd);
		return ret;
	}

	/* Deassert reset (active low) */
	gpiod_set_value_cansleep(imx681->reset_gpio, 0);

	usleep_range(IMX681_RESET_DELAY_US,
		     IMX681_RESET_DELAY_US + IMX681_RESET_DELAY_RANGE_US);

	return 0;
}

static int imx681_power_off(struct device *dev)
{
	struct v4l2_subdev *sd = dev_get_drvdata(dev);
	struct imx681 *imx681 = to_imx681(sd);

	/* Assert reset */
	gpiod_set_value_cansleep(imx681->reset_gpio, 1);
	clk_disable_unprepare(imx681->xclk);
	regulator_disable(imx681->avdd);

	return 0;
}

static int imx681_identify_module(struct imx681 *imx681)
{
	u64 val;
	int ret;

	ret = cci_read(imx681->cci, IMX681_REG_CHIP_ID, &val, NULL);
	if (ret) {
		dev_err(imx681->dev,
			"failed to read chip ID register 0x0016: %d\n", ret);
		return ret;
	}

	if (val != IMX681_CHIP_ID) {
		dev_err(imx681->dev, "chip ID mismatch: 0x%04llx != 0x%04x\n",
			val, IMX681_CHIP_ID);
		return -EIO;
	}

	return 0;
}

static int imx681_init_controls(struct imx681 *imx681)
{
	struct v4l2_ctrl_handler *ctrl_hdlr = &imx681->ctrl_handler;
	struct v4l2_fwnode_device_properties props;
	struct v4l2_ctrl *link_freq;
	s64 hblank, vblank;
	int ret;

	ret = v4l2_ctrl_handler_init(ctrl_hdlr, 6);
	if (ret)
		return ret;

	/* Pixel rate (read-only) */
	v4l2_ctrl_new_std(ctrl_hdlr, &imx681_ctrl_ops,
			  V4L2_CID_PIXEL_RATE, IMX681_PIXEL_RATE,
			  IMX681_PIXEL_RATE, 1, IMX681_PIXEL_RATE);

	/* Link frequency (read-only) */
	link_freq = v4l2_ctrl_new_int_menu(ctrl_hdlr, &imx681_ctrl_ops,
					   V4L2_CID_LINK_FREQ,
					   __fls(imx681->link_freq_bitmap),
					   __ffs(imx681->link_freq_bitmap),
					   imx681_link_frequencies);
	if (link_freq)
		link_freq->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	/* Horizontal blanking (read-only, fixed) */
	hblank = IMX681_LINE_LENGTH_PCK - IMX681_WIDTH;
	imx681->hblank = v4l2_ctrl_new_std(ctrl_hdlr, &imx681_ctrl_ops,
					   V4L2_CID_HBLANK, hblank, hblank,
					   1, hblank);
	if (imx681->hblank)
		imx681->hblank->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	/* Vertical blanking is fixed until its sensor register is verified. */
	vblank = IMX681_FRAME_LENGTH_LINES - IMX681_HEIGHT;
	imx681->vblank = v4l2_ctrl_new_std(ctrl_hdlr, &imx681_ctrl_ops,
					   V4L2_CID_VBLANK, vblank,
					   vblank, 1, vblank);
	if (imx681->vblank)
		imx681->vblank->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	/* Exposure */
	imx681->exposure = v4l2_ctrl_new_std(ctrl_hdlr, &imx681_ctrl_ops,
					     V4L2_CID_EXPOSURE,
					     IMX681_EXPOSURE_MIN,
					     IMX681_EXPOSURE_MAX, 1,
					     IMX681_EXPOSURE_DEFAULT);

	/* Raw 0x0204 code only; physical gain belongs in a future helper. */
	imx681->analogue_gain =
		v4l2_ctrl_new_std(ctrl_hdlr, &imx681_ctrl_ops,
				  V4L2_CID_ANALOGUE_GAIN,
				  IMX681_ANALOG_GAIN_MIN,
				  IMX681_ANALOG_GAIN_MAX, 1,
				  IMX681_ANALOG_GAIN_DEFAULT);

	if (ctrl_hdlr->error) {
		ret = ctrl_hdlr->error;
		dev_err(imx681->dev, "control init failed: %d\n", ret);
		goto error;
	}

	ret = v4l2_fwnode_device_parse(imx681->dev, &props);
	if (ret)
		goto error;

	ret = v4l2_ctrl_new_fwnode_properties(ctrl_hdlr, &imx681_ctrl_ops,
					      &props);
	if (ret)
		goto error;

	imx681->sd.ctrl_handler = ctrl_hdlr;
	return 0;

error:
	v4l2_ctrl_handler_free(ctrl_hdlr);
	return ret;
}

static int imx681_parse_endpoint(struct imx681 *imx681)
{
	struct fwnode_handle *fwnode = dev_fwnode(imx681->dev);
	struct v4l2_fwnode_endpoint bus_cfg = {
		.bus_type = V4L2_MBUS_CSI2_DPHY,
	};
	struct fwnode_handle *ep;
	int ret;

	ep = fwnode_graph_get_next_endpoint(fwnode, NULL);
	if (!ep) {
		dev_err(imx681->dev, "no endpoint found in firmware node\n");
		return -ENXIO;
	}

	ret = v4l2_fwnode_endpoint_alloc_parse(ep, &bus_cfg);
	fwnode_handle_put(ep);
	if (ret) {
		dev_err(imx681->dev, "failed to parse endpoint: %d\n", ret);
		return ret;
	}

	if (bus_cfg.bus.mipi_csi2.num_data_lanes != IMX681_NUM_LANES) {
		dev_err(imx681->dev,
			"expected %d data lanes, got %d\n",
			IMX681_NUM_LANES,
			bus_cfg.bus.mipi_csi2.num_data_lanes);
		ret = -EINVAL;
		goto done;
	}

	ret = v4l2_link_freq_to_bitmap(imx681->dev,
				       bus_cfg.link_frequencies,
				       bus_cfg.nr_of_link_frequencies,
				       imx681_link_frequencies,
				       ARRAY_SIZE(imx681_link_frequencies),
				       &imx681->link_freq_bitmap);
	if (ret)
		dev_err(imx681->dev, "link frequency mismatch: %d\n", ret);

done:
	v4l2_fwnode_endpoint_free(&bus_cfg);
	return ret;
}

static int imx681_probe(struct i2c_client *client)
{
	struct imx681 *imx681;
	int ret;

	imx681 = devm_kzalloc(&client->dev, sizeof(*imx681), GFP_KERNEL);
	if (!imx681)
		return -ENOMEM;

	imx681->dev = &client->dev;

	/* Initialise V4L2 subdev */
	v4l2_i2c_subdev_init(&imx681->sd, client, &imx681_subdev_ops);

	/* Initialise CCI regmap for 16-bit register addresses */
	imx681->cci = devm_cci_regmap_init_i2c(client, 16);
	if (IS_ERR(imx681->cci)) {
		ret = PTR_ERR(imx681->cci);
		dev_err(imx681->dev, "failed to init CCI: %d\n", ret);
		return ret;
	}

	imx681->xclk = devm_v4l2_sensor_clk_get(imx681->dev, NULL);
	if (IS_ERR(imx681->xclk))
		return dev_err_probe(imx681->dev, PTR_ERR(imx681->xclk),
				     "failed to get clock\n");

	if (clk_get_rate(imx681->xclk) != 19200000)
		return dev_err_probe(imx681->dev, -EINVAL,
				     "external clock is not 19.2 MHz\n");

	imx681->avdd = devm_regulator_get(imx681->dev, "avdd");
	if (IS_ERR(imx681->avdd))
		return dev_err_probe(imx681->dev, PTR_ERR(imx681->avdd),
				     "failed to get avdd regulator\n");

	/* Get the active-low reset GPIO. */
	imx681->reset_gpio = devm_gpiod_get(imx681->dev, "reset",
					    GPIOD_OUT_HIGH);
	if (IS_ERR(imx681->reset_gpio))
		return dev_err_probe(imx681->dev,
				     PTR_ERR(imx681->reset_gpio),
				     "failed to get reset GPIO\n");

	/* Parse CSI-2 endpoint */
	ret = imx681_parse_endpoint(imx681);
	if (ret) {
		dev_err(imx681->dev, "endpoint parse failed: %d\n", ret);
		return ret;
	}

	/* Probe against the actual powered sensor, then hand ownership to RPM. */
	ret = imx681_power_on(imx681->dev);
	if (ret)
		return ret;

	ret = imx681_identify_module(imx681);
	if (ret)
		goto error_power_off;

	/* Init V4L2 controls */
	ret = imx681_init_controls(imx681);
	if (ret)
		goto error_power_off;

	/* Setup subdev */
	imx681->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	imx681->sd.entity.function = MEDIA_ENT_F_CAM_SENSOR;
	imx681->sd.internal_ops = &imx681_internal_ops;

	/* Init media entity */
	imx681->pad.flags = MEDIA_PAD_FL_SOURCE;
	ret = media_entity_pads_init(&imx681->sd.entity, 1, &imx681->pad);
	if (ret) {
		dev_err(imx681->dev, "media entity init failed: %d\n", ret);
		goto error_handler_free;
	}

	imx681->sd.state_lock = imx681->ctrl_handler.lock;
	ret = v4l2_subdev_init_finalize(&imx681->sd);
	if (ret < 0) {
		dev_err(imx681->dev, "subdev init finalize failed: %d\n", ret);
		goto error_media_entity;
	}

	ret = v4l2_async_register_subdev_sensor(&imx681->sd);
	if (ret < 0) {
		dev_err(imx681->dev,
			"async register subdev failed: %d\n", ret);
		goto error_subdev_cleanup;
	}

	pm_runtime_set_active(imx681->dev);
	pm_runtime_enable(imx681->dev);
	pm_runtime_idle(imx681->dev);

	return 0;

error_subdev_cleanup:
	v4l2_subdev_cleanup(&imx681->sd);
error_media_entity:
	media_entity_cleanup(&imx681->sd.entity);
error_handler_free:
	v4l2_ctrl_handler_free(imx681->sd.ctrl_handler);
error_power_off:
	imx681_power_off(imx681->dev);
	return ret;
}

static void imx681_remove(struct i2c_client *client)
{
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct imx681 *imx681 = to_imx681(sd);

	v4l2_async_unregister_subdev(sd);
	v4l2_subdev_cleanup(&imx681->sd);
	media_entity_cleanup(&sd->entity);
	v4l2_ctrl_handler_free(imx681->sd.ctrl_handler);

	pm_runtime_disable(imx681->dev);
	if (!pm_runtime_status_suspended(imx681->dev))
		imx681_power_off(imx681->dev);
	pm_runtime_set_suspended(imx681->dev);
}

static DEFINE_RUNTIME_DEV_PM_OPS(imx681_pm_ops, imx681_power_off,
				 imx681_power_on, NULL);

#ifdef CONFIG_ACPI
static const struct acpi_device_id imx681_acpi_ids[] = {
	{ "SONY0681" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(acpi, imx681_acpi_ids);
#endif

static struct i2c_driver imx681_i2c_driver = {
	.driver = {
		.name = "imx681",
		.pm = pm_ptr(&imx681_pm_ops),
		.acpi_match_table = ACPI_PTR(imx681_acpi_ids),
	},
	.probe = imx681_probe,
	.remove = imx681_remove,
};
module_i2c_driver(imx681_i2c_driver);

MODULE_DESCRIPTION("Sony IMX681 CMOS Image Sensor Driver");
MODULE_AUTHOR("Andre Gilerson <andre.gilerson@gmail.com>");
MODULE_LICENSE("GPL");
