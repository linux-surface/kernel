// SPDX-License-Identifier: GPL-2.0-only
/*
 * ams OSRAM TCS3430 Ambient Light & XYZ Tristimulus IIO Driver
 */

#include <linux/array_size.h>
#include <linux/bits.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/iio/iio.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pm.h>

#define TCS3430_ENABLE			0x80
#define TCS3430_ATIME			0x81
#define TCS3430_CFG1			0x90
#define TCS3430_ID			0x92
#define TCS3430_STATUS			0x93
#define TCS3430_DATA			0x94
#define TCS3430_CFG2			0x9f
#define TCS3430_CFG3			0xab
#define TCS3430_INTENAB			0xdd

#define TCS3430_ENABLE_PON		BIT(0)
#define TCS3430_ENABLE_AEN		BIT(1)
#define TCS3430_ID_MASK			GENMASK(7, 2)
#define TCS3430_ID_VAL			0xdc

/* 72 integration cycles * 2.78 ms = ~200 ms continuous integration */
#define TCS3430_INTEGRATION_CYCLES	72
#define TCS3430_CYCLE_US		2780

static const int tcs3430_gains[] = { 1, 4, 16, 64 };

struct tcs3430_data {
	struct i2c_client *client;
	struct mutex lock;
	u8 gain_code;
	int frame[4]; /* Z, Y (photopic), IR1, X */
};

static int tcs3430_write(struct tcs3430_data *data, u8 reg, u8 value)
{
	return i2c_smbus_write_byte_data(data->client, reg, value);
}

static int tcs3430_init_hw(struct tcs3430_data *data)
{
	int ret;

	ret = tcs3430_write(data, TCS3430_ENABLE, 0x00);
	if (ret < 0)
		return ret;

	ret = tcs3430_write(data, TCS3430_ATIME,
			    TCS3430_INTEGRATION_CYCLES - 1);
	if (ret < 0)
		return ret;

	ret = tcs3430_write(data, TCS3430_CFG1, data->gain_code);
	if (ret < 0)
		return ret;

	ret = tcs3430_write(data, TCS3430_CFG2, 0x04);
	if (ret < 0)
		return ret;

	ret = tcs3430_write(data, TCS3430_CFG3, 0x0c);
	if (ret < 0)
		return ret;

	ret = tcs3430_write(data, TCS3430_INTENAB, 0x00);
	if (ret < 0)
		return ret;

	return tcs3430_write(data, TCS3430_ENABLE,
			     TCS3430_ENABLE_PON | TCS3430_ENABLE_AEN);
}

static int tcs3430_read_frame(struct tcs3430_data *data)
{
	u8 raw[8];
	int ret, i;
	int y;

	ret = i2c_smbus_read_i2c_block_data(data->client, TCS3430_DATA,
					    sizeof(raw), raw);
	if (ret != sizeof(raw))
		return ret < 0 ? ret : -EIO;

	for (i = 0; i < 4; i++)
		data->frame[i] = raw[i * 2] | (raw[i * 2 + 1] << 8);

	y = data->frame[1];
	if (y > 52000 && data->gain_code > 0) {
		data->gain_code--;
		tcs3430_write(data, TCS3430_CFG1, data->gain_code);
	} else if (y < 200 && data->gain_code < ARRAY_SIZE(tcs3430_gains) - 1) {
		data->gain_code++;
		tcs3430_write(data, TCS3430_CFG1, data->gain_code);
	}

	return 0;
}

static int tcs3430_read_raw(struct iio_dev *indio_dev,
			    const struct iio_chan_spec *chan,
			    int *val, int *val2, long mask)
{
	struct tcs3430_data *data = iio_priv(indio_dev);
	int ret, gain;

	switch (mask) {
	case IIO_CHAN_INFO_PROCESSED:
		mutex_lock(&data->lock);
		ret = tcs3430_read_frame(data);
		if (!ret) {
			gain = tcs3430_gains[data->gain_code & 3];
			*val = (data->frame[1] * 64) / gain;
			ret = IIO_VAL_INT;
		}
		mutex_unlock(&data->lock);
		return ret;
	case IIO_CHAN_INFO_RAW:
		mutex_lock(&data->lock);
		ret = tcs3430_read_frame(data);
		if (!ret) {
			*val = data->frame[chan->address];
			ret = IIO_VAL_INT;
		}
		mutex_unlock(&data->lock);
		return ret;
	case IIO_CHAN_INFO_HARDWAREGAIN:
		mutex_lock(&data->lock);
		*val = tcs3430_gains[data->gain_code & 3];
		mutex_unlock(&data->lock);
		return IIO_VAL_INT;
	case IIO_CHAN_INFO_INT_TIME:
		*val = 0;
		*val2 = TCS3430_INTEGRATION_CYCLES * TCS3430_CYCLE_US;
		return IIO_VAL_INT_PLUS_MICRO;
	default:
		return -EINVAL;
	}
}

#define TCS3430_INTENSITY_CHANNEL(label, idx) {				\
	.type = IIO_INTENSITY,						\
	.indexed = 1,							\
	.channel = (idx),						\
	.extend_name = (label),						\
	.address = (idx),						\
	.info_mask_separate = BIT(IIO_CHAN_INFO_RAW),			\
	.info_mask_shared_by_all = BIT(IIO_CHAN_INFO_HARDWAREGAIN) |	\
				   BIT(IIO_CHAN_INFO_INT_TIME),		\
}

static const struct iio_chan_spec tcs3430_channels[] = {
	{
		.type = IIO_LIGHT,
		.info_mask_separate = BIT(IIO_CHAN_INFO_PROCESSED),
		.info_mask_shared_by_all = BIT(IIO_CHAN_INFO_HARDWAREGAIN) |
					   BIT(IIO_CHAN_INFO_INT_TIME),
	},
	TCS3430_INTENSITY_CHANNEL("z", 0),
	TCS3430_INTENSITY_CHANNEL("y", 1),
	TCS3430_INTENSITY_CHANNEL("ir", 2),
	TCS3430_INTENSITY_CHANNEL("x", 3),
};

static const struct iio_info tcs3430_info = {
	.read_raw = tcs3430_read_raw,
};

static void tcs3430_power_off(void *priv)
{
	struct tcs3430_data *data = priv;

	tcs3430_write(data, TCS3430_ENABLE, 0x00);
}

static int tcs3430_probe(struct i2c_client *client)
{
	struct tcs3430_data *data;
	struct iio_dev *indio_dev;
	int ret;

	if (!i2c_check_functionality(client->adapter,
				     I2C_FUNC_SMBUS_BYTE_DATA |
				     I2C_FUNC_SMBUS_READ_I2C_BLOCK))
		return -EOPNOTSUPP;

	ret = i2c_smbus_read_byte_data(client, TCS3430_ID);
	if (ret < 0)
		return ret;
	if ((ret & TCS3430_ID_MASK) != TCS3430_ID_VAL)
		return dev_err_probe(&client->dev, -ENODEV,
				     "unexpected TCS3430 ID: %#02x\n", ret);

	indio_dev = devm_iio_device_alloc(&client->dev, sizeof(*data));
	if (!indio_dev)
		return -ENOMEM;

	data = iio_priv(indio_dev);
	data->client = client;
	data->gain_code = 3; /* 64x default gain */

	ret = devm_mutex_init(&client->dev, &data->lock);
	if (ret)
		return ret;

	ret = tcs3430_init_hw(data);
	if (ret < 0)
		return ret;

	ret = devm_add_action_or_reset(&client->dev, tcs3430_power_off, data);
	if (ret)
		return ret;

	indio_dev->name = "tcs3430";
	indio_dev->info = &tcs3430_info;
	indio_dev->modes = INDIO_DIRECT_MODE;
	indio_dev->channels = tcs3430_channels;
	indio_dev->num_channels = ARRAY_SIZE(tcs3430_channels);
	i2c_set_clientdata(client, data);

	return devm_iio_device_register(&client->dev, indio_dev);
}

static int tcs3430_suspend(struct device *dev)
{
	struct tcs3430_data *data = dev_get_drvdata(dev);
	int ret;

	mutex_lock(&data->lock);
	ret = tcs3430_write(data, TCS3430_ENABLE, 0x00);
	mutex_unlock(&data->lock);

	return ret < 0 ? ret : 0;
}

static int tcs3430_resume(struct device *dev)
{
	struct tcs3430_data *data = dev_get_drvdata(dev);
	int ret;

	mutex_lock(&data->lock);
	ret = tcs3430_init_hw(data);
	mutex_unlock(&data->lock);

	return ret < 0 ? ret : 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(tcs3430_pm_ops, tcs3430_suspend,
				tcs3430_resume);

static const struct of_device_id tcs3430_of_match[] = {
	{ .compatible = "ams,tcs3430" },
	{ }
};
MODULE_DEVICE_TABLE(of, tcs3430_of_match);

static const struct i2c_device_id tcs3430_id[] = {
	{ "tcs3430" },
	{ }
};
MODULE_DEVICE_TABLE(i2c, tcs3430_id);

static struct i2c_driver tcs3430_driver = {
	.driver = {
		.name = "tcs3430",
		.of_match_table = tcs3430_of_match,
		.pm = pm_sleep_ptr(&tcs3430_pm_ops),
	},
	.probe = tcs3430_probe,
	.id_table = tcs3430_id,
};
module_i2c_driver(tcs3430_driver);

MODULE_DESCRIPTION("ams OSRAM TCS3430 Ambient Light and XYZ Color Sensor Driver");
MODULE_LICENSE("GPL");
