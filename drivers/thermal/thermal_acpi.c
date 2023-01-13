// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2022 Linaro Limited
 *
 * Author: Daniel Lezcano <daniel.lezcano@linaro.org>
 *
 * ACPI thermal configuration
 */
#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/units.h>
#include <uapi/linux/thermal.h>

#include "thermal_core.h"

/*
 * An hysteresis value below zero is invalid and we can consider a
 * value greater than 20°K/°C is invalid too.
 */
#define HYSTERESIS_MIN_DECIK	0
#define HYSTERESIS_MAX_DECIK	200

/*
 * Minimum temperature for full military grade is 218°K (-55°C) and
 * max temperature is 448°K (175°C). We can consider those values as
 * the boundaries for the [trips] temperature returned by the
 * firmware. Any values out of these boundaries can be considered
 * bogus and we can assume the firmware has no data to provide.
 */
#define TEMPERATURE_MIN_DECIK	2180
#define TEMPERATURE_MAX_DECIK	4480

static int thermal_acpi_get_temperature_object(struct acpi_device *adev,
					       char *object, int *temperature)
{
	unsigned long long temp;
	acpi_status status;

	status = acpi_evaluate_integer(adev->handle, object, NULL, &temp);
	if (ACPI_FAILURE(status)) {
		acpi_handle_debug(adev->handle, "No temperature object '%s'\n", object);
		return -ENODEV;
	}

	if (temp < TEMPERATURE_MIN_DECIK || temp >= TEMPERATURE_MAX_DECIK) {
		acpi_handle_info(adev->handle, "Invalid temperature '%llu deci°K' for object '%s'\n",
				 temp, object);
		return -ENODATA;
	}

	*temperature = deci_kelvin_to_millicelsius(temp);

	return 0;
}

/**
 * thermal_acpi_trip_gtsh() - Get the global hysteresis value
 * @adev: the acpi device to get the description from
 *
 * Get the global hysteresis value for the trip points. If any call
 * fail, we shall return a zero hysteresis value.
 *
 * Return: An integer between %HYSTERESIS_MIN_DECIK and %HYSTERESIS_MAX_DECIK
 */
int thermal_acpi_trip_gtsh(struct acpi_device *adev)
{
	unsigned long long hyst;
	acpi_status status;

	status = acpi_evaluate_integer(adev->handle, "GTSH", NULL, &hyst);
	if (ACPI_FAILURE(status))
		return 0;

	if (hyst < HYSTERESIS_MIN_DECIK || hyst >= HYSTERESIS_MAX_DECIK) {
		acpi_handle_info(adev->handle, "Invalid hysteresis '%llu deci°K' for object 'GTSH'\n",
				 hyst);
		return 0;
	}

	return deci_kelvin_to_millicelsius(hyst);
}
EXPORT_SYMBOL_GPL(thermal_acpi_trip_gtsh);

/**
 * thermal_acpi_trip_act() - Get the specified active trip point
 * @adev: the acpi device to get the description from
 * @trip: a &struct thermal_trip to be filled if the function succeed
 * @id: an integer speciyfing the active trip point id
 *
 * The function calls the ACPI framework to get the "_ACTx" objects
 * which describe the active trip points. The @id builds the "_ACTx"
 * string with the numbered active trip point name. Then it fills the
 * @trip structure with the information retrieved from those objects.
 *
 * Return:
 * * 0 - Success
 * * -ENODEV - Failed to retrieve the ACPI object
 * * -ENODATA - The ACPI object value appears to be inconsistent
 */
int thermal_acpi_trip_act(struct acpi_device *adev,
			  struct thermal_trip *trip, int id)
{
	char name[5];
	int ret;

	sprintf(name, "_AC%d", id);

	ret = thermal_acpi_get_temperature_object(adev, name, &trip->temperature);
	if (ret)
		return ret;

	trip->hysteresis = 0;
	trip->type = THERMAL_TRIP_ACTIVE;

	return 0;
}
EXPORT_SYMBOL_GPL(thermal_acpi_trip_act);

/**
 * thermal_acpi_trip_psv() - Get the passive trip point
 * @adev: the acpi device to get the description from
 * @trip: a &struct thermal_trip to be filled if the function succeed
 *
 * The function calls the ACPI framework to get the "_PSV" object
 * which describe the passive trip point. Then it fills the @trip
 * structure with the information retrieved from those objects.
 *
 * Return:
 * * 0 - Success
 * * -ENODEV - Failed to retrieve the ACPI object
 * * -ENODATA - The ACPI object value appears to be inconsistent
 */
int thermal_acpi_trip_psv(struct acpi_device *adev, struct thermal_trip *trip)
{
	int ret;

	ret = thermal_acpi_get_temperature_object(adev, "_PSV", &trip->temperature);
	if (ret)
		return ret;

	trip->hysteresis = 0;
	trip->type = THERMAL_TRIP_PASSIVE;

	return 0;
}
EXPORT_SYMBOL_GPL(thermal_acpi_trip_psv);

/**
 * thermal_acpi_trip_hot() - Get the near critical trip point
 * @adev: the acpi device to get the description from
 * @trip: a &struct thermal_trip to be filled if the function succeed
 *
 * The function calls the ACPI framework to get the "_HOT" object
 * which describe the hot trip point. Then it fills the @trip
 * structure with the information retrieved from those objects.
 *
 * Return:
 * * 0 - Success
 * * -ENODEV - Failed to retrieve the ACPI object
 * * -ENODATA - The ACPI object appears to be inconsistent
 */
int thermal_acpi_trip_hot(struct acpi_device *adev, struct thermal_trip *trip)
{
	int ret;

	ret = thermal_acpi_get_temperature_object(adev, "_HOT", &trip->temperature);
	if (ret)
		return ret;

	trip->hysteresis = 0;
	trip->type = THERMAL_TRIP_HOT;

	return 0;
}
EXPORT_SYMBOL_GPL(thermal_acpi_trip_hot);

/**
 * thermal_acpi_trip_crit() - Get the critical trip point
 * @adev: the acpi device to get the description from
 * @trip: a &struct thermal_trip to be filled if the function succeed
 *
 * The function calls the ACPI framework to get the "_CRT" object
 * which describe the critical trip point. Then it fills the @trip
 * structure with the information retrieved from this object.
 *
 * Return:
 * * 0 - Success
 * * -ENODEV - Failed to retrieve the ACPI object
 * * -ENODATA - The ACPI object value appears to be inconsistent
 */
int thermal_acpi_trip_crit(struct acpi_device *adev, struct thermal_trip *trip)
{
	int ret;

	ret = thermal_acpi_get_temperature_object(adev, "_CRT", &trip->temperature);
	if (ret)
		return ret;

	/*
	 * The hysteresis value has no sense here because critical
	 * trip point has no u-turn
	 */
	trip->hysteresis = 0;
	trip->type = THERMAL_TRIP_CRITICAL;

	return 0;
}
EXPORT_SYMBOL_GPL(thermal_acpi_trip_crit);
