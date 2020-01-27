// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bug.h>
#include <linux/fixp-arith.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "math.h"

/*
 * Since we need to work with [-pi, pi] in the atan functions, we are using
 * 1 << 29 for the fixed point numbers. This allows us to store numbers from
 * [-4, 4] using the full 32-bit signed integer range.
 *
 * Some constants such as PI have been already converted to the fixed-point
 * format and are defined in math.h.
 */

static inline s32 ipts_math_mul(s32 x, s32 y)
{
	return (x * (s64)y) >> 29;
}

static inline s32 ipts_math_div(s32 x, s32 y)
{
	return ((s64)x << 29) / y;
}

static s32 ipts_math_atan(s32 x)
{
	s32 tmp = ipts_math_mul(
			ipts_math_mul(x, (abs(x) - (1 << 29))),
			CONST_2447 + ipts_math_mul(CONST_0663, abs(x)));

	return ipts_math_mul(M_PI_4, x) - tmp;
}

static s32 ipts_math_atan2(s32 y, s32 x)
{
	s32 z;

	if (x != 0) {
		if (abs(x) > abs(y)) {
			z = ipts_math_div(y, x);
			if (x > 0)
				return ipts_math_atan(z);
			else if (y >= 0)
				return ipts_math_atan(z) + M_PI;
			else
				return ipts_math_atan(z) - M_PI;
		} else {
			z = ipts_math_div(x, y);
			if (y > 0)
				return -ipts_math_atan(z) + M_PI_2;
			else
				return -ipts_math_atan(z) - M_PI_2;
		}
	} else {
		if (y > 0)
			return M_PI_2;
		else if (y < 0)
			return -M_PI_2;
	}

	return 0;
}

/*
 * Convert altitude in range [0, 9000] and azimuth in range [0, 36000]
 * to x-/y-tilt in range [-9000, 9000]. Azimuth is given
 * counter-clockwise, starting with zero on the right. Altitude is
 * given as angle between stylus and z-axis.
 */
void ipts_math_altitude_azimuth_to_tilt(s32 alt, s32 azm, s32 *tx, s32 *ty)
{
	s32 sin_alt, cos_alt;
	s32 sin_azm, cos_azm;

	s32 x, y, z;
	s64 atan_x, atan_y;

	sin_alt = fixp_sin32_rad(alt, 36000) / 4;
	sin_azm = fixp_sin32_rad(azm, 36000) / 4;

	cos_alt = fixp_cos32_rad(alt, 36000) / 4;
	cos_azm = fixp_cos32_rad(azm, 36000) / 4;

	x = ipts_math_mul(sin_alt, cos_azm);
	y = ipts_math_mul(sin_alt, sin_azm);
	z = cos_alt;

	atan_x = ipts_math_atan2(z, x);
	atan_y = ipts_math_atan2(z, y);

	atan_x = atan_x * 4500;
	atan_y = atan_y * 4500;

	atan_x = atan_x / M_PI_4;
	atan_y = atan_y / M_PI_4;

	*tx = 9000 - atan_x;
	*ty = atan_y - 9000;
}
