/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTS_MATH_H_
#define _IPTS_MATH_H_

#include <linux/types.h>

/* (pi / 4) * (1 << 29) */
#define M_PI_4 421657428
#define M_PI_2 (M_PI_4 * 2)
#define M_PI   (M_PI_2 * 2)

/* 0.2447 * (1 << 29) */
#define CONST_2447 131372312

/* 0.0663 * (1 << 29) */
#define CONST_0663 35594541

void ipts_math_altitude_azimuth_to_tilt(s32 alt, s32 azm, s32 *tx, s32 *ty);

#endif /* _IPTS_MATH_H_ */
