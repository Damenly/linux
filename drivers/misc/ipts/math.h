// Copyright 2021 The FydeOS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _IPTS_MATH_H_
#define _IPTS_MATH_H_

#include <linux/types.h>
#define MAX_INT    0x7ffffff
int fix_hypot(int x, int y);
int fix_div_round(int x, int y);
int fix_div_long_round(long x, long y);
int fix_zoom(int x, int origin_max, int new_max);
#define SCALE_FACTOR 8
#define SCALE_INT(n) ((n) << SCALE_FACTOR)
#define REDUCE_INT(n) ((n) >> SCALE_FACTOR)
#endif /* _IPTS_MATH_H_ */
