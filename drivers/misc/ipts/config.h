// Copyright 2021 The FydeOS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _IPTS_CONFIG_H_
#define _IPTS_CONFIG_H_
#include <linux/types.h>

#define CONTACT_STABILITY_THRESHOLD 10
#define CONTACT_TOUCH_THRESHOLD     10

struct surface_touch_config {
  u16 vendor_id;
  u16 product_id;
  char name[32];
  bool invert_x;
  bool invert_y;
  u32 width;
  u32 height;
  bool block_on_palm;
  int touch_threshold;
  int stability_threshold;
};

struct surface_touch_config* get_match_config(u16 vendor, u16 product);
#endif /* _IPTS_CONFIG_H_ */
