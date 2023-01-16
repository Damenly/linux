// Copyright 2021 The FydeOS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _IPTS_INPUT_DEVICE_H_
#define _IPTS_INPUT_DEVICE_H_

#include <linux/types.h>

struct ipts_context;

int init_input_devices(struct ipts_context *ipts);

int report_data(struct ipts_context *ipts);

void remove_input_devices(struct ipts_context *ipts);
#endif /* _IPTS_INPUT_DEVICE_H_ */
