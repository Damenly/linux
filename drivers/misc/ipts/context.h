/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2020 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#ifndef _IPTS_CONTEXT_H_
#define _IPTS_CONTEXT_H_
#include <linux/types.h>
#include <linux/device.h>
#include <linux/input.h>
#include <linux/cdev.h>
#include <linux/mei_cl_bus.h>

#include "protocol.h"
#include "input_device.h"
#include "touch-processing.h"
#include "config.h"

enum ipts_host_status {
	IPTS_HOST_STATUS_STARTING,
	IPTS_HOST_STATUS_STARTED,
	IPTS_HOST_STATUS_STOPPING,
	IPTS_HOST_STATUS_STOPPED,
};

enum ipts_request_status {
  IPTS_IDLE,
  IPTS_REQUEST_FRAME,
  IPTS_HANDLE_FRAME,
};

struct ipts_buffer_info {
	u8 *address;
	dma_addr_t dma_address;
};

struct ipts_context {
	struct mei_cl_device *cldev;
	struct device *dev;

	bool restart;
	enum ipts_host_status status;
	struct ipts_get_device_info_rsp device_info;

	struct ipts_buffer_info data[IPTS_BUFFERS];
	struct ipts_buffer_info doorbell;

	struct ipts_buffer_info feedback[IPTS_BUFFERS];
	struct ipts_buffer_info workqueue;
	struct ipts_buffer_info host2me;
  u32 current_doorbell;
  enum ipts_request_status request_status;
  struct delayed_work request_work;
  //struct delayed_work release_touch;
  struct iptsd_touch_processor tp;
  struct surface_touch_config *config;
  struct input_dev *touch_dev;
  struct input_dev *stylus_dev;

};

#define REFRESH_DELAY msecs_to_jiffies(30)
#define REFERSH_NO_INPUT msecs_to_jiffies(100)
#define INIT_IPTS_TIMEOUT msecs_to_jiffies(150)

extern bool devmode;

#endif /* _IPTS_CONTEXT_H_ */
