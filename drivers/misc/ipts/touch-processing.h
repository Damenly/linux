/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTSD_TOUCH_PROCESSING_H_
#define _IPTSD_TOUCH_PROCESSING_H_

#include <linux/types.h>

#include "heatmap.h"
#include "protocol.h"
#include "config.h"
#include "contact.h"

#define IPTSD_MAX_STYLI 10
#define BELL_THRESHOLD 2
#define USE_FILTER 0
#define FILTER_OUT(a,b) (a->bell - b->bell) < BELL_THRESHOLD

struct iptsd_touch_input {
	int x;
	int y;
	int area;
	int index;
	int slot;
  int major;
	bool is_stable;
  int pressure;
	struct contact *contact;
};

struct iptsd_touch_processor {
  uint8_t touch_count;
  bool filter_out;
	struct heatmap *hm;
  struct heatmap *last_hm;
	struct contact *contacts;
	struct iptsd_touch_input *inputs;

	struct surface_touch_config *config;
	struct ipts_get_device_info_rsp *device_info;
};

//double iptsd_touch_processing_dist(struct iptsd_touch_input *input, struct iptsd_touch_input *other);
void iptsd_touch_processing_inputs(struct iptsd_touch_processor *tp, struct heatmap *hm);
struct heatmap *iptsd_touch_processing_get_heatmap(struct iptsd_touch_processor *tp, int w, int h);
int iptsd_touch_processing_init(struct iptsd_touch_processor *tp);
void iptsd_touch_processing_free(struct iptsd_touch_processor *tp);

#endif /* _IPTSD_TOUCH_PROCESSING_H_ */
