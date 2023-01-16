/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTSD_CONTACT_H_
#define _IPTSD_CONTACT_H_

#include <linux/types.h>

#include "heatmap.h"

#define PALM_AREA_THRESHOLD 35
#define PALM_INDEX 0xfe
#define VISITED_INDEX 0xff

struct hm_info {
  int x;
  int y;
};

struct tp_surface {
  int pt;
  struct hm_info info[PALM_AREA_THRESHOLD];
};

struct cluster {
	long x;
	long y;
	long w;
	long max_v;
  int area;
  int max_x;
  int max_y;
  int min_x;
  int min_y;
};

struct contact {
	/* center */
	int x;
	int y;
  int slot;
  int index;
	int max_v;
  int major;
  int area;
  bool is_stable;
};

uint8_t contacts_get(struct heatmap *hm, struct heatmap *last_hm,  struct contact *contacts, int count);

void release_contact_buff(void);
int setup_contact_buff(void);

#endif /* _IPTSD_CONTACT_H_ */
