/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _IPTSD_HEATMAP_H_
#define _IPTSD_HEATMAP_H_
#include <linux/types.h>

struct heatmap {
  uint8_t touch_count;
  u32 bell;
	int width;
	int height;
	int size;
	int touch_threshold;
  int average;
  int diagonal;

	uint8_t *data;
	uint8_t *visited;
};

void heatmap_average(struct heatmap *hm);
uint8_t heatmap_value(struct heatmap *hm, int x, int y);
bool heatmap_is_touch(struct heatmap *hm, int x, int y);
bool heatmap_compare(struct heatmap *hm, int x1, int y1, int x2, int y2);
uint8_t heatmap_get_visited(struct heatmap *hm, int x, int y);
void heatmap_set_visited(struct heatmap *hm, int x, int y, uint8_t index);
int heatmap_init(struct heatmap *hm, int w, int h, int threshold);
void heatmap_free(struct heatmap *hm);
void release_heatmap(struct heatmap *hm);

#endif /* _IPTSD_HEATMAP_H_ */
