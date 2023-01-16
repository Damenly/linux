// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/errno.h>
#include <linux/slab.h>

#include "math.h"
#include "heatmap.h"

void heatmap_average(struct heatmap *hm)
{
  int i;
  if (!hm->size || !hm->data)
    return;
  hm->average = 0;

	for (i = 0; i < hm->size; i++)
		hm->average += hm->data[i];

  hm->average = fix_div_round(hm->average, hm->size);
}

uint8_t heatmap_value(struct heatmap *hm, int x, int y)
{
	if (x < 0 || x >= hm->width)
		return 0;

	if (y < 0 || y >= hm->height)
		return 0;

	return hm->data[y * hm->width + x] >= hm->average
    ? 0 : hm->average - hm->data[y * hm->width + x];
}

bool heatmap_is_touch(struct heatmap *hm, int x, int y)
{
	return heatmap_value(hm, x, y) >= hm->touch_threshold;
}

bool heatmap_compare(struct heatmap *hm, int x1, int y1, int x2, int y2)
{
	int v1 = heatmap_value(hm, x1, y1);
	int v2 = heatmap_value(hm, x2, y2);

	if (v2 > v1)
		return false;

	if (v2 < v1)
		return true;

	if (x2 > x1)
		return false;

	if (x2 < x1)
		return true;

	if (y2 > y1)
		return false;

	if (y2 < y1)
		return true;

	return y2 == y1;
}

uint8_t heatmap_get_visited(struct heatmap *hm, int x, int y)
{
	if (!hm->visited || x < 0 || x >= hm->width ||
       y < 0 || y >= hm->height)
		return 0;

	return hm->visited[y * hm->width + x];
}

void heatmap_set_visited(struct heatmap *hm, int x, int y, uint8_t value)
{
	if (!hm->visited || x < 0 || x >= hm->width ||
       y < 0 || y >= hm->height)
    return;

	hm->visited[y * hm->width + x] = value;
}

void heatmap_free(struct heatmap *hm)
{
  if(!hm || !hm->visited)
    return;
  kfree(hm->visited);
  hm->visited = NULL;
}

int heatmap_init(struct heatmap *hm, int w, int h, int threshold)
{
  hm->data = NULL;
  hm->touch_threshold = threshold;
  if (w == hm->width && h == hm->height){
    memset(hm->visited, 0, hm->size);
    return 0;
  }
  hm->width = w;
  hm->height = h;
	hm->size = w * h;
  hm->diagonal = fix_hypot(w,h);
  heatmap_free(hm);
	hm->visited = kzalloc(hm->size, GFP_NOWAIT);
	if (!hm->visited) {
		return -ENOMEM;
	}
	return 0;
}

void release_heatmap(struct heatmap *hm){
  if (!hm)
    return;
  heatmap_free(hm);
  kfree(hm);
}

