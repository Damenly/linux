// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/errno.h>
#include <linux/slab.h>
#include "contact.h"
#include "heatmap.h"
#include "protocol.h"
#include "touch-processing.h"
#include "math.h"
#include "input_data.h"

#define STABLE_CONTACT_AREA 5

void iptsd_touch_processing_inputs(struct iptsd_touch_processor *tp, struct heatmap *hm)
{
	int x, y, i;

  heatmap_average(hm);
	tp->touch_count = contacts_get(hm, tp->last_hm, tp->contacts, tp->device_info->max_contacts);

  if (USE_FILTER && tp->touch_count == 0 && tp->last_hm->touch_count != 0)
    tp->filter_out = FILTER_OUT(hm, tp->last_hm);
  else
    tp->filter_out = false;

#ifdef DEBUG
  pr_info("Get %d contacts.\n", tp->touch_count);
#endif
	for (i = 0; i < tp->device_info->max_contacts; i++) {
    if (i < tp->touch_count) {
      x = tp->contacts[i].x;
      y = tp->contacts[i].y;

      if (tp->config->invert_x)
        x = SCALE_INT(hm->width-1) - x;
      if (tp->config->invert_y)
        y = SCALE_INT(hm->height-1) - y;

  		tp->inputs[i].x = fix_zoom(x, SCALE_INT(hm->width), IPTS_MAX_X);
  		tp->inputs[i].y = fix_zoom(y, SCALE_INT(hm->height), IPTS_MAX_Y);
      tp->inputs[i].major = fix_zoom(tp->contacts[i].major, hm->diagonal, IPTS_DIAGONAL);
      tp->inputs[i].pressure = tp->contacts[i].max_v;
    }
		tp->inputs[i].index = tp->contacts[i].index;
		tp->inputs[i].slot = tp->contacts[i].slot;
    tp->inputs[i].area = tp->contacts[i].area;
		tp->inputs[i].is_stable = tp->contacts[i].area >= STABLE_CONTACT_AREA;
		tp->inputs[i].contact = &tp->contacts[i];
#ifdef DEBUG
    pr_info("Raw data: slot:%d,index:%d, contact(%d,%d), revert(%d,%d),output(%d,%d)\n",
        tp->inputs[i].slot, tp->inputs[i].index,
        tp->contacts[i].x,tp->contacts[i].y, x,y, tp->inputs[i].x,tp->inputs[i].y);
#endif
	}

#ifdef DEBUG
  pr_info("filter_out:%d, bell_intervals:%u\n", tp->filter_out, hm->bell - tp->last_hm->bell);
#endif
}

struct heatmap *iptsd_touch_processing_get_heatmap(struct iptsd_touch_processor *tp, int w, int h)
{
  struct heatmap *tmp_hm = tp->hm;
  if(!tp->filter_out) {
    tp->hm = tp->last_hm;
    tp->last_hm = tmp_hm;
  }
	if(heatmap_init(tp->hm, w, h, tp->config->touch_threshold)){
    pr_err("No memory for heatmap\n");
  };

	return tp->hm;
}

int iptsd_touch_processing_init(struct iptsd_touch_processor *tp)
{
	int  max_contacts = tp->device_info->max_contacts;
  tp->hm = kmalloc(sizeof(struct heatmap), GFP_KERNEL);
  if (!tp->hm)
    return -ENOMEM;
  tp->hm->data = NULL;
  tp->hm->visited = NULL;
  tp->last_hm = kmalloc(sizeof(struct heatmap), GFP_KERNEL);
  if (!tp->last_hm)
    return -ENOMEM;
  tp->last_hm->data = NULL;
  tp->last_hm->visited = NULL;
	tp->contacts = kmalloc(max_contacts * sizeof(struct contact), GFP_KERNEL);
	if (!tp->contacts)
		return -ENOMEM;

	tp->inputs = kzalloc(max_contacts * sizeof(struct iptsd_touch_input), GFP_KERNEL);
	if (!tp->inputs)
		return -ENOMEM;

	return 0;
}

void iptsd_touch_processing_free(struct iptsd_touch_processor *tp)
{
	if (tp->contacts)
		kfree(tp->contacts);

	if (tp->inputs)
		kfree(tp->inputs);
  release_heatmap(tp->hm);
  release_heatmap(tp->last_hm);
}
