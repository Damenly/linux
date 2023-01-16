// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>

#include "contact.h"
#include "heatmap.h"
#include "math.h"
#define MAX_SLOTS 10

static void cluster_add(struct cluster *c, int x, int y, int w)
{
	c->x += w * x;
	c->y += w * y;
	c->w += w;
  c->area++;
  if (c->max_x < x)
    c->max_x = x;
  if (c->max_y < y)
    c->max_y = y;
  if (c->min_x > x)
    c->min_x = x;
  if (c->min_y > y)
    c->min_y = y;

	if (c->max_v < w)
		c->max_v = w;
}

static void cluster_mean(struct cluster *c, int *x, int *y)
{
	*x = fix_div_long_round(SCALE_INT(c->x), c->w);
	*y = fix_div_long_round(SCALE_INT(c->y), c->w);
}

bool add_to_surface_test_palm(struct tp_surface *tp, int x, int y)
{
  if (tp->pt == PALM_AREA_THRESHOLD) // if a touch surface's area is above PALM_AREA_THRESHOLD, it is a plam.
    return true;
  tp->info[tp->pt].x = x;
  tp->info[tp->pt].y = y;
  tp->pt++;
  return false;
}

bool pop_from_surface(struct tp_surface *tp, int *x, int *y)
{
  if(tp->pt < 1)
    return false;
  tp->pt--;
  *x = tp->info[tp->pt].x;
  *y = tp->info[tp->pt].y;
  return true;
}

static void __cluster_get(struct heatmap *hm, int x, int y, struct cluster *c, struct tp_surface *tp, uint8_t *index)
{
	int v = heatmap_value(hm, x, y);

	if (!heatmap_is_touch(hm, x, y)) {
    heatmap_set_visited(hm, x, y, VISITED_INDEX);
		return;
  }
	if (heatmap_get_visited(hm, x, y))
		return;

	cluster_add(c, x, y, v);
  if(add_to_surface_test_palm(tp, x ,y)) // set the palm touch to 0xFF, we don't transfer it to a contact.
    *index = PALM_INDEX;
	heatmap_set_visited(hm, x, y, *index);

	__cluster_get(hm, x + 1, y, c, tp, index);
	__cluster_get(hm, x - 1, y, c, tp, index);
	__cluster_get(hm, x, y + 1, c, tp, index);
	__cluster_get(hm, x, y - 1, c, tp, index);
}

void reset_cluster(struct cluster *c) {
  memset(c, 0 ,sizeof(struct cluster));
  c->min_x = MAX_INT;
  c->min_y = MAX_INT;
}

static void cluster_get(struct heatmap *hm, int x, int y, struct cluster *c, struct tp_surface *tp, uint8_t *touch_index)
{

  reset_cluster(c);
  tp->pt = 0;
	__cluster_get(hm, x, y, c, tp, touch_index);

}

void contact_from_cluster(struct cluster *cluster, struct contact *c, uint8_t index)
{

	cluster_mean(cluster, &c->x, &c->y);

	c->max_v = cluster->max_v;
  c->area = cluster->area;
  c->index = index;
  c->slot = index;
  c->major = fix_hypot(cluster->max_x - cluster->min_x, cluster->max_y - cluster->min_y);
}

int find_trace_index(struct heatmap *last_hm, struct tp_surface *tp)
{
  int i;
  uint8_t touch_index;
  for ( i=0; i< tp->pt; i++) {
    touch_index = heatmap_get_visited(last_hm, tp->info[i].x, tp->info[i].y);
    if (touch_index && touch_index != VISITED_INDEX)
      return touch_index;
  }
  return 0;
}

void refill_touch(struct heatmap *hm, struct tp_surface *tp, uint8_t index)
{
  int x,y;
  while(pop_from_surface(tp, &x, &y))
    heatmap_set_visited(hm, x, y, index);
}

struct tp_surface* reset_surface(struct tp_surface* tp) {
  tp->pt = 0;
  return tp;
}

struct tp_surface *tp_stack = NULL;

void release_contact_buff(void) {
  if (tp_stack != NULL)
    kfree(tp_stack);
}

int setup_contact_buff(void) {
  if (tp_stack == NULL) {
     tp_stack = kmalloc(sizeof(struct tp_surface) * MAX_SLOTS, GFP_KERNEL);
     if (!tp_stack)
       return -ENOMEM;
   }
   return 0;
}

#ifdef DEBUG
void dump_slots(uint8_t *slots) {
  pr_info("slots:[%u,%u,%u,%u,%u\n       %u,%u,%u,%u,%u]\n",
    slots[0],slots[1],slots[2],slots[3],slots[4],
    slots[5],slots[6],slots[7],slots[8],slots[9]);
}

void dump_tp_hm(struct tp_surface *tp, struct heatmap *hm) {
  int i;
  for (i = 0; i < tp->pt; i++)
    pr_info("tp (%d,%d, hm visited:%u)\n", tp->info[i].x, tp->info[i].y,
          heatmap_get_visited(hm,tp->info[i].x, tp->info[i].y));
}
#endif

int get_new_slot(uint8_t *slots) {
  int i;
  for (i=0; i<MAX_SLOTS;i++)
    if (slots[i] == 0){
      slots[i] = 1;
      return i;
    }
  return MAX_SLOTS;
}

uint8_t contacts_get(struct heatmap *hm, struct heatmap *last_hm, struct contact *contacts, int count)
{
	int i, x, y;
  uint8_t c = 1;
  struct cluster cluster;
  uint8_t index;
  uint8_t slot_handled[MAX_SLOTS];
  struct contact* c_stack[MAX_SLOTS];
  struct tp_surface *tp;
  int stack_pt = 0;
  uint8_t touch_index;
	if (count == 0)
		return 0;
  memset(hm->visited, 0, hm->size);
  memset(slot_handled, 0, MAX_SLOTS);
  tp = reset_surface(&tp_stack[0]);
  if (!hm->data)
    goto end;
	for (x = 0; x < hm->width; x++) {
		for (y = 0; y < hm->height; y++) {
			if (!heatmap_is_touch(hm, x, y))
				continue;

			if (heatmap_get_visited(hm, x, y))
				continue;
      touch_index = c;
			cluster_get(hm, x, y, &cluster, tp, &touch_index);
      if (cluster.area) {  // there is a real touch
        if (touch_index == PALM_INDEX) {  //the touch is palm
          refill_touch(hm, tp, PALM_INDEX);
          continue;
        }
        index = find_trace_index(last_hm, tp); //trace the history.
        if (index == PALM_INDEX){  //it is a palm
          refill_touch(hm, tp, PALM_INDEX);
          continue;
        }
        if (index) {  //it is in a serial touches.
          if (index != c)
            refill_touch(hm, tp, (uint8_t)index);
#ifdef DEBUG
          dump_tp_hm(tp, last_hm);
          pr_info("trace touch index:%u", index);
#endif
          slot_handled[index-1] = 1;
			    contact_from_cluster(&cluster, &contacts[c - 1], index-1);
        }else { // it is a new touch
          contact_from_cluster(&cluster, &contacts[c - 1], c - 1);
          c_stack[stack_pt] = &contacts[c - 1];
          stack_pt++;
          tp = reset_surface(&tp_stack[stack_pt]);
        }
#ifdef DEBUG
          pr_info("touch index:%d, (%d,%d)\n", c, contacts[c - 1].x, contacts[c - 1].y);
#endif
        c++;
      }

			if (c > count)
				break;
		}
	}
  for (i = 0; i<stack_pt; i++) {
    x = get_new_slot(slot_handled);
#ifdef DEBUG
    pr_info("get new touch index:%d\n", x + 1);
#endif
    c_stack[i]->slot = x;
    c_stack[i]->index = x;
    refill_touch(hm, &tp_stack[i], (uint8_t) x + 1); //record for history trace.
    reset_surface(&tp_stack[i]);
  }
#ifdef DEBUG
  dump_slots(slot_handled);
#endif
end:
  c--; //restore the real count of contacts.
  for (i = c; i < count; i++){
    x = get_new_slot(slot_handled);
    //reset the non touch slots;
    contacts[i].slot = x;
    contacts[i].index = -1;
    contacts[i].area = 0;
  }
  hm->touch_count = c;
	return c;
}
