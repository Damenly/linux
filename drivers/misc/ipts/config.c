#include "config.h"

struct surface_touch_config configs[] = {
  {
    .vendor_id = 0x1B96,
    .product_id = 0x005E,
    .name = "surface book 1",
    .invert_x = false,
    .invert_y = true,
    .width = 2853,
    .height = 1902,
  },{
    .vendor_id = 0x045E,
    .product_id = 0x0021,
    .name = "surface book 2-13",
    .invert_x = false,
    .invert_y = true,
    .width = 2853,
    .height = 1902,
  },{
    .vendor_id = 0x045E,
    .product_id = 0x0020,
    .name = "surface book 2-15",
    .invert_x = false,
    .invert_y = false,
    .width = 3171,
    .height = 2114,
  },{
    .vendor_id = 0x045E,
    .product_id = 0x09B2,
    .name = "surface book 3-13",
    .invert_x = false,
    .invert_y = true,
    .width = 2953,
    .height = 1902,
  },{
    .vendor_id = 0x045E,
    .product_id = 0x09B1,
    .name = "surface book 3-15",
    .invert_x = false,
    .invert_y = false,
    .width = 3171,
    .height = 2114,
  },{
    .vendor_id = 0x1B96,
    .product_id = 0x0979,
    .name = "surface laptop 1-2",
    .invert_x = false,
    .invert_y = false,
    .width = 2853,
    .height = 1902,
  },{
  },{
    .vendor_id = 0x045E,
    .product_id = 0x0984,
    .name = "surface book 3-15",
    .invert_x = false,
    .invert_y = false,
    .width = 3171,
    .height = 2114,
  },{
    .vendor_id = 0x01B96,
    .product_id = 0x006A,
    .name = "surface pro4 a",
    .invert_x = true,
    .invert_y = true,
    .width = 2598,
    .height = 1732,
  },{
    .vendor_id = 0x01B96,
    .product_id = 0x0021,
    .name = "surface pro4 b",
    .invert_x = true,
    .invert_y = true,
    .width = 2598,
    .height = 1732,
  },{
    .vendor_id = 0x01B96,
    .product_id = 0x001F,
    .name = "surface pro5",
    .invert_x = true,
    .invert_y = true,
    .width = 2598,
    .height = 1732,
  },{
    .vendor_id = 0x045E,
    .product_id = 0x001F,
    .name = "surface pro6",
    .invert_x = true,
    .invert_y = true,
    .width = 2598,
    .height = 1732,
  },{
    .vendor_id = 0x045E,
    .product_id = 0x099F,
    .name = "surface pro7",
    .invert_x = true,
    .invert_y = true,
    .width = 2598,
    .height = 1732,
  },
};

struct surface_touch_config* get_match_config(u16 vendor, u16 product)
{
  int i;
  struct surface_touch_config *result = NULL;
  for ( i=0; i< sizeof(configs)/sizeof(struct surface_touch_config); i++) {
    if (vendor == configs[i].vendor_id && product == configs[i].product_id) {
      result = &configs[i];
      break;
    }
  }
  if (!result->touch_threshold)
    result->touch_threshold = CONTACT_TOUCH_THRESHOLD;
  if (!result->stability_threshold)
    result->stability_threshold = CONTACT_STABILITY_THRESHOLD;

  return result;
}
