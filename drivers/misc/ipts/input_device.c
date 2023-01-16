//#define DEBUG
#include <linux/input.h>
#include <linux/input/mt.h>
#include <linux/slab.h>
#include "context.h"
#include "input_data.h"
#include "input_device.h"
#include "heatmap.h"
#include "touch-processing.h"
#include "math.h"
#include "config.h"
#include "contact.h"
#include "receiver.h"
#define MAXNAME 32

size_t max_data_size;

bool is_over_boundary(size_t offset) {
  return max_data_size <= offset;
}

static int input_devices_res(int virt, int phys)
{
  return fix_div_round(virt * 10, phys);
}

int init_stylus_device(struct ipts_context *ipts)
{
  struct input_dev *stylus;
  int ret, res_x, res_y;
  stylus = devm_input_allocate_device(ipts->dev);
  if (stylus == NULL)
    return -ENOMEM;
  stylus->name = kasprintf(GFP_KERNEL, "%s:%s",ipts->config->name, "Stylus");
  stylus->phys = "intel_mei";
  stylus->id.bustype = BUS_VIRTUAL;
  stylus->id.vendor = ipts->device_info.vendor_id;
  stylus->id.product = ipts->device_info.device_id;
  stylus->id.version = ipts->device_info.fw_rev;
  stylus->dev.parent = ipts->dev;
  stylus->evbit[0] = BIT(EV_ABS) | BIT(EV_KEY);
  __set_bit(INPUT_PROP_DIRECT, stylus->propbit);
  __set_bit(INPUT_PROP_POINTER, stylus->propbit);
  input_set_capability(stylus, EV_KEY, BTN_TOUCH);
  input_set_capability(stylus, EV_KEY, BTN_STYLUS);
  input_set_capability(stylus, EV_KEY, BTN_TOOL_PEN);
  input_set_capability(stylus, EV_KEY, BTN_TOOL_RUBBER);

  res_x = input_devices_res(IPTS_MAX_X, ipts->config->width);
  res_y = input_devices_res(IPTS_MAX_Y, ipts->config->height);

  input_set_abs_params(stylus, ABS_X, 0, IPTS_MAX_X, 0, 0);
  input_abs_set_res(stylus, ABS_X, res_x);
  input_set_abs_params(stylus, ABS_Y, 0, IPTS_MAX_Y, 0, 0);
  input_abs_set_res(stylus, ABS_Y, res_y);
  input_set_abs_params(stylus, ABS_MISC, 0, 65535, 0, 0);
  input_set_abs_params(stylus, ABS_PRESSURE, 0, 4096, 0, 0);
  ret = input_register_device(stylus);
  if (ret) {
    return ret;
  }
  ipts->stylus_dev = stylus;
  return 0;
}

int init_touch_device(struct ipts_context *ipts)
{
  struct input_dev *input;
  int ret, res_x, res_y;
  input  = devm_input_allocate_device(ipts->dev);
  if (input == NULL)
    return -ENOMEM;

  res_x = input_devices_res(IPTS_MAX_X, ipts->config->width);
  res_y = input_devices_res(IPTS_MAX_Y, ipts->config->height);

  input->name = kasprintf(GFP_KERNEL, "%s:%s",ipts->config->name, "TouchScreen");
  input->phys = "intel_mei";
  input->id.bustype = BUS_VIRTUAL;
  input->id.vendor = ipts->device_info.vendor_id;
  input->id.product = ipts->device_info.device_id;
  input->id.version = ipts->device_info.fw_rev;
  input->dev.parent = ipts->dev;
  input->evbit[0] = BIT(EV_ABS) | BIT(EV_KEY);
  input_mt_init_slots(input, ipts->device_info.max_contacts,
			    INPUT_MT_DIRECT);
  input_set_capability(input, EV_KEY, BTN_TOUCH);
  __set_bit(INPUT_PROP_DIRECT, input->propbit);
  input_set_abs_params(input, ABS_X, 0, IPTS_MAX_X, 0, 0);
  input_abs_set_res(input, ABS_X, res_x);
  input_set_abs_params(input, ABS_Y, 0, IPTS_MAX_Y, 0, 0);
  input_abs_set_res(input, ABS_Y, res_y);
  input_set_abs_params(input, ABS_MT_TRACKING_ID, 0, ipts->device_info.max_contacts, 0, 0);
  input_set_abs_params(input, ABS_MT_POSITION_X, 0, IPTS_MAX_X, 0, 0);
  input_abs_set_res(input, ABS_MT_POSITION_X, res_x);
  input_set_abs_params(input, ABS_MT_POSITION_Y, 0, IPTS_MAX_Y, 0, 0);
  input_abs_set_res(input, ABS_MT_POSITION_Y, res_y);
  input_set_abs_params(input, ABS_PRESSURE, 0, 200, 0, 0);
  input_set_abs_params(input, ABS_MT_TOOL_TYPE, 0, MT_TOOL_MAX, 0, 0);
  input_set_abs_params(input, ABS_MT_TOOL_X, 0, IPTS_MAX_X, 0, 0);
  input_abs_set_res(input, ABS_MT_TOOL_X, res_x);
  input_set_abs_params(input, ABS_MT_TOOL_Y, 0, IPTS_MAX_Y, 0, 0);
  input_abs_set_res(input, ABS_MT_TOOL_Y, res_y);
  input_set_abs_params(input, ABS_MT_TOUCH_MAJOR, 0, IPTS_DIAGONAL, 0, 0);
  input_abs_set_res(input, ABS_MT_TOUCH_MAJOR, input_devices_res(IPTS_DIAGONAL, fix_hypot(ipts->config->width, ipts->config->height)));
  ret = input_register_device(input);
  if (ret) {
    return ret;
  }
  ipts->tp.config = ipts->config;
  ipts->tp.device_info = &ipts->device_info;
  ret = iptsd_touch_processing_init(&ipts->tp);
  if (ret)
    dev_warn(ipts->dev, "touch process init error, may not support multitouch.\n");
  ipts->touch_dev = input;

  return 0;
}

int init_input_devices(struct ipts_context *ipts)
{
  int ret = 0;
  if (ipts->touch_dev != NULL)
    return 0;
  ipts->config = get_match_config(ipts->device_info.vendor_id, ipts->device_info.device_id);
  if (ipts->config == NULL)
    return -ENODEV;
  ret = setup_contact_buff();
  if (ret) {
    dev_err(ipts->dev,"No memory for contact buffer\n");
    return ret;
  }
  max_data_size = ipts->device_info.data_size;
  ret = init_touch_device(ipts);
  if (ret) {
    dev_err(ipts->dev, "Error creating touch input device, ret:%d\n", ret);
    return ret;
  }
  ret = init_stylus_device(ipts);
  if (ret)
    dev_warn(ipts->dev, "Error creating stylus device, ret:%d\n", ret);
  return 0;
}

void remove_input_devices(struct ipts_context *ipts)
{
  if (ipts->touch_dev != NULL) {
    input_unregister_device(ipts->touch_dev);
    ipts->touch_dev = NULL;
  }
  if (ipts->stylus_dev != NULL) {
    input_unregister_device(ipts->stylus_dev);
    ipts->stylus_dev = NULL;
  }
  release_contact_buff();
  iptsd_touch_processing_free(&ipts->tp);
}

void dump_data(uint8_t *data, size_t offset, size_t size) {
 #ifdef DEBUG
  int i;
  for ( i = 1; i <= size; i++) {
    printk(KERN_CONT "%2.2x ", data[offset + i]);
    if ( i % 8 == 0)
      printk(KERN_CONT "\n");
  }
 #endif
 return;
}

int report_hid_single_touch(struct ipts_context *ipts, u8 *data, size_t *offset)
{
  struct input_dev *touch = ipts->touch_dev;
  struct ipts_singletouch_data *sdata;
  int x,y;
  uint8_t *report = (uint8_t *) (data + *offset);
  *offset += sizeof(uint8_t);
  if (*report != IPTS_SINGLETOUCH_REPORT_ID) {
    dev_dbg(&touch->dev, "Read reportid:%u, we only handle singletouch inputs", *report);
    dump_data(data, *offset, sizeof(struct ipts_singletouch_data));
    return 0;
  }
  sdata = (struct ipts_singletouch_data *) (data + *offset);
  input_mt_slot(touch, 0);
  if (sdata->touch) {
    x = (int) (sdata->x * IPTS_MAX_X / IPTS_SINGLETOUCH_MAX_VALUE);
    y = (int) (sdata->y * IPTS_MAX_Y / IPTS_SINGLETOUCH_MAX_VALUE);
    dev_dbg(&touch->dev, "get touch (%u, %u)", x, y);
    input_event(touch, EV_ABS, ABS_MT_TRACKING_ID, 0);
    input_event(touch, EV_ABS, ABS_MT_POSITION_X, x);
    input_event(touch, EV_ABS, ABS_MT_POSITION_Y, y);
    input_event(touch, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
    input_event(touch, EV_ABS, ABS_MT_TOOL_X, x);
    input_event(touch, EV_ABS, ABS_MT_TOOL_Y, y);
    input_event(touch, EV_KEY, BTN_TOUCH, 1);
    input_event(touch, EV_ABS, ABS_X, x);
    input_event(touch, EV_ABS, ABS_Y, y);
  }else{
    input_event(touch, EV_ABS, ABS_MT_TRACKING_ID, -1);
    input_event(touch, EV_KEY, BTN_TOUCH, 0);
  }
  input_mt_sync_frame(touch);
  input_sync(touch);
  return 0;
}

int report_tp(struct input_dev *touch, struct iptsd_touch_processor *tp)
{
  int i;
  struct iptsd_touch_input *in;
  for (i = 0; i<tp->device_info->max_contacts; i++) {
    in = &tp->inputs[i];
    input_mt_slot(touch, in->slot);
    if (i < tp->touch_count) {
      dev_dbg(&touch->dev, "tp slot:%d, x:%d, y:%d, is_stable:%d, area:%d", in->slot, in->x, in->y, in->is_stable, in->area);
      input_event(touch, EV_ABS, ABS_MT_TRACKING_ID, in->index);
      input_event(touch, EV_ABS, ABS_MT_POSITION_X, in->x);
      input_event(touch, EV_ABS, ABS_MT_POSITION_Y, in->y);
      input_event(touch, EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
      input_event(touch, EV_ABS, ABS_PRESSURE, in->pressure);
      input_event(touch, EV_ABS, ABS_MT_TOUCH_MAJOR, in->major);
    } else {
      input_event(touch, EV_ABS, ABS_MT_TRACKING_ID, -1);
    }
  }
  return 0;
}

int report_touch(struct ipts_context *ipts, size_t frame_size, uint8_t *data, size_t offset)
{
  size_t size = 0;
  size_t frame_offset = offset;
  struct heatmap *hm = NULL;
  struct ipts_report *report;
  struct ipts_heatmap_dim *dim;
  struct input_dev *touch = ipts->touch_dev;
  struct iptsd_touch_processor *tp = &ipts->tp;
  while (size < frame_size) {
    report = (struct ipts_report *) (data + frame_offset);
    frame_offset += sizeof(struct ipts_report);
    switch (report->type) {
    case IPTS_REPORT_TYPE_TOUCH_HEATMAP_DIM:
      dim = (struct ipts_heatmap_dim *) (data + frame_offset);
      dev_dbg(&touch->dev,"ipts report payload:touch:heatmap_dim, width:%u, height:%u\n", dim->width, dim->height);
      frame_offset += sizeof(struct ipts_heatmap_dim);
      hm = iptsd_touch_processing_get_heatmap(tp, dim->width, dim->height);
      break;
    case IPTS_REPORT_TYPE_TOUCH_HEATMAP:
      if (!hm)
        break;
      if (hm->size > report->size) {
        dev_err(&touch->dev, "Got wrong hm size, hm size:%u, report size:%u\n", hm->size, report->size);
        return 0;
      }
      hm->data = data + frame_offset;
      hm->bell = ipts->current_doorbell;
      iptsd_touch_processing_inputs(tp, hm);

      dev_dbg(&touch->dev,"ipts report payload:filter:%d, touch count:%d, bell:%u\n", tp->filter_out, tp->touch_count, ipts->current_doorbell);
      if(tp->filter_out) {
        return 0;
      }
      report_tp(touch, tp);
      frame_offset += hm->size;
      break;
    default:
      dev_dbg(&touch->dev,"report touch unknow type:%d, size:%llu\n", report->type, report->size);
      dump_data(data, frame_offset, report->size);
      frame_offset += report->size;
      if(is_over_boundary(frame_offset)) {
        dev_err(&touch->dev, "The touchscreen's offset is out of boundary. offset:%u\n", frame_offset);
        return 0;
      }
    }
    size += report->size + sizeof(struct ipts_report);
  }

  input_mt_sync_frame(touch);
  input_sync(touch);
  return 0;
}

void stylus_data_v1_to_v2(struct ipts_stylus_data_v1 *v1, struct ipts_stylus_data_v2 *v2)
{
  v2->mode = v1->mode;
  v2->x = v1->x;
  v2->y = v1->y;
  v2->pressure = v1->pressure * 4;
  v2->altitude = 0;
  v2->azimuth = 0;
  v2->timestamp = 0;
}

void report_stylus_data(struct input_dev *stylus, struct iptsd_touch_processor *tp, struct ipts_stylus_data_v2 *data)
{
  int prox = (data->mode & IPTS_STYLUS_REPORT_MODE_PROX) >> 0;
  int touch = (data->mode & IPTS_STYLUS_REPORT_MODE_TOUCH) >> 1;
  int button = (data->mode & IPTS_STYLUS_REPORT_MODE_BUTTON) >> 2;
  int rubber = (data->mode & IPTS_STYLUS_REPORT_MODE_RUBBER) >> 3;
  int btn_pen = prox * (1 - rubber);
  int btn_rubber = prox * rubber;
  input_event(stylus, EV_KEY, BTN_TOUCH, touch);
  input_event(stylus, EV_KEY, BTN_TOOL_PEN, btn_pen);
  input_event(stylus, EV_KEY, BTN_TOOL_RUBBER, btn_rubber);
  input_event(stylus, EV_KEY, BTN_STYLUS, button);
  input_event(stylus, EV_ABS, ABS_X, data->x);
  input_event(stylus, EV_ABS, ABS_Y, data->y);
  input_event(stylus, EV_ABS, ABS_PRESSURE, data->pressure);
  input_event(stylus, EV_ABS, ABS_MISC, data->timestamp);
  input_mt_sync_frame(stylus);
  input_sync(stylus);
}

int report_stylus(struct input_dev *stylus, struct iptsd_touch_processor *tp, size_t frame_size, u8 *data, size_t offset)
{
  size_t size = 0;
  struct ipts_report *report;
  struct ipts_stylus_report *sreport;
  struct ipts_stylus_data_v1 *data_v1;
  struct ipts_stylus_data_v2 *data_v2 = NULL;
  struct ipts_stylus_data_v2 temp_data_v2;
  size_t frame_offset = offset;
  uint8_t i;
  while (size < frame_size) {
    report = (struct ipts_report *) (data + frame_offset);
    frame_offset += sizeof(struct ipts_report);
    if (report->type == IPTS_REPORT_TYPE_STYLUS_V1 || report->type == IPTS_REPORT_TYPE_STYLUS_V2) {
      sreport = (struct ipts_stylus_report *) (data + frame_offset);
      frame_offset += sizeof(struct ipts_stylus_report);
      for ( i=0; i<sreport->elements; i++) {
        if (report->type == IPTS_REPORT_TYPE_STYLUS_V1) {
          dev_dbg(&stylus->dev,"ipts report payload:stylus:v1\n");
          data_v1 = (struct ipts_stylus_data_v1 *)(data + frame_offset);
          frame_offset += sizeof(struct ipts_stylus_data_v1);
          stylus_data_v1_to_v2(data_v1, &temp_data_v2);
          data_v2 = &temp_data_v2;
        }else if (report->type == IPTS_REPORT_TYPE_STYLUS_V2) {
          dev_dbg(&stylus->dev,"ipts report payload:stylus:v2\n");
          data_v2 = (struct ipts_stylus_data_v2 *)(data + frame_offset);
          frame_offset += sizeof(struct ipts_stylus_data_v2);
        }else {
          break;
        }
        if (data_v2){
          report_stylus_data(stylus, tp, data_v2);
          data_v2 = NULL;
        }
      }
    }else{
      frame_offset += report->size;
      if(is_over_boundary(frame_offset)) {
        dev_err(&stylus->dev, "The stylus's offset is out of boundary. offset:%u\n", frame_offset);
        return 0;
      }
    }
    size += report->size + sizeof(struct ipts_report);
  }
  return 0;
}

int report_payload(struct ipts_context *ipts, uint8_t *data, size_t *offset)
{
  uint32_t i;
  int ret;
  struct ipts_payload_frame *frame;
  struct ipts_payload *payload = (struct ipts_payload *)(data + *offset);
  *offset += sizeof(struct ipts_payload);
  for ( i=0; i < payload->frames; i++) {
    frame = (struct ipts_payload_frame *)(DATA_PT(ipts) + *offset);
    *offset += sizeof(struct ipts_payload_frame);
    switch (frame->type) {
    case IPTS_PAYLOAD_FRAME_TYPE_STYLUS:
      dev_dbg(ipts->dev,"ipts report payload:stylus\n");
      ret = report_stylus(ipts->stylus_dev, &ipts->tp, frame->size, data, *offset);
      break;
    case IPTS_PAYLOAD_FRAME_TYPE_TOUCH:
      dev_dbg(ipts->dev,"ipts report payload:touch\n");
      ret = report_touch(ipts, frame->size, data, *offset);
      break;
    default:
      dev_dbg(ipts->dev, "Unknow frame type:%u\n", frame->type);
      *offset += (size_t) frame->size;
    }
    if (is_over_boundary(*offset)){
      dev_dbg(ipts->dev, "over boundry offset:%u\n", *offset);
      return 0;
    }
    if (ret < 0)
      dev_err(ipts->dev, "Failed to handle payload frame: ret:%d\n", ret);
  }
  return 0;
}

int report_data(struct ipts_context *ipts)
{
  size_t offset = sizeof(struct ipts_data);
  struct ipts_data* data = IPTS_DATA_PT(ipts);
  dev_dbg(ipts->dev, "report doorbell:%u\n", ipts->current_doorbell);
  switch (data->type) {
  case IPTS_DATA_TYPE_PAYLOAD:
    dev_dbg(ipts->dev,"ipts report payload.\n");
    return report_payload(ipts, DATA_PT(ipts), &offset);
  case IPTS_DATA_TYPE_HID_REPORT:
    dev_dbg(ipts->dev,"ipts report hid.\n");
    return report_hid_single_touch(ipts, DATA_PT(ipts), &offset);
  default:
    dev_dbg(ipts->dev, "Failed to parse data type:%d\n", data->type);
  }
  return 0;
}
