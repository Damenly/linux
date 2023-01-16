// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2020 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */
//#define DEBUG
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/mei_cl_bus.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "context.h"
#include "control.h"
#include "protocol.h"
#include "receiver.h"
#include "input_data.h"
#include "uapi.h"

#define IPTS_DRV_NAME "ipts"

bool devmode;
module_param(devmode, bool, 0644);

static int ipts_mei_set_dma_mask(struct mei_cl_device *cldev)
{
	int ret;

	ret = dma_coerce_mask_and_coherent(&cldev->dev, DMA_BIT_MASK(64));
	if (!ret)
		return 0;

	return dma_coerce_mask_and_coherent(&cldev->dev, DMA_BIT_MASK(32));
}

static void input_request_dispatch(struct work_struct *work)
{
  struct ipts_context *ipts = container_of(to_delayed_work(work),
             struct ipts_context, request_work);
  u32 doorbell;
  int diff;
  if (ipts->touch_dev == NULL || ipts->request_status != IPTS_REQUEST_FRAME ||
      ipts->doorbell.address == NULL || ipts->status != IPTS_HOST_STATUS_STARTED
      ) {
    dev_dbg(ipts->dev, "Someting wrong: touch:%p, request_status:%d,doorbell:%p, status:%d\n",
      ipts->touch_dev, ipts->request_status, ipts->doorbell.address, ipts->status);
    goto end;
  }
  doorbell = GET_DOORBELL(ipts);
  if (ipts->current_doorbell == doorbell) {
    dev_dbg(ipts->dev, "Same doorbell:%u\n", doorbell);
    goto end;
  }
  ipts->request_status = IPTS_HANDLE_FRAME;
  diff = doorbell - ipts->current_doorbell;
  dev_dbg(ipts->dev, "get new doorbells:%d, target doorbell:%u\n", diff, doorbell);
  if (diff > 10 || diff < 0){
    ipts->current_doorbell = doorbell;
    ipts_receiver_flush(ipts);
  } else {
    for (; diff > 0; diff-- ){
      report_data(ipts);
      ipts_control_send_feedback(ipts, GET_BUFF(ipts));
      ipts->current_doorbell++;
    }
  }
  ipts->request_status = IPTS_REQUEST_FRAME;
  schedule_delayed_work(&ipts->request_work, REFRESH_DELAY);
  return;

end:
  schedule_delayed_work(&ipts->request_work, REFERSH_NO_INPUT);
}

static int ipts_mei_probe(struct mei_cl_device *cldev,
			  const struct mei_cl_device_id *id)
{
	int ret;
	struct ipts_context *ipts;

	if (ipts_mei_set_dma_mask(cldev)) {
		dev_err(&cldev->dev, "Failed to set DMA mask for IPTS\n");
		return -EFAULT;
	}

	ret = mei_cldev_enable(cldev);
	if (ret) {
		dev_err(&cldev->dev, "Failed to enable MEI device: %d\n", ret);
		return ret;
	}

	ipts = kzalloc(sizeof(*ipts), GFP_KERNEL);
	if (!ipts) {
		mei_cldev_disable(cldev);
		return -ENOMEM;
	}

	ipts->cldev = cldev;
	ipts->dev = &cldev->dev;
	ipts->status = IPTS_HOST_STATUS_STOPPED;
  if (!devmode) {
    ipts->current_doorbell = 0xFFFF;
    ipts->request_status = IPTS_IDLE;
    ipts->touch_dev = NULL;
    ipts->stylus_dev = NULL;
    ipts->config = NULL;
    INIT_DELAYED_WORK(&ipts->request_work, input_request_dispatch);
  }
	mei_cldev_set_drvdata(cldev, ipts);
	ret = mei_cldev_register_rx_cb(cldev, ipts_receiver_callback);
  if (ret)
    dev_warn(&cldev->dev,"register rx error:%d ,ipts may not work!", ret);
  ret = mei_cldev_register_notif_cb(cldev, ipts_mei_notif);
  if (ret)
     dev_warn(&cldev->dev,"register notif error:%d", ret);
  ret = ipts_control_start(ipts);
  if (ret){
    dev_err(&cldev->dev, "Error to start ipts, ret:%d\n", ret);
    return ret;
  }
  pr_info("ipts driver probed.");
	return 0;
}

static void ipts_mei_remove(struct mei_cl_device *cldev)
{
	int i;
	struct ipts_context *ipts = mei_cldev_get_drvdata(cldev);
  if (!devmode) {
    if (ipts->request_status != IPTS_IDLE) {
      cancel_delayed_work_sync(&ipts->request_work);
      ipts->request_status = IPTS_IDLE;
    }
    remove_input_devices(ipts);
  }
	ipts_control_stop(ipts);

	for (i = 0; i < 20; i++) {
		if (ipts->status == IPTS_HOST_STATUS_STOPPED)
			break;

		msleep(25);
	}

	mei_cldev_disable(cldev);
	kfree(ipts);
  pr_info("ipts driver removed.");
}

static struct mei_cl_device_id ipts_mei_device_id_table[] = {
	{ "", IPTS_MEI_UUID, MEI_CL_VERSION_ANY },
	{},
};
MODULE_DEVICE_TABLE(mei, ipts_mei_device_id_table);

#ifdef CONFIG_PM_SLEEP
static int ipts_suspend(struct device *dev)
{
  pr_info ("ipts driver suspend");
  return 0;
}

static int ipts_resume(struct device *dev)
{
  pr_info("ipts driver resume");
  return 0;
}
static SIMPLE_DEV_PM_OPS(ipts_pm_ops, ipts_suspend, ipts_resume);
#define IPTS_PM_OPS (&ipts_pm_ops)
#else
#define IPTS_PM_OPS NULL
#endif

static struct mei_cl_driver ipts_mei_driver = {
  .driver = {
    .pm = IPTS_PM_OPS,
  },
	.id_table = ipts_mei_device_id_table,
	.name = IPTS_DRV_NAME,
	.probe = ipts_mei_probe,
	.remove = ipts_mei_remove,
};

static int __init ipts_mei_init(void)
{
	int ret;

  if (devmode) {
	  ret = ipts_uapi_init();
	  if (ret)
		  return ret;
  }
	ret = mei_cldev_driver_register(&ipts_mei_driver);
	if (ret && devmode) {
		ipts_uapi_free();
		return ret;
	}

	return 0;
}

static void __exit ipts_mei_exit(void)
{
	mei_cldev_driver_unregister(&ipts_mei_driver);
  if (devmode)
	  ipts_uapi_free();
}

MODULE_DESCRIPTION("IPTS touchscreen driver");
MODULE_AUTHOR("Dorian Stoll <dorian.stoll@tmsp.io>");
MODULE_LICENSE("GPL");

module_init(ipts_mei_init);
module_exit(ipts_mei_exit);
