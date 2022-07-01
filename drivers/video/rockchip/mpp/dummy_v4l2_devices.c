// SPDX-License-Identifier: GPL-2.0+
// Copyright 2022 The FydeOS Authors.
// Author: Yang Tsao<yang@fydeos.io>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include "dummy_v4l2_devices.h"
#define DUMMY_DEC_NAME "video-dec0"
#define DUMMY_ENC_NAME "video-enc0"

static int dummy_v4l2_release(struct inode *inode, struct file *file) {return 0;}

static ssize_t dummy_v4l2_read(struct file *file, char *buf, size_t count, loff_t *ppos) {
  struct miscdevice *dev = (struct miscdevice *) file->private_data;
  unsigned long n;
  if (count < 4) 
    return -1;
  if (strncmp(dev->name, DUMMY_DEC_NAME, 7)) {
    n = copy_to_user(buf, "enc", 4);
  } else {
    n = copy_to_user(buf, "dec", 4);
  }
  if (n) return -1;
  return 4;
}

static ssize_t dummy_v4l2_write(struct file *file, const char *buf, size_t count, loff_t *ppos) {
  return count;
}

static long dymmy_v4l2_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {return 0;}

struct file_operations fops = {
  .owner = THIS_MODULE,
  .release = dummy_v4l2_release,
  .read = dummy_v4l2_read,
  .write = dummy_v4l2_write,
  .compat_ioctl = dymmy_v4l2_ioctl,
};

static struct miscdevice v4l2_dec_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = DUMMY_DEC_NAME,
  .fops = &fops,
};

static struct miscdevice v4l2_enc_dev = {
  .minor = MISC_DYNAMIC_MINOR,
  .name = DUMMY_ENC_NAME,
  .fops = &fops,
};

int init_dummy_v4l2_devices() {
  int ret = 0;
  ret = misc_register(&v4l2_dec_dev);
  if (ret) {
    pr_err("failed to register dummy v4l2 dec device, ret:%d", ret);
    return ret;
  }
  ret = misc_register(&v4l2_enc_dev);
  if (ret) {
    pr_err("failed to register dummy v4l2 enc device, ret:%d", ret);
    return ret;
  }
  return 0;
}

void cleanup_dummy_v4l2_devices() {
  misc_deregister(&v4l2_dec_dev);
  misc_deregister(&v4l2_enc_dev);
}
