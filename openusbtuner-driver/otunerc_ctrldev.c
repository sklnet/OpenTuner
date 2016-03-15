/*
 * otunerc: /dev/otunerc device
 *
 * Copyright (C) 2010-11 Honza Petrous <jpetrous@smartimp.cz>
 * [Created 2010-03-23]
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/delay.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
#include <asm/semaphore.h>
#include <linux/device.h>
#else
#include <linux/semaphore.h>
#endif
#include <linux/uaccess.h>
#include <linux/device.h>

#include <linux/time.h>
#include <linux/poll.h>

#include "otunerc_priv.h"
#include "otunerc_proxyfe.h"
#include "otunerc_proxydmx.h"
#include "logs.h"

#define OTUNERC_CTRLDEV_NAME    "otunerc"

#define OTUNER_MSG_LEN (sizeof(struct opentuner_message))

static ssize_t otunerc_ctrldev_write(struct file *filp, const char *buff,
                    size_t len, loff_t *off)
{
    struct otunerc_ctx *ctx = filp->private_data;
    struct dvb_demux *demux = ctx->demux;
    char *kernel_buf;
    int tailsize = len % 188;

    if (ctx->closing) {
        len = -EINTR;
        goto out_write;
    }

    if (len < 188) {
        printLog(ERROR, "otunerc%d: Data are shorter then TS packet size (188B)\n", ctx->idx);
        len = -EINVAL;
        goto out_write;
    }

    len -= tailsize;
    kernel_buf = kmalloc(len, GFP_KERNEL);

    if (kernel_buf == NULL) {
        len = -ENOMEM;
        goto out_write;
    }

    if (down_interruptible(&ctx->tswrite_sem)) {
        len = -ERESTARTSYS;
        goto out_write_with_kfree;
    }

    if (copy_from_user(kernel_buf, buff, len)) {
        printLog(ERROR, "otunerc%d: userdata passing error\n", ctx->idx);
        len = -EINVAL;
        goto out_write_with_kfree_with_up;
    }

    if (ctx->config->tscheck) {
        int i;

        for (i = 0; i < len; i += 188)
            if (kernel_buf[i] != 0x47) { /* start of TS packet */
                printLog(ERROR, "otunerc%d: Data not start on packet boundary: index=%d data=%02x %02x %02x %02x %02x ...\n",
                        ctx->idx, i / 188, kernel_buf[i], kernel_buf[i + 1],
                        kernel_buf[i + 2], kernel_buf[i + 3], kernel_buf[i + 4]);
                len = -EINVAL;
                goto out_write_with_kfree_with_up;
            }
    }

    ctx->stat_wr_data += len;
    dvb_dmx_swfilter_packets(demux, kernel_buf, len / 188);

#ifdef CONFIG_PROC_FS
    /* TODO:  analyze injected data for statistics */
#endif
out_write_with_kfree_with_up:
    up(&ctx->tswrite_sem);
out_write_with_kfree:
    kfree(kernel_buf);
out_write:
    return len;
}

static ssize_t otunerc_ctrldev_read(struct file *filp, char __user *buff,
        size_t len, loff_t *off)
{
    struct otunerc_ctx *ctx = filp->private_data;

    ctx->stat_rd_data += len;

    /* read op is not using in current otuner protocol */
    return 0 ;
}

static int otunerc_ctrldev_open(struct inode *inode, struct file *filp)
{
    struct otunerc_ctx *ctx;
    int minor;

    if (inode != NULL)
		minor = MINOR(inode->i_rdev);
    else {
		printLog(CRITICAL, "Can't open otunerc with minor NULL\n");
        return -ENOENT;
    }

    printLog(INFO, "Open otunerc%d", minor);

    ctx = filp->private_data = otunerc_get_ctx(minor);
    if (ctx == NULL)
        return -EINVAL;

    ctx->stat_ctrl_sess++;

    memset(ctx->pidtab, -1, sizeof(ctx->pidtab));

    ctx->fd_opened++;
    ctx->closing = 0;

    return 0;
}

static int otunerc_ctrldev_close(struct inode *inode, struct file *filp)
{
    struct otunerc_ctx *ctx = filp->private_data;
    struct opentuner_message fakemsg;

    printLog(FINE, "closing (fd_opened=%d)\n", ctx->fd_opened);

    ctx->fd_opened--;
    ctx->closing = ctx->fd_opened <= 0;

    /* set FAKE response, to allow finish any waiters
       in otunerc_ctrldev_xchange_message() */
    ctx->ctrldev_response.type = -1;
    printLog(FINE, "faked response\n");
    wake_up_interruptible(&ctx->ctrldev_wait_response_wq);

    /* clear pidtab */
    printLog(FINE, "sending pidtab cleared ...\n");
//    if (down_interruptible(&ctx->xchange_sem))
//        return -ERESTARTSYS;
    memset(&fakemsg, 0, sizeof(fakemsg));
    fakemsg.type = MSG_NULL;
    otunerc_ctrldev_xchange_message(ctx, &fakemsg, 0);
//    up(&ctx->xchange_sem);
    printLog(FINE, "pidtab clearing done\n");

    if (ctx->closing && ctx->initialized) {
        printLog(FINE, "Release proxy demux and frontend\n");
        otunerc_demux_clear(ctx);
        otunerc_frontend_clear(ctx);
        ctx->initialized = 0;
    }

    return 0;
}

#define DIRECTION_UP 1
#define DIRECTION_DOWN 2
static long up_down_mgs_properties(opentuner_message_t *msg_src, opentuner_message_t *msg_dest, int direction) {
    long ret;

    ret = 0;

    if (msg_src->type != MSG_GET_PROPERTY && msg_src->type != MSG_SET_PROPERTY) {
        ret = 0;
    }
    else if (msg_src->body.prop == NULL || msg_src->body.prop->props == NULL)
        ret = -EINVAL;
    else if (direction == DIRECTION_UP) {
        printLog(FINE, "Upload dtv_properies to user space: %d properties\n", msg_src->body.prop->num);
        if (copy_to_user(&msg_dest->body.prop->num, &msg_src->body.prop->num, sizeof(msg_dest->body.prop->num))) {
            printLog(ERROR, "Upload dtv_properties failed\n");
            ret = -EFAULT;
        }
        else {
            printLog(FINE, "Upload dtv_properties values to user space\n");
            if (copy_to_user(msg_dest->body.prop->props, msg_src->body.prop->props, sizeof(struct dtv_property) * msg_dest->body.prop->num)) {
                printLog(ERROR, "Upload dtv_properties failed\n");
                ret = -EFAULT;
            }
        }
    }
    else if (direction == DIRECTION_DOWN) {
        printLog(ERROR, "Download dtv_properties from user space: %d properties\n", msg_src->body.prop->num);
        msg_dest->body.prop = kzalloc(sizeof(struct dtv_properties), GFP_KERNEL);
        if (msg_dest->body.prop == NULL) {
            ret = -ENOMEM;
        }
        else {
            if (copy_from_user(&msg_dest->body.prop->num, &msg_src->body.prop->num, sizeof(msg_src->body.prop->num))) {
                printLog(ERROR, "Download dtv_properties failed\n");
                ret = -EFAULT;
            }
            else {
                msg_dest->body.prop->props = kcalloc(sizeof (struct dtv_property), msg_dest->body.prop->num, GFP_KERNEL);
                if (msg_dest->body.prop->props == NULL) {
                    ret = -ENOMEM;
                    kfree(msg_dest->body.prop);
                }
                else {
                    printLog(FINE, "Download dtv_properties values from user space\n");
                    if (copy_from_user(msg_dest->body.prop->props, msg_src->body.prop->props, sizeof(struct dtv_property) * msg_dest->body.prop->num)) {
                        printLog(ERROR, "Upload dtv_properties failed\n");
                        ret = -EFAULT;
                    }
                }
            }
        }
    }
    else
        ret = -EINVAL;

    return ret;
}

static long otunerc_ctrldev_ioctl(struct file *file, unsigned int cmd,
                    unsigned long arg)
{
    struct otunerc_ctx *ctx = file->private_data;
    int len, i, ret = 0;
    opentuner_def_t tuner_setup;
    char *text;
    struct dtv_properties *p_poiter;
    opentuner_message_t *ioctl_message;

    if (ctx->closing)
        return -EINTR;

    if (down_interruptible(&ctx->ioctl_sem))
        return -ERESTARTSYS;

    switch (cmd) {
    case OPENTUNER_SETUP_FRONTEND:
    {
        printLog(FINE, "msg OPENTUNER_SETUP_FRONTEND\n");
        if (ctx->initialized) {
            printLog(ERROR, "OTuner already initialized.\n");
            ret = -EINVAL;
            break;
        }
        if (copy_from_user(&tuner_setup, (void *) arg, sizeof(opentuner_def_t))) {
                ret = -EFAULT;
                break;
        }

        // Check some parameters
        if (tuner_setup.num_modes < 0 || tuner_setup.num_modes > MAX_NUM_VTUNER_MODES) {
            printLog(ERROR, "Number of modes for tuner out of limits [0,%d]\n", MAX_NUM_VTUNER_MODES);
            ret = -EINVAL;
            break;
        }

        // Set real FE_INFO
        memcpy(&ctx->feinfo, &tuner_setup.real_fe_info, sizeof(struct dvb_frontend_info));

        // Set dev name (for nim_sockets)
        tuner_setup.name[127] = 0;
        len = strlen(tuner_setup.name) + 1;
        ctx->name = kzalloc(len, GFP_KERNEL);
        if (ctx->name == NULL) {
            ret = -ENOMEM;
            printLog(ERROR, "Not available memory for tuner name\n");
            break;
        }
        strncpy(ctx->name, tuner_setup.name, len - 1);

        // Set modes
        ctx->num_modes = tuner_setup.num_modes;
        for (i = 0; i < MAX_NUM_VTUNER_MODES; i++) {
            ctx->ctypes[i] = NULL; // Reset default modes
        }
        ret = 0;
        for (i = 0; i < ctx->num_modes; i++) {
            if (tuner_setup.modes != NULL)
            text = tuner_setup.modes[i];
            else
            text = NULL;
            if (text != NULL) {
            len = strlen(text) + 1;
            ctx->ctypes[i] = kzalloc(len, GFP_KERNEL);
            if (ctx->ctypes[i] == NULL) {
                ret = -ENOMEM;
                printLog(ERROR, "Not available memory for tuner mode\n");
                break;
            }
                strncpy(ctx->ctypes[i], text, len - 1);
            }
            else {
                ctx->num_modes--;
                i--;
            }
        }
        if (ret)
            break;

        ctx->vtype = tuner_setup.fe_type;
        ctx->has_outputs = tuner_setup.has_output;
        ctx->hw_adapter_nr = tuner_setup.adapter_hw_nr;
        ctx->hw_demux_nr = tuner_setup.demux_hw_nr;
        ctx->nim_entry_token.owner = THIS_MODULE;

        if (otunerc_frontend_init(ctx)) {
            printLog(ERROR, "otunerc%d: failed to initialize tuner's internals\n", ctx->idx);
            ret = -ENODEV;
        }
        else {
            if (otunerc_demux_init(ctx)) {
                otunerc_frontend_clear(ctx);
                printLog(ERROR, "otunerc%d: failed to initialize tuner's demux\n", ctx->idx);
                ret = -ENODEV;
            }
            else
                printLog(INFO, "otunerc%d succesfully initialized\n", ctx->idx);
        }
    }
    break;

    case OPENTUNER_GET_MESSAGE:
        printLog(FINE, "msg OPENTUNER_GET_MESSAGE\n");
        if (wait_event_interruptible(ctx->ctrldev_wait_request_wq,
                    ctx->ctrldev_request.type != -1)) {
            ret = -ERESTARTSYS;
            break;
        }

        BUG_ON(ctx->ctrldev_request.type == -1);

        ioctl_message = (opentuner_message_t *) arg;
        p_poiter = ioctl_message->body.prop;

        if (copy_to_user(ioctl_message, &ctx->ctrldev_request, OTUNER_MSG_LEN)) {
            ret = -EFAULT;
        }
        if (ioctl_message->type == MSG_GET_PROPERTY || ioctl_message->type == MSG_SET_PROPERTY) {
            ioctl_message->body.prop = p_poiter;
            ret = up_down_mgs_properties(&ctx->ctrldev_request, ioctl_message, DIRECTION_UP);
        }
        else
            ret = 0;

        ctx->ctrldev_request.type = -1;

        if (ctx->noresponse)
            up(&ctx->xchange_sem);
        else if (ret) {
            // Prepare error-fake response
            memset(&ctx->ctrldev_response, 0, sizeof(opentuner_message_t));
            ctx->ctrldev_response.type = ctx->ctrldev_request.type;
            ctx->ctrldev_response.exit_code = ret;
        }

        break;

    case OPENTUNER_SET_RESPONSE:
        printLog(FINE, "msg OPENTUNER_SET_RESPONSE\n");

        ioctl_message = (opentuner_message_t *) arg;
        p_poiter = ioctl_message->body.prop;

        if (copy_from_user(&ctx->ctrldev_response, ioctl_message, OTUNER_MSG_LEN)) {
            ret = -EFAULT;
        }
        else if (ioctl_message->type == MSG_GET_PROPERTY || ioctl_message->type == MSG_SET_PROPERTY) {
            ioctl_message->body.prop = p_poiter;
            ctx->ctrldev_response.body.prop = NULL;
            ret = up_down_mgs_properties(ioctl_message, &ctx->ctrldev_response, DIRECTION_DOWN);
        }
        else
            ret = 0;

        wake_up_interruptible(&ctx->ctrldev_wait_response_wq);

        break;

    default:
        printLog(ERROR, "otunerc%d: unknown IOCTL 0x%x\n", ctx->idx, cmd);
        ret = -ENOTTY; /* Linus: the only correct one return value for unsupported ioctl */

        break;
    }
    up(&ctx->ioctl_sem);

    return ret;
}

static unsigned int otunerc_ctrldev_poll(struct file *filp, poll_table *wait)
{
    struct otunerc_ctx *ctx = filp->private_data;
    unsigned int mask = 0;

    if (ctx->closing)
        return -EINTR;

    poll_wait(filp, &ctx->ctrldev_wait_request_wq, wait);

    if (ctx->ctrldev_request.type > -1) {
        mask = POLLPRI;
        printLog(FINE, "Poll: new message available\n");
    }

    return mask;
}

/* ------------------------------------------------ */

static const struct file_operations otunerc_ctrldev_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = otunerc_ctrldev_ioctl,
    .write = otunerc_ctrldev_write,
    .read  = otunerc_ctrldev_read,
    .poll  = (void *) otunerc_ctrldev_poll,
    .open  = otunerc_ctrldev_open,
    .release  = otunerc_ctrldev_close
};

static struct class *pclass;
static struct cdev cdev;
static dev_t chdev;

int otunerc_register_ctrldev(struct otunerc_config *config)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
    int idx;
    struct device *clsdev;
#endif

    chdev = MKDEV(OPENTUNER_MAJOR, 0);

    if (register_chrdev_region(chdev, config->devices, OTUNERC_CTRLDEV_NAME)) {
        printLog(ERROR, "otunerc: unable to get major %d\n", OPENTUNER_MAJOR);
        return -EINVAL;
    }

    cdev_init(&cdev, &otunerc_ctrldev_fops);

    cdev.owner = THIS_MODULE;
    cdev.ops = &otunerc_ctrldev_fops;

    if (cdev_add(&cdev, chdev, config->devices) < 0)
        printLog(WARNING, "otunerc: unable to create dev\n");

    pclass = class_create(THIS_MODULE, "otuner");
    if (IS_ERR(pclass)) {
        printLog(ERROR, "otunerc: unable to register major %d\n", OPENTUNER_MAJOR);
        return PTR_ERR(pclass);
    }
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
    for (idx = 0; idx < config->devices; idx++) {
        clsdev = device_create(pclass, NULL,
                               MKDEV(OPENTUNER_MAJOR, idx),
                               /*ctx*/ NULL, "misc/otunerc%d", idx);
        printLog(INFO, "otunerc: registered /dev/misc/otunerc%d\n",
                idx);
    }
#endif

    return 0;
}

void otunerc_unregister_ctrldev(struct otunerc_config *config)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
    int idx;
#endif

    printLog(INFO, "otunerc: unregistering\n");

    unregister_chrdev_region(chdev, config->devices);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
    for (idx = 0; idx < config->devices; idx++)
        device_destroy(pclass, MKDEV(OPENTUNER_MAJOR, idx));
#endif

    cdev_del(&cdev);

    class_destroy(pclass);
}


int otunerc_ctrldev_xchange_message(struct otunerc_ctx *ctx,
        struct opentuner_message *msg, int wait4response)
{
    int res;

    printLog(FINE, "Detect new message: type = %d\n", msg->type);
    if (down_interruptible(&ctx->xchange_sem)) {
        return -ERESTARTSYS;
    }

    printLog(FINE, "Check for opened frontend\n");
    if (ctx->fd_opened < 1) {
        up(&ctx->xchange_sem);
        printLog(ERROR, "No frontend opend\n");
        res = -EINVAL;
        goto exit_otunerc_ctrldev_xchange_message;
    }

    if(ctx->ctrldev_request.type != -1)
        printLog(WARNING, "otunerc%d: orphan request detected, type %d\n", ctx->idx, ctx->ctrldev_request.type);

    msg->exit_code = 0;
    memcpy(&ctx->ctrldev_request, msg, sizeof(struct opentuner_message));
    ctx->ctrldev_response.type = -1;
    ctx->noresponse = !wait4response;
    wake_up_interruptible(&ctx->ctrldev_wait_request_wq);

    printLog(FINE, "Check for response required\n");
    if (!wait4response) {
        msg->exit_code = 1;
        res = 0;
        goto exit_otunerc_ctrldev_xchange_message;
    }

    if (wait_event_interruptible(ctx->ctrldev_wait_response_wq, ctx->ctrldev_response.type != -1)) {
        printLog(ERROR, "Response timeout\n");
        ctx->ctrldev_request.type = -1;
        res = -ERESTARTSYS;
        goto exit_otunerc_ctrldev_xchange_message;
    }

    BUG_ON(ctx->ctrldev_response.type == -1);

    if (!ctx->ctrldev_response.exit_code)
        memcpy(msg, &ctx->ctrldev_response, sizeof(struct opentuner_message));
    else
        msg->exit_code = ctx->ctrldev_response.exit_code;
    printLog(FINE, "Message response exit code = %d\n", msg->exit_code);
    if (msg->exit_code == 0)
        msg->exit_code = 1;
    ctx->ctrldev_response.type = -1;

    res = 0;

exit_otunerc_ctrldev_xchange_message:

    up(&ctx->xchange_sem);
    return res;
}
// kate: indent-mode cstyle; indent-width 4; replace-tabs on;
