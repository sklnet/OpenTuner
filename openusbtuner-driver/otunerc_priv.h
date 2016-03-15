/*
 * otunerc: Internal defines
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

#ifndef _OTUNERC_PRIV_H
#define _OTUNERC_PRIV_H

#include <linux/module.h>	/* Specifically, a module */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/cdev.h>
#include <linux/list.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 8, 0)
#include <media/dvb-core/demux.h>
#include <media/dvb-core/dmxdev.h>
#include <media/dvb-core/dvb_demux.h>
#include <media/dvb-core/dvb_frontend.h>
#include <media/dvb-core/dvb_net.h>
#include <media/dvb-core/dvbdev.h>
#else
#include <media/dvb/dvb-core/demux.h>
#include <media/dvb/dvb-core/dmxdev.h>
#include <media/dvb/dvb-core/dvb_demux.h>
#include <media/dvb/dvb-core/dvb_frontend.h>
#include <media/dvb/dvb-core/dvb_net.h>
#include <media/dvb/dvb-core/dvbdev.h>
#endif


#include "openusbtunerapi.h"
#include "nim_sockets_proc.h"

#define MAX_PIDTAB_LEN 30

#define PID_UNKNOWN 0x0FFFF

#define MAX_NUM_VTUNER_MODES 3

struct otunerc_config {

	int debug;
	int tscheck;
	int devices;
	struct list_head *adapter_head;
};

struct otunerc_ctx {

	/* DVB api */
	struct dvb_adapter *dvb_adapter;
	struct dvb_demux *demux;
	struct dvb_frontend *fe;
	struct dvb_device *fe_dev;
	struct dmx_frontend fe_hw;
	nim_socket_entry_t nim_entry;
	nim_socket_module_entry_t nim_entry_token;

	/* internals */
	int idx;
	char *name;
	fe_type_t vtype;
	struct dvb_frontend_info feinfo;
	struct otunerc_config *config;
	int has_outputs;
	int hw_adapter_nr;
	int hw_demux_nr;
	int initialized;

	unsigned short pidtab[MAX_PIDTAB_LEN];

	struct semaphore xchange_sem;
	struct semaphore ioctl_sem;
	struct semaphore tswrite_sem;
	int fd_opened;
	int closing;

	char *procname;

	/* ctrldev */
	char trail[188];
	unsigned int trailsize;
	int noresponse;
	int num_modes;
	char *ctypes[MAX_NUM_VTUNER_MODES];
	struct opentuner_message ctrldev_request;
	struct opentuner_message ctrldev_response;
	wait_queue_head_t ctrldev_wait_request_wq;
	wait_queue_head_t ctrldev_wait_response_wq;

	/* proc statistics */
	unsigned int stat_wr_data;
	unsigned int stat_rd_data;
	unsigned int stat_ctrl_sess;
	unsigned short pidstat[MAX_PIDTAB_LEN];
};

int otunerc_register_ctrldev(struct otunerc_config *config);
void otunerc_unregister_ctrldev(struct otunerc_config *config);
struct otunerc_ctx *otunerc_get_ctx(int minor);
int otunerc_ctrldev_xchange_message(struct otunerc_ctx *ctx, struct opentuner_message *msg, int wait4response);

#define dprintk(ctx, fmt, arg...) do {					\
if (ctx->config && (ctx->config->debug))				\
	printk(KERN_DEBUG "opentunerc%d: " fmt, ctx->idx, ##arg);	\
} while (0)

#endif
