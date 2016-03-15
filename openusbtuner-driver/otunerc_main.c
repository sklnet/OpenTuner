/*
 * otunerc: Based on Virtual adapter driver
 *
 * Copyright (C) 2010-11 Honza Petrous <jpetrous@smartimp.cz>
 * [Created 2010-03-23]
 * Sponsored by Smartimp s.r.o. for its NessieDVB.com box
 *
 * Readapt by discovery for external USB tuner.
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

#include <linux/module.h>	/* Specifically, a module */
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif
#include <linux/wait.h>

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

#include "otunerc_priv.h"
#include "otunerc_proxyfe.h"
#include "otunerc_proxydmx.h"
#include "logs.h"

#define OPENTUNER_MODULE_VERSION "1.0"

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

#define DRIVER_NAME		"OpenTuner proxy"

#define OPENTUNERC_PROC_FILENAME	"otunerc%i"

#define OPENTUNERC_MAX_ADAPTERS	4

static struct otunerc_ctx *otunerc_tbl = NULL;

/* module params */
static struct otunerc_config config = {
	.devices = 2,
	.tscheck = 0,
	.debug = 0,
	.adapter_head = NULL
};

/* ----------------------------------------------------------- */


#ifdef CONFIG_PROC_FS

static char *get_fe_name(struct dvb_frontend_info *feinfo)
{
	return (feinfo && feinfo->name) ? feinfo->name : "(not set)";
}

/**
 * @brief  procfs file handler
 * @param  buffer:
 * @param  start:
 * @param  offset:
 * @param  size:
 * @param  eof:
 * @param  data:
 * @return =0: success <br/>
 *         <0: if any error occur
 */
#define MAXBUF 512
int otunerc_read_proc(char *buffer, char **start, off_t offset, int size,
			int *eof, void *data) {
	char outbuf[MAXBUF] = "[ otunerc driver, version " OPENTUNER_MODULE_VERSION " ]\n";
	int blen, i, pcnt;
	struct otunerc_ctx *ctx = (struct otunerc_ctx *) data;

	blen = strlen(outbuf);
	sprintf(outbuf+blen, "  sessions: %u\n", ctx->stat_ctrl_sess);
	blen = strlen(outbuf);
	sprintf(outbuf+blen, "  TS data : %u\n", ctx->stat_wr_data);
	blen = strlen(outbuf);
	sprintf(outbuf+blen, "  PID tab :");
	pcnt = 0;
	for (i = 0; i < MAX_PIDTAB_LEN; i++) {
		blen = strlen(outbuf);
		if (ctx->pidtab[i] != PID_UNKNOWN) {
			sprintf(outbuf+blen, " %x", ctx->pidtab[i]);
			pcnt++;
		}
	}
	blen = strlen(outbuf);
	sprintf(outbuf+blen, " (len=%d)\n", pcnt);
	blen = strlen(outbuf);
	sprintf(outbuf+blen, "  FE type : %s\n", get_fe_name(&ctx->feinfo));

	blen = strlen(outbuf);
	sprintf(outbuf+blen, "  msg xchg: %d/%d\n", ctx->ctrldev_request.type, ctx->ctrldev_response.type);

	blen = strlen(outbuf);

	if (size < blen)
		return -EINVAL;

	if (offset != 0)
		return 0;

	strcpy(buffer, outbuf);

	/* signal EOF */
	*eof = 1;

	return blen;

}
#endif

static char *my_strdup(const char *s)
{
	char *rv = kmalloc(strlen(s)+1, GFP_KERNEL);
	if (rv)
		strcpy(rv, s);
	return rv;
}

struct otunerc_ctx *otunerc_get_ctx(int minor)
{
	if (minor >= config.devices || minor < 0)
		return NULL;

	return &otunerc_tbl[minor];
}

static int __init otunerc_init(void)
{
	struct otunerc_ctx *ctx = NULL;
	int ret = -EINVAL, i, idx;
	struct dvb_adapter fake_adapter;

	setLevelLog(&config.debug);

	printLog(INFO, "virtual DVB adapter usb driver, version %s, (c) 2013-14 Discovery\n", OPENTUNER_MODULE_VERSION);

	if (request_module("dvb-core")) {
		printLog(WARNING, "dvb-core not found\n");
	}

	printLog(FINE, "Searching dvb_adapter list\n");
	// Create fake adapter to point at the HEAD list of registered adapters.
	ret = dvb_register_adapter(&fake_adapter, DRIVER_NAME, THIS_MODULE, NULL, adapter_nr);
	if (ret < 0) {
	  printLog(CRITICAL, "Error during registering fake adapter: %d\n", -ret);
	  goto err_init;
	}

	// Get reference of HEAD adapter's list.
	config.adapter_head = fake_adapter.list_head.next;
	// Destroy fake adapter.
	ret = dvb_unregister_adapter(&fake_adapter);
	if (ret < 0) {
	  printLog(CRITICAL, "Error during de-registering fake adapter: %d. Reboot required.\n", -ret);
	  goto err_init;
	}


	ret = initialize_demux_proxy();
	if (ret) {
	    printLog(CRITICAL, "Error during initialiazing demux proxy module: %d.\n", -ret);
	    goto err_init;
	}

	otunerc_tbl = kcalloc(config.devices, sizeof(struct otunerc_ctx), GFP_KERNEL);
	if (otunerc_tbl == NULL) {
		ret = -ENOMEM;
		goto err_init;
	}

	printLog(FINE, "Build otunerc contexts\n");
	for (idx = 0; idx < config.devices; idx++) {
		ctx = &otunerc_tbl[idx];
		ctx->idx = idx;
		ctx->config = &config;
		ctx->ctrldev_request.type = -1;
		ctx->ctrldev_response.type = -1;
		init_waitqueue_head(&ctx->ctrldev_wait_request_wq);
		init_waitqueue_head(&ctx->ctrldev_wait_response_wq);

		sema_init(&ctx->xchange_sem, 1);
		sema_init(&ctx->ioctl_sem, 1);
		sema_init(&ctx->tswrite_sem, 1);

		/* init pid table */
		for (i = 0; i < MAX_PIDTAB_LEN; i++)
			ctx->pidtab[i] = PID_UNKNOWN;

#ifdef CONFIG_PROC_FS
		{
			char procfilename[64];

			sprintf(procfilename, OPENTUNERC_PROC_FILENAME,
					ctx->idx);
			ctx->procname = my_strdup(procfilename);
			if (create_proc_read_entry(ctx->procname, 0, NULL,
							otunerc_read_proc,
							ctx) == 0)
				printk(KERN_WARNING
					"otunerc%d: Unable to register '%s' proc file\n",
					ctx->idx, ctx->procname);
		}
#endif
	}

	printLog(FINE, "Registering otunerc devices\n");
	otunerc_register_ctrldev(&config);

out:
	return ret;

err_init:
	goto out;
}

static void __exit otunerc_exit(void)
{
	int idx;

	printLog(FINE, "De-registering otunerc devices\n");
	otunerc_unregister_ctrldev(&config);

#ifdef CONFIG_PROC_FS
	for (idx = 0; idx < config.devices; idx++) {
		struct otunerc_ctx *ctx = &otunerc_tbl[idx];
		remove_proc_entry(ctx->procname, NULL);
		kfree(ctx->procname);
	}
#endif

	kfree(otunerc_tbl);

	release_demux_proxy();

	printk(KERN_NOTICE "otunerc: unloaded successfully\n");
}

module_init(otunerc_init);
module_exit(otunerc_exit);

MODULE_AUTHOR("Discovery");
MODULE_DESCRIPTION("Proxy DVB device");
MODULE_LICENSE("GPL");
MODULE_VERSION(OPENTUNER_MODULE_VERSION);

module_param_named(devices, config.devices, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(devices, "Number of virtual adapters (default is 2)");

module_param_named(tscheck, config.tscheck, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(tscheck, "Check TS packet validity (default is 0)");

module_param_named(debug, config.debug, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(debug, "Enable debug messages (default is 25 - INFO + ERROR + CRITICAL)");

