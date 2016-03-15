
#ifndef _OTUNERC_PROXYDMX_H
#define _OTUNERC_PROXYDMX_H

#include <linux/list.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 8, 0)
#include <media/dvb-core/dvb_frontend.h>
#include <media/dvb-core/dvb_demux.h>
#include <media/dvb-core/dvbdev.h>
#include <media/dvb-core/dmxdev.h>
#else
#include <media/dvb/dvb-core/dvb_frontend.h>
#include <media/dvb/dvb-core/dvb_demux.h>
#include <media/dvb/dvb-core/dvbdev.h>
#include <media/dvb/dvb-core/dmxdev.h>
#endif

#include "otunerc_priv.h"

int /*__devinit*/ otunerc_demux_init(struct otunerc_ctx *ctx);
int /*__devinit*/ otunerc_demux_clear(struct otunerc_ctx *ctx);

int initialize_demux_proxy(void);
int release_demux_proxy(void);

#endif
