/*
 * otunerc: Driver for Proxy Frontend
 *
 * Copyright (C) 2010-11 Honza Petrous <jpetrous@smartimp.cz>
 * [Inspired on proxy frontend by Emard <emard@softhome.net>]
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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 8, 0)
#include <media/dvb-core/dvb_frontend.h>
#else
#include <media/dvb/dvb-core/dvb_frontend.h>
#endif

#include "otunerc_proxyfe.h"
#include "nim_sockets_proc.h"
#include "logs.h"

struct dvb_proxyfe_state {
	struct dvb_frontend frontend;
	struct otunerc_ctx *ctx;
};

struct dvb_fake_private {
    struct dvb_device *device;
};


#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 0, 0)
static int patch_kernel_ioctl(struct file *file, unsigned int cmd, void *arg);
#else
static int patch_kernel_ioctl(struct inode *node, struct file *file, unsigned int cmd, void *arg);
#endif


static int dvb_proxyfe_read_status(struct dvb_frontend *fe, fe_status_t *status)
{
	struct dvb_proxyfe_state *state = fe->demodulator_priv;
	struct otunerc_ctx *ctx = state->ctx;
	struct opentuner_message msg;
    int ret;

	msg.type = MSG_READ_STATUS;
	ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);

    if (!ret) {
        *status = msg.body.status;
        return msg.exit_code;
    }
    else
        return -EPERM;
}

static int dvb_proxyfe_read_ber(struct dvb_frontend *fe, u32 *ber)
{
	struct dvb_proxyfe_state *state = fe->demodulator_priv;
	struct otunerc_ctx *ctx = state->ctx;
	struct opentuner_message msg;
    int ret;

	msg.type = MSG_READ_BER;
	ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);

    if (!ret) {
        *ber = msg.body.ber;
        return msg.exit_code;
    }
    else
        return -EPERM;
}

static int dvb_proxyfe_read_signal_strength(struct dvb_frontend *fe,
						u16 *strength)
{
	struct dvb_proxyfe_state *state = fe->demodulator_priv;
	struct otunerc_ctx *ctx = state->ctx;
	struct opentuner_message msg;
    int ret;

	msg.type = MSG_READ_SIGNAL_STRENGTH;
	ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);

    if (!ret) {
        *strength = msg.body.ss;
        return msg.exit_code;
    }
    else
        return -EPERM;
}

static int dvb_proxyfe_read_snr(struct dvb_frontend *fe, u16 *snr)
{
	struct dvb_proxyfe_state *state = fe->demodulator_priv;
	struct otunerc_ctx *ctx = state->ctx;
	struct opentuner_message msg;
    int ret;

	msg.type = MSG_READ_SNR;
	ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);

    if (!ret) {
        *snr = msg.body.snr;
        return msg.exit_code;
    }
    else
        return -EPERM;
}

static int dvb_proxyfe_read_ucblocks(struct dvb_frontend *fe, u32 *ucblocks)
{
	struct dvb_proxyfe_state *state = fe->demodulator_priv;
	struct otunerc_ctx *ctx = state->ctx;
	struct opentuner_message msg;
    int ret;

	msg.type = MSG_READ_UCBLOCKS;
	ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);

    if (!ret) {
        *ucblocks = msg.body.ucb;
        return msg.exit_code;
    }
    else
        return -EPERM;
}

static int convert_fe_parameters(struct dvb_frontend_parameters *p, fe_type_t from, fe_type_t to) {
    if (from == to)
	return 0;
    else {
	return 0; //TODO
    }
}

static int dvb_proxyfe_get_frontend(struct dvb_frontend *fe,
					struct dvb_frontend_parameters *p) {
	struct dvb_proxyfe_state *state = fe->demodulator_priv;
	struct otunerc_ctx *ctx = state->ctx;
	struct opentuner_message msg;
    int ret;

	msg.type = MSG_GET_FRONTEND;
	ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);

    if (!ret) {
        memcpy(p, &msg.body.fe_params, sizeof(struct dvb_frontend_parameters));
        ret = convert_fe_parameters(p, ctx->feinfo.type, ctx->vtype);
        if (!ret)
            return 1;
        else
            return ret;
    }
    else
        return -EPERM;
}

static int dvb_proxyfe_set_frontend(struct dvb_frontend *fe,
					struct dvb_frontend_parameters *p) {
	struct dvb_proxyfe_state *state = fe->demodulator_priv;
	struct otunerc_ctx *ctx = state->ctx;
	struct opentuner_message msg;
	int ret;

	memset(&msg, 0, sizeof(msg));
	memcpy(&msg.body.fe_params, p, sizeof(struct dvb_frontend_parameters));
	ret = convert_fe_parameters(&msg.body.fe_params, ctx->vtype, ctx->feinfo.type);

	if (!ret) {
	    msg.type = MSG_SET_FRONTEND;
	    ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);
	}

	if (ret)
        return -EPERM;
	else
        return msg.exit_code;
}

static int dvb_proxyfe_get_property(struct dvb_frontend *fe, struct dtv_properties* tvp)
{
    int ret;
    struct dtv_properties props;
    struct dvb_proxyfe_state *state = fe->demodulator_priv;
    struct otunerc_ctx *ctx = state->ctx;
    struct opentuner_message msg;

    ret = 0;
    msg.type = MSG_GET_PROPERTY;
    msg.body.prop = &props;
    props.num = tvp->num;

    printLog(FINE, "FE_GET_PROPERTY Debug: request %d properties\n", props.num);

    props.props = NULL;
    props.props = kcalloc(sizeof(struct dtv_property), props.num, GFP_KERNEL);
    if (props.props == NULL)
        ret = -ENOMEM;
    else if (copy_from_user(props.props, tvp->props, sizeof(struct dtv_property) * props.num)) {
        ret = -EFAULT;
        printLog(FINE, "FE_GET_PROPERTY Debug: read request from user space failed\n");
    }

    if (!ret)
        ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);
    if (!ret) {
        tvp->num = msg.body.prop->num;
        printLog(FINE, "FE_GET_PROPERTY Debug: upload to user space %d properties\n", props.num);
        if (copy_to_user(tvp->props, msg.body.prop->props, sizeof(struct dtv_property) * props.num))
            ret = -EFAULT;
        else
            ret = msg.exit_code;

        kfree(msg.body.prop->props);
        kfree(msg.body.prop);
    }
    else
        ret = -EPERM;

    if (props.props != NULL)
        kfree(props.props);
    return ret;
}

static int dvb_proxyfe_set_property(struct dvb_frontend *fe, struct dtv_properties* tvp)
{
    int ret;
    struct dtv_properties *props;
    struct dvb_proxyfe_state *state = fe->demodulator_priv;
    struct otunerc_ctx *ctx = state->ctx;
    struct opentuner_message msg;

    ret = 0;
    msg.type = MSG_SET_PROPERTY;
    props = NULL;
    props = kzalloc(sizeof(struct dtv_properties), GFP_KERNEL);
    if (props == NULL)
        ret = -ENOMEM;
    else {
        msg.body.prop = props;
        props->num = tvp->num;

        printLog(FINE, "FE_SET_PROPERTY Debug: setting %d property/ies on frontend\n", props->num);

        props->props = kcalloc(sizeof(struct dtv_property), props->num, GFP_KERNEL);
        if (props->props == NULL)
            ret = -ENOMEM;
        else {
            printLog(FINE, "FE_SET_PROPERTY Debug: download properties from user space\n");
            ret = copy_from_user(props->props, tvp->props, sizeof(struct dtv_property) * props->num);
            if (!ret) {
                printLog(FINE, "FE_SET_PROPERTY Debug: send request to client\n");
                ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);
            }
            else {
                printLog(FINE, "FE_SET_PROPERTY Debug: error coping properties: %d byte to go\n", ret);
                ret = -EFAULT;
            }
        }
        if (!ret)
            ret = msg.exit_code;
        else
            ret = -EPERM;
    }

    if (props != NULL) {
        if (props->props != NULL)
            kfree(props->props);
        kfree(props);
    }
    return ret;
}

static enum dvbfe_algo dvb_proxyfe_get_frontend_algo(struct dvb_frontend *fe)
{
	return DVBFE_ALGO_SW;
}

static int dvb_proxyfe_sleep(struct dvb_frontend *fe)
{
	return 0;
}

static int dvb_proxyfe_init(struct dvb_frontend *fe)
{
    return 0;
}

static int dvb_proxyfe_set_tone(struct dvb_frontend *fe, fe_sec_tone_mode_t tone)
{
	struct dvb_proxyfe_state *state = fe->demodulator_priv;
	struct otunerc_ctx *ctx = state->ctx;
	struct opentuner_message msg;
    int ret;

	msg.body.tone = tone;
	msg.type = MSG_SET_TONE;
	ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);

    if (!ret)
        return msg.exit_code;
    else
        return -EPERM;
}

static int dvb_proxyfe_set_voltage(struct dvb_frontend *fe, fe_sec_voltage_t voltage)
{
	struct dvb_proxyfe_state *state = fe->demodulator_priv;
	struct otunerc_ctx *ctx = state->ctx;
	struct opentuner_message msg;
    int ret;

	msg.body.voltage = voltage;
	msg.type = MSG_SET_VOLTAGE;
	ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);

    if (!ret)
        return msg.exit_code;
    else
        return -EPERM;
}

static int dvb_proxyfe_send_diseqc_msg(struct dvb_frontend *fe, struct dvb_diseqc_master_cmd *cmd)
{
	struct dvb_proxyfe_state *state = fe->demodulator_priv;
	struct otunerc_ctx *ctx = state->ctx;
	struct opentuner_message msg;
    int ret;

	memcpy(&msg.body.diseqc_master_cmd, cmd, sizeof(struct dvb_diseqc_master_cmd));
	msg.type = MSG_SEND_DISEQC_MSG;
	ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);

    if (!ret)
        return msg.exit_code;
    else
        return -EPERM;
}

static int dvb_proxyfe_send_diseqc_burst(struct dvb_frontend *fe, fe_sec_mini_cmd_t burst)
{
	struct dvb_proxyfe_state *state = fe->demodulator_priv;
	struct otunerc_ctx *ctx = state->ctx;
	struct opentuner_message msg;

	msg.body.burst = burst;
	msg.type = MSG_SEND_DISEQC_BURST;

	if (!otunerc_ctrldev_xchange_message(ctx, &msg, 1))
        return msg.exit_code;
    else
        return -EPERM;
}

static int dvb_proxyfe_diseqc_reset_overload(struct dvb_frontend *fe) {
    struct dvb_proxyfe_state *state = fe->demodulator_priv;
    struct otunerc_ctx *ctx = state->ctx;
    struct opentuner_message msg;

    msg.type = MSG_DISEQC_RESET_OVERLOAD;

    if (!otunerc_ctrldev_xchange_message(ctx, &msg, 1))
        return msg.exit_code;
    else
        return -EPERM;
}

static int dvb_proxyfe_diseqc_recv_slave_reply(struct dvb_frontend *fe, struct dvb_diseqc_slave_reply *reply) {
    struct dvb_proxyfe_state *state = fe->demodulator_priv;
    struct otunerc_ctx *ctx = state->ctx;
    struct opentuner_message msg;
    int ret;

    msg.type = MSG_DISEQC_RECV_SLAVE_REPLY;
    ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);
    if (!ret) {
        memcpy(reply, &msg.body.slave_reply, sizeof(struct dvb_diseqc_slave_reply));
        return msg.exit_code;
    }
    else
        return -EPERM;
}

static int dvb_proxyfe_enable_high_lnb_voltage(struct dvb_frontend *fe, int value) {
    struct dvb_proxyfe_state *state = fe->demodulator_priv;
    struct otunerc_ctx *ctx = state->ctx;
    struct opentuner_message msg;

    msg.type = MSG_ENABLE_HIGH_LNB_VOLTAGE;
    msg.body.high_voltage = value;

    if (!otunerc_ctrldev_xchange_message(ctx, &msg, 1))
        return msg.exit_code;
    else
        return -EPERM;
}

static int dvb_proxyfe_set_frontend_tune_mode(struct dvb_frontend *fe, unsigned int value) {
    struct dvb_proxyfe_state *state = fe->demodulator_priv;
    struct otunerc_ctx *ctx = state->ctx;
    struct opentuner_message msg;

    msg.type = MSG_SET_FRONTEND_TUNE_MODE;
    msg.body.tune_mode = value;

    if (!otunerc_ctrldev_xchange_message(ctx, &msg, 1))
        return msg.exit_code;
    else
        return -EPERM;
}

static int dvb_proxyfe_dishnetwork_send_legacy_cmd(struct dvb_frontend *fe, unsigned int value) {
    struct dvb_proxyfe_state *state = fe->demodulator_priv;
    struct otunerc_ctx *ctx = state->ctx;
    struct opentuner_message msg;

    msg.type = MSG_DISHNETWORK_SEND_LEGACY_CMD;
    msg.body.legacy_cmd = value;

    if (!otunerc_ctrldev_xchange_message(ctx, &msg, 1))
        return msg.exit_code;
    else
        return -EPERM;
}

static int dvb_proxyfe_get_event(struct dvb_frontend *fe, struct dvb_frontend_event *fe_event) {
    struct dvb_proxyfe_state *state = fe->demodulator_priv;
    struct otunerc_ctx *ctx = state->ctx;
    struct opentuner_message msg;
    int ret;

    msg.type = MSG_GET_EVENT;
    ret = otunerc_ctrldev_xchange_message(ctx, &msg, 1);
    if (!ret) {
        memcpy(fe_event, &msg.body.fe_event, sizeof(struct dvb_frontend_event));
        return msg.exit_code;
    }
    else
        return -EPERM;
}

static void dvb_proxyfe_release(struct dvb_frontend *fe)
{
	struct dvb_proxyfe_state *state = fe->demodulator_priv;

	kfree(state);
}

static struct dvb_frontend_ops dvb_proxyfe_proxy_ops = {
	.release = dvb_proxyfe_release,

	.init = dvb_proxyfe_init,
	.sleep = dvb_proxyfe_sleep,

	.get_frontend = NULL,
	.get_property = NULL,
    .get_frontend_algo = dvb_proxyfe_get_frontend_algo,
	.set_frontend = NULL,

	.read_status = NULL,
	.read_ber = NULL,
	.read_signal_strength = NULL,
	.read_snr = NULL,
	.read_ucblocks = NULL,

	.set_voltage = NULL,
	.set_tone = NULL,

	.diseqc_send_master_cmd         = NULL,
	.diseqc_send_burst              = NULL,

};


static struct dvb_frontend *dvb_proxyfe_proxy_attach(struct otunerc_ctx *ctx)
{
	struct dvb_frontend *fe = ctx->fe;

	if (!fe) {
		struct dvb_proxyfe_state *state = NULL;

		/* allocate memory for the internal state */
		state = kmalloc(sizeof(struct dvb_proxyfe_state), GFP_KERNEL);
		if (state == NULL) {
			return NULL;
		}

		fe = &state->frontend;
		fe->demodulator_priv = state;
/*
        switch (ctx->vtype) {
            case FE_QPSK:
                if ((ctx->feinfo.caps & FE_CAN_2G_MODULATION) == FE_CAN_2G_MODULATION)
                    fe->dtv_property_cache.delivery_system = SYS_DVBS2;
                else
                    fe->dtv_property_cache.delivery_system = SYS_DVBS;
                break;
            case FE_QAM:
                fe->dtv_property_cache.delivery_system = SYS_DVBC_ANNEX_AC; //FIXME
                break;
            case FE_OFDM:
                if ((ctx->feinfo.caps & FE_CAN_2G_MODULATION) == FE_CAN_2G_MODULATION)
                    fe->dtv_property_cache.delivery_system = SYS_DVBT2;
                else
                    fe->dtv_property_cache.delivery_system = SYS_DVBT;
                break;
            case FE_ATSC:
                fe->dtv_property_cache.delivery_system = SYS_ATSC; //FIXME
                break;
        }*/
		state->ctx = ctx;
	}

	memcpy(&fe->ops, &dvb_proxyfe_proxy_ops, sizeof(struct dvb_frontend_ops));
	memcpy(&fe->ops.info, &ctx->feinfo, sizeof(struct dvb_frontend_info));

	return fe;
}

static int do_fe_ioctl_override_callback_part2(struct dvb_frontend *fe, unsigned int cmd, void *parg) {
    switch (cmd) {
        case FE_READ_SIGNAL_STRENGTH:
            printLog(FINE, "Proxy FE_READ_SIGNAL_STRENGTH. arg = %p\n", parg);
            return dvb_proxyfe_read_signal_strength(fe, (__u16 *) parg);

        case FE_READ_SNR:
            printLog(FINE, "Proxy FE_READ_SNR. arg = %p\n", parg);
            return dvb_proxyfe_read_snr(fe, (__u16 *) parg);

        case FE_READ_UNCORRECTED_BLOCKS:
            printLog(FINE, "Proxy FE_READ_UNCORRECTED_BLOCKS. arg = %p\n", parg);
            return dvb_proxyfe_read_ucblocks(fe, (__u32 *) parg);

        case FE_SET_FRONTEND:
            printLog(FINE, "Proxy FE_SET_FRONTEND. arg = %p\n", parg);
            return dvb_proxyfe_set_frontend(fe, (struct dvb_frontend_parameters *) parg);

        case FE_GET_FRONTEND:
            printLog(FINE, "Proxy FE_GET_FRONTEND. arg = %p\n", parg);
            return dvb_proxyfe_get_frontend(fe, (struct dvb_frontend_parameters *) parg);

        case FE_SET_FRONTEND_TUNE_MODE:
            printLog(FINE, "Proxy FE_SET_FRONTEND_TUNE_MODE. arg = %p\n", parg);
            return dvb_proxyfe_set_frontend_tune_mode(fe, (unsigned int) parg);

        case FE_GET_EVENT:
            printLog(FINE, "Proxy FE_GET_EVENT. arg = %p\n", parg);
            return dvb_proxyfe_get_event(fe, (struct dvb_frontend_event *) parg);

        case FE_DISHNETWORK_SEND_LEGACY_CMD:
            printLog(FINE, "Proxy FE_DISHNETWORK_SEND_LEGACY_CMD. arg = %p\n", parg);
            return dvb_proxyfe_dishnetwork_send_legacy_cmd(fe, (unsigned int) parg);

        default:
            printLog(ERROR, "Proxy Unknow command %d. arg = %p [SKIPPED]\n", cmd, parg);
            return -EINVAL;
    }
}

static int do_fe_ioctl_override_callback_part1(struct dvb_frontend *fe, unsigned int cmd, void *parg) {
    switch (cmd) {
        case FE_SET_PROPERTY:
            printLog(FINE, "Proxy FE_SET_PROPERTY. arg = %p\n", parg);
            return dvb_proxyfe_set_property(fe, (struct dtv_properties *) parg);

        case FE_GET_PROPERTY:
            printLog(FINE, "Proxy FE_GET_PROPERTY. arg = %p\n", parg);
            return dvb_proxyfe_get_property(fe, (struct dtv_properties *) parg);

        case FE_GET_INFO:
            printLog(FINE, "Proxy FE_GET_INFO. arg = %p\n", parg);
            memcpy(parg, &fe->ops.info, sizeof(struct dvb_frontend_info));
            return 1;

        case FE_DISEQC_RESET_OVERLOAD:
            printLog(FINE, "Proxy FE_DISEQC_RESET_OVERLOAD. arg = %p\n", parg);
            return dvb_proxyfe_diseqc_reset_overload(fe);

        case FE_DISEQC_SEND_MASTER_CMD:
            printLog(FINE, "Proxy FE_DISEQC_SEND_MASTER_CMD. arg = %p\n", parg);
            return dvb_proxyfe_send_diseqc_msg(fe, (struct dvb_diseqc_master_cmd *) parg);

        case FE_DISEQC_RECV_SLAVE_REPLY:
            printLog(FINE, "Proxy FE_DISEQC_RECV_SLAVE_REPLY. arg = %p\n", parg);
            return dvb_proxyfe_diseqc_recv_slave_reply(fe, (struct dvb_diseqc_slave_reply *) parg);

        case FE_DISEQC_SEND_BURST:
            printLog(FINE, "Proxy FE_DISEQC_SEND_BURST. arg = %p\n", parg);
            return dvb_proxyfe_send_diseqc_burst(fe, (fe_sec_mini_cmd_t) parg);

        case FE_SET_TONE:
            printLog(FINE, "Proxy FE_SET_TONE. arg = %p\n", parg);
            return dvb_proxyfe_set_tone(fe, (fe_sec_tone_mode_t) parg);

        case FE_SET_VOLTAGE:
            printLog(FINE, "Proxy FE_SET_VOLTAGE. arg = %p\n", parg);
            return dvb_proxyfe_set_voltage(fe, (fe_sec_voltage_t) parg);

        case FE_ENABLE_HIGH_LNB_VOLTAGE:
            printLog(FINE, "Proxy FE_ENABLE_HIGH_LNB_VOLTAGE. arg = %p\n", parg);
            return dvb_proxyfe_enable_high_lnb_voltage(fe, (int) parg);

        case FE_READ_STATUS:
            printLog(FINE, "Proxy FE_READ_STATUS. arg = %p\n", parg);
            return dvb_proxyfe_read_status(fe, (fe_status_t *) parg);

        case FE_READ_BER:
            printLog(FINE, "Proxy FE_READ_BER. arg = %p\n", parg);
            return dvb_proxyfe_read_ber(fe, (__u32 *) parg);

        default:
            return do_fe_ioctl_override_callback_part2(fe, cmd, parg);
    }
}

static int fe_ioctl_override_callback(struct dvb_frontend *fe, unsigned int cmd, void *parg) {
    void *v_state;
    struct dvb_proxyfe_state *state;

    v_state = fe->demodulator_priv;
    if (v_state) {
        state = v_state;
        if (state->frontend.id == fe->id && state->ctx && state->ctx->dvb_adapter == fe->dvb) {
            return do_fe_ioctl_override_callback_part1(fe, cmd, parg);
        }
        else
            return 0;
    }
    else {
        return 0;
    }
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 0, 0)
static int patch_kernel_ioctl(struct file *file, unsigned int cmd, void *arg) {
#else
static int patch_kernel_ioctl(struct inode *node, struct file *file, unsigned int cmd, void *arg) {
#endif
    //FIXME: Private date is "knowed by kernel source"
    struct dvb_device *dvbdev = file->private_data;
    struct dvb_frontend *fe = dvbdev->priv;
    int res;

    printLog(FINE, "New kernel_ioctl command (cmd=%d, arg=%p)\n", cmd, arg);

    res = fe_ioctl_override_callback(fe, cmd, arg);
    printLog(FINE, "kernel_ioctl command (cmd=%d, arg=%p) exit with %d\n", cmd, arg, res);
    if (res > 0) // Success.
        res = 0;

    return res;
}


int /*__devinit*/ otunerc_frontend_init(struct otunerc_ctx *ctx)
{
	int ret = 0;
	int i;
	struct dvb_adapter *item;
    struct dvb_device *fe_devices;
    struct dvb_fake_private *private_fe;

	if (ctx->initialized) {
		printLog(INFO, "otunerc%d: frontend already initialized as type=%d\n",
				ctx->idx, ctx->vtype);
		return 0;
	}

	// Searching for hardware dvb_adapter
	item = NULL;
	ctx->dvb_adapter = NULL;
	list_for_each_entry(item, ctx->config->adapter_head, list_head) {
	    if (item->num == ctx->hw_adapter_nr) {
		ctx->dvb_adapter = item;
		break;
	    }
	}
	if (ctx->dvb_adapter == NULL) {
	    printLog(ERROR, "No hw adapter %d found.\n", ctx->hw_adapter_nr);
	    return -ENOENT;
	}

	ctx->fe = dvb_proxyfe_proxy_attach(ctx);
	if (ctx->fe == NULL)
	    ret = -ENOMEM;
	else {
        ctx->fe->id = 0;
        printLog(FINE, "Searching for free frontend id\n");
        list_for_each_entry(fe_devices, &ctx->dvb_adapter->device_list, list_head) {
            if (fe_devices->type == DVB_DEVICE_FRONTEND) {
                if (ctx->fe->id <= fe_devices->id)
                    ctx->fe->id = fe_devices->id + 1;
            }
        }
        printLog(FINE, "Free frontend id = %d\n", ctx->fe->id);
        ret = dvb_register_frontend(ctx->dvb_adapter, ctx->fe);

	    if (!ret) {
            ctx->fe_dev = NULL;
            list_for_each_entry(fe_devices, &ctx->dvb_adapter->device_list, list_head) {
                if (fe_devices->type == DVB_DEVICE_FRONTEND && fe_devices->id == ctx->fe->id) {
                    ctx->fe_dev = fe_devices;
                    break;
                }
            }
            if (ctx->fe_dev == NULL) {
                printLog(ERROR, "Could't find dvb_device initializing frontend %d\n", ctx->fe->id);
                dvb_unregister_frontend(ctx->fe);
                return -ENOENT;
            }

            private_fe = (struct dvb_fake_private *) ctx->fe->frontend_priv;
            if (ctx->fe_dev != private_fe->device) {
                printLog(WARNING, "Found dvb_device for frontend in adapter's list but seems differs from frontend_priv pointer\n");
                //ctx->fe_dev = private_fe->device;
            }

            ctx->fe_dev->kernel_ioctl = patch_kernel_ioctl;
            ctx->fe_hw.source = DMX_FRONTEND_0 + ctx->fe->id;

            // Build nim_socket
            memset(&ctx->nim_entry.dvb_type_str, 0, sizeof(ctx->nim_entry.dvb_type_str));
            switch (ctx->vtype) {
                case FE_OFDM:
                    if ((ctx->fe->ops.info.caps & FE_CAN_2G_MODULATION) == FE_CAN_2G_MODULATION)
                        strcpy(ctx->nim_entry.dvb_type_str, "DVB-T2");
                    else
                        strcpy(ctx->nim_entry.dvb_type_str, "DVB-T");
                    break;
                case FE_QPSK:
                    if ((ctx->fe->ops.info.caps & FE_CAN_2G_MODULATION) == FE_CAN_2G_MODULATION)
                        strcpy(ctx->nim_entry.dvb_type_str, "DVB-S2");
                    else
                        strcpy(ctx->nim_entry.dvb_type_str, "DVB-S");
                    break;
                case FE_QAM:
                    strcpy(ctx->nim_entry.dvb_type_str, "DVB-C");
                    break;
                default:
                    strcpy(ctx->nim_entry.dvb_type_str, "unkn");
                    break;
            }
            ctx->nim_entry.frontendIndex = 0;
            ctx->nim_entry.has_outputs = ctx->has_outputs;
            ctx->nim_entry.i2cDevice = 0;
            ctx->nim_entry.internally_connectable = 0;

            memset(&ctx->nim_entry.modes, 0, sizeof(ctx->nim_entry.modes));
            for (i = 0; i < ctx->num_modes; i++) {
                strcpy(ctx->nim_entry.modes[i], ctx->ctypes[i]);
            }
            memset(ctx->nim_entry.name, 0, sizeof(ctx->nim_entry.name));
            strcpy(ctx->nim_entry.name, ctx->name);

            ctx->nim_entry.socket_no = 0;
            ctx->nim_entry.verdor = 0;

            ret = registerNimSocketForModule(&ctx->nim_entry_token, &ctx->nim_entry);

            if (ret) {
                printLog(ERROR, "Error registering new nim_socket: %d\n", ret);
                dvb_unregister_frontend(ctx->fe);
            }

            else {
                ctx->initialized = 1;
            }
	    }
	}

	return ret;
}

int /*__devinit*/ otunerc_frontend_clear(struct otunerc_ctx *ctx)
{
	int ret;
	struct dvb_proxyfe_state *state;
    struct dvb_adapter *adapter;

    adapter = NULL;
	if (ctx->initialized) {
	    unregisterNimSocketForModule(&ctx->nim_entry_token);
	    ret = dvb_unregister_frontend(ctx->fe);
	}
	else
	    ret = 0;
	if (ctx->initialized && !ret) {
	    ctx->initialized = 0;
        adapter = ctx->dvb_adapter;
	    ctx->dvb_adapter = NULL;

	    state = ctx->fe->demodulator_priv;
	    kfree(state);
	    ctx->fe = NULL;

	}

	return ret;
}
// kate: indent-mode cstyle; indent-width 4; replace-tabs on;
