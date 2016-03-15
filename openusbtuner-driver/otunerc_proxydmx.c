#include "otunerc_proxydmx.h"

struct dvb_registered_demux_proxy {
    struct list_head demux_list;
};

struct dvb_registered_link_fe_demux {
    struct list_head link_list;
};

struct dvb_demux_proxy {
    struct list_head header;
    int adapter_num;
    struct dvb_demux *demux;
    struct dvb_device *dvbdev;
    struct dmxdev *device;
    int use_count;

    int (*start_feed_original)(struct dvb_demux_feed *feed);
    int (*stop_feed_original)(struct dvb_demux_feed *feed);
};

struct dvb_link_fe_demux_proxy {
    struct list_head header;
    struct otunerc_ctx *ctx;
    struct dvb_demux_proxy *demux_proxy;
};

static struct dvb_registered_demux_proxy know_demuxes;
static struct dvb_registered_link_fe_demux linked_demuxes;

int initialize_demux_proxy(void) {
    INIT_LIST_HEAD(&linked_demuxes.link_list);
    INIT_LIST_HEAD(&know_demuxes.demux_list);

    return 0;
}

int release_demux_proxy(void) {
    return 0;
}

static int pidtab_find_index(unsigned short *pidtab, int pid)
{
    int i = 0;

    while (i < MAX_PIDTAB_LEN) {
        if (pidtab[i] == pid)
            return i;
        i++;
    }

    return -1;
}

static int pidtab_add_pid(unsigned short *pidtab, int pid)
{
    int i;

    /* TODO: speed-up hint: add pid sorted */

    for (i = 0; i < MAX_PIDTAB_LEN; i++)
        if (pidtab[i] == PID_UNKNOWN) {
            pidtab[i] = pid;
            return 0;
        }

    return -1;
}

static int pidtab_del_pid(unsigned short *pidtab, int pid)
{
    int i;

    /* TODO: speed-up hint: delete sorted */

    for (i = 0; i < MAX_PIDTAB_LEN; i++)
        if (pidtab[i] == pid) {
            pidtab[i] = PID_UNKNOWN;
            /* TODO: move rest */
            return 0;
        }

    return -1;
}

static void pidtab_copy_to_msg(struct otunerc_ctx *ctx,
                               struct opentuner_message *msg)
{
    int i;

    for (i = 0; i < (MAX_PIDTAB_LEN - 1); i++)
        msg->body.pidlist[i] = ctx->pidtab[i]; /*TODO: optimize it*/
    msg->body.pidlist[MAX_PIDTAB_LEN - 1] = 0;
}

static struct otunerc_ctx *get_context_by_fe(struct dmx_frontend* frontend) {
    struct dvb_link_fe_demux_proxy *item;


    list_for_each_entry(item, &linked_demuxes.link_list, header) {
        if (&(item->ctx->fe_hw) == frontend)
            return item->ctx;
    }

    return NULL;
}

static int remove_context_by_fe(struct dmx_frontend* frontend) {
    struct dvb_link_fe_demux_proxy *item;
    struct dvb_link_fe_demux_proxy *tmp;

    list_for_each_entry_safe(item, tmp, &linked_demuxes.link_list, header) {
        if (&(item->ctx->fe_hw) == frontend) {
            list_del(&tmp->header);
            kfree(tmp);
            return 0;
        }
    }

    return -ENOENT;
}

static int otunerc_start_feed(struct dvb_demux_feed *feed, struct otunerc_ctx *ctx) {
    struct opentuner_message msg;

    switch (feed->type) {
    case DMX_TYPE_TS:
        break;
    case DMX_TYPE_SEC:
        break;
    case DMX_TYPE_PES:
        printk(KERN_ERR "otunerc%d: feed type PES is not supported\n",
               ctx->idx);
        return -EINVAL;
    default:
        printk(KERN_ERR "otunerc%d: feed type %d is not supported\n",
               ctx->idx, feed->type);
        return -EINVAL;
    }

    /* organize PID list table */

    if (pidtab_find_index(ctx->pidtab, feed->pid) < 0) {
        pidtab_add_pid(ctx->pidtab, feed->pid);

        pidtab_copy_to_msg(ctx, &msg);

        msg.type = MSG_PIDLIST;
        otunerc_ctrldev_xchange_message(ctx, &msg, 0);
    }

    return 0;
}

static int otunerc_stop_feed(struct dvb_demux_feed *feed, struct otunerc_ctx *ctx) {
    struct opentuner_message msg;

    /* organize PID list table */

    if (pidtab_find_index(ctx->pidtab, feed->pid) > -1) {
        pidtab_del_pid(ctx->pidtab, feed->pid);

        pidtab_copy_to_msg(ctx, &msg);

        msg.type = MSG_PIDLIST;
        otunerc_ctrldev_xchange_message(ctx, &msg, 0);
    }

    return 0;
}

static struct dvb_demux_proxy *find_proxy_for(struct dvb_demux *demux) {
    struct dvb_demux_proxy *dmx_proxy;

    list_for_each_entry(dmx_proxy, &know_demuxes.demux_list, header) {
        if (dmx_proxy->demux == demux)
            return dmx_proxy;
    }
    return NULL;
}


static int start_feed_proxy(struct dvb_demux_feed *feed) {
    struct dvb_demux_proxy *dmx_proxy;
    struct otunerc_ctx *ctx;
    int ret;

    dmx_proxy = find_proxy_for(feed->demux);
    if (dmx_proxy == NULL)
        return -EINVAL;
    else {
        // Throw message to otuner
        ctx = get_context_by_fe(feed->demux->dmx.frontend);
        if (ctx != NULL)
            ret = otunerc_start_feed(feed, ctx);
        else
            ret = -ENOENT;
        if (!ret)
            ret = dmx_proxy->start_feed_original(feed);
        return ret;
    }
}

static int stop_feed_proxy (struct dvb_demux_feed *feed) {
    struct dvb_demux_proxy *dmx_proxy;
    struct otunerc_ctx *ctx;
    int ret;

    dmx_proxy = find_proxy_for(feed->demux);
    if (dmx_proxy == NULL)
        return -EINVAL;
    else {
        // Throw message to otuner
        ctx = get_context_by_fe(feed->demux->dmx.frontend);
        ret = 0;
        if (ctx != NULL)
            ret = otunerc_stop_feed(feed, ctx);
        if (!ret)
            ret = dmx_proxy->stop_feed_original(feed);
        return ret;
    }
}


static struct dvb_demux_proxy *find_or_create_dmx_proxy(struct dvb_adapter *adapter, int demux_nr, struct dmx_frontend *fe_hw) {
    struct dvb_demux_proxy *dmx_proxy;
    struct dmxdev *dev;
    struct dvb_device *dvbdev;

    // Search demux inside well know proxy demuxes
    dmx_proxy = NULL;
    list_for_each_entry(dmx_proxy, &know_demuxes.demux_list, header) {
        if (dmx_proxy->dvbdev->id == demux_nr && dmx_proxy->dvbdev->adapter->num == adapter->num)
            break;

        dmx_proxy = NULL;
    }
    // If found, return it, otherwise, search for real demux
    if (dmx_proxy != NULL)
        return dmx_proxy;
    else {
        // Search inside dvb device list of adapter for demux with id demux_nr
        dvbdev = NULL;
        list_for_each_entry(dvbdev, &adapter->device_list, list_head) {
            if (dvbdev->type == DVB_DEVICE_DEMUX && dvbdev->id == demux_nr)
                break;
            dvbdev = NULL;
        }
        // If found, proxy it and register it inside well know proxy demuxes.
        if (dvbdev != NULL) {
            dmx_proxy = kzalloc(sizeof(struct dvb_demux_proxy), GFP_KERNEL);
            if (dmx_proxy == NULL) {
                printk(KERN_ERR "Not available memory to allocate proxy demux\n");
                return NULL;
            }
            dmx_proxy->adapter_num = adapter->num;
            dmx_proxy->dvbdev = dvbdev;
            dev = (struct dmxdev *) dvbdev->priv;	// Legal assignment according to kernel source code of dvb-api
            dmx_proxy->device = dev;
            dmx_proxy->demux = (struct dvb_demux *) dev->demux;	// Legal "casting" because the two struct are in the same memory address for definition in kernel dvb api.

            // Override operations for proxy demux
            dmx_proxy->start_feed_original = dmx_proxy->demux->start_feed;
            dmx_proxy->stop_feed_original = dmx_proxy->demux->stop_feed;
            dmx_proxy->demux->start_feed = start_feed_proxy;
            dmx_proxy->demux->stop_feed = stop_feed_proxy;

            dmx_proxy->device->demux->add_frontend(dmx_proxy->device->demux, fe_hw);

            dmx_proxy->use_count = 1;

            list_add_tail(&dmx_proxy->header, &know_demuxes.demux_list);

            return dmx_proxy;
        }
        else // Otherwise return NULL (never it'll be!!)
            return NULL;
    }
}

static int restore_dmx_proxy(struct dvb_demux_proxy *dmx_proxy, struct dmx_frontend *fe_hw) {
    int ret;

    if (dmx_proxy->use_count == 0) {

        ret = dmx_proxy->device->demux->remove_frontend(dmx_proxy->device->demux, fe_hw);

        if (!ret) {
            dmx_proxy->demux->start_feed = dmx_proxy->start_feed_original;
            dmx_proxy->demux->stop_feed = dmx_proxy->stop_feed_original;
            list_del(&dmx_proxy->header);
            ret = remove_context_by_fe(fe_hw);
            kfree(dmx_proxy);
        }
    }
    else
        ret = 0;

    return ret;
}

int /*__devinit*/ otunerc_demux_init(struct otunerc_ctx *ctx) {
    struct dvb_demux_proxy *proxy;
    struct dvb_link_fe_demux_proxy *link;

    proxy = find_or_create_dmx_proxy(ctx->dvb_adapter, ctx->hw_demux_nr, &ctx->fe_hw);
    if (proxy == NULL)
        return -ENOENT;
    else {
        link = kzalloc(sizeof(struct dvb_link_fe_demux_proxy), GFP_KERNEL);
        link->demux_proxy = proxy;
        link->ctx = ctx;

        list_add_tail(&link->header, &linked_demuxes.link_list);

        ctx->demux = proxy->demux;
        proxy->use_count++;
        return 0;
    }
}

int /*__devinit*/ otunerc_demux_clear(struct otunerc_ctx *ctx) {
    struct dvb_demux_proxy *proxy;

    proxy = find_proxy_for(ctx->demux);
    if (proxy != NULL) {
        proxy->use_count--;
        if (proxy->use_count < 0)
            proxy->use_count = 0;

        return restore_dmx_proxy(proxy, &ctx->fe_hw);
    }
    else
        return -ENOENT;
}
