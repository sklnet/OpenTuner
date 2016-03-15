#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <errno.h>
#include <syslog.h>
#include <getopt.h>
#include <linux/dvb/dmx.h>
#include <linux/dvb/frontend.h>
#include <linux/dvb/version.h>

#include "openusbtunerapi.h"
#include "logs.h"

#define SYS_USB_DEVICES_DIR_NEW "/sys/bus/usb/devices"
#define SYS_USB_DEVICES_DIR_OLD "/sys/class/usb_device"

#define SYS_USB_DVB_ROOT_DIR "italysat-dvb"
#define OTUNER_PATH "/dev/misc"
#define MAX_ADAPTERS 8
#define BUFFER_SIZE ((188 / 4) * 4096) /* multiple of ts packet and page size */
#define DEMUX_BUFFER_SIZE (8 * ((188 / 4) * 4096)) /* 1.5MB */

#define UNSAFE_IOCTL(ret, cmd, message) ret = (cmd); if (ret) perror (message)
#define SAFE_IOCTL(cmd, message, label) if (cmd) { perror (message); goto label; }

#define USBHELPER_VERSION "1.0"

#if DVB_API_VERSION < 5
typedef enum {
	DMX_TAP_TS = 0,
	DMX_TAP_PES = DMX_PES_OTHER, /* for backward binary compat. */
} dmx_tap_type_t;
#endif

struct vtuner_adapter
{
    opentuner_def_t tuner_def;
    int real_usb_adapter_index;
	int real_usb_frontend_index;
	int real_usb_demux_index;
    int vtunerindex;
    char *buffer;
    int fd_frontend;
    int fd_demux;
    int fd_vtuner;
    pthread_t eventthread, pumpthread;
    __u16 pidlist[30];
	int initialized;
};

struct client_config {
	int adaptercount;
	int vtunercount;

	int running;
	struct vtuner_adapter adapters[MAX_ADAPTERS];

	int debugLevel;
	int adapter_hw_nr;
	int demux_hw_nr;
	int demonize;

	char *dvb_subfolder_name;
	int forced_kernel_version;
};

static struct client_config config = {
	.adaptercount = 0,
	.vtunercount = 0,
	.running = 1,
	.adapter_hw_nr = 0,
	.demux_hw_nr = 0,
	.debugLevel = INFO | ERROR | CRITICAL,
	.demonize = 1,
	.dvb_subfolder_name = NULL,
	.forced_kernel_version = 0
};

void debug_fe_properties(struct dtv_properties *props) {
	int i;
	struct dtv_property *prop;
	printLog(FINE, "\tDebug dtv_properties: %p pointer address\n", props);
	if (props != NULL) {
		printLog(FINE, "\tDebug dtv_properties: %d properties\n", props->num);
		for (i = 0; i < props->num; i++) {
			prop = &props->props[i];
			printLog(FINE, "\tproperty %d: cmd = %d, value = %d\n", i, prop->cmd, prop->u.data);
		}
	}
}

void sigint_handler(int sig)
{
	printLog(ERROR, "Application error: %d (%s)\n", sig, strerror(sig));
	config.running = 0;
}

void sort_adapters()
{
	printLog(FINE, "Sorting %d adapters found\n", config.adaptercount);
	int i;
	for (i = config.adaptercount - 1; i > 0; i--)
	{
		int j;
		for (j = 0; j < i; j++)
		{
			if (config.adapters[j].real_usb_adapter_index > config.adapters[j + 1].real_usb_adapter_index)
			{
				char name[128];
				int index;
				strcpy(name, config.adapters[j].tuner_def.name);
				index = config.adapters[j].real_usb_adapter_index;

				strcpy(config.adapters[j].tuner_def.name, config.adapters[j + 1].tuner_def.name);
				config.adapters[j].real_usb_adapter_index = config.adapters[j + 1].real_usb_adapter_index;

				strcpy(config.adapters[j + 1].tuner_def.name, name);
				config.adapters[j + 1].real_usb_adapter_index = index;
			}
		}
	}
}

int scan_adapters()
{
	DIR *dirusb, *dirdev, *dirvtun;
	struct dirent *edirusb, *edirdev, *edirvtun;
	int i;

	printLog(INFO, "Scan for adapters (old kernel)\n");

	/* adapters detect */
	dirusb = opendir(SYS_USB_DEVICES_DIR_OLD);
	if (!dirusb) {
		printLog(ERROR, "Could not open %s system folder\n", SYS_USB_DEVICES_DIR_OLD);
		return -1;
	}

	while ((edirusb = readdir(dirusb)) != NULL && config.adaptercount < MAX_ADAPTERS)
	{
		char devdir[256];
		if (edirusb->d_name[0] == '.') continue;

		printLog(FINE, "Searching for %s/%s/device/%s\n", SYS_USB_DEVICES_DIR_OLD, edirusb->d_name, config.dvb_subfolder_name);
		sprintf(devdir, "%s/%s/device/%s", SYS_USB_DEVICES_DIR_OLD, edirusb->d_name, config.dvb_subfolder_name);
		dirdev = opendir(devdir);
		if (!dirdev)
		{
			sprintf(devdir, "%s/%s/device", SYS_USB_DEVICES_DIR_OLD, edirusb->d_name);
			dirdev = opendir(devdir);
			if (!dirdev) continue;
		}

		printLog(FINE, "FOUND: Load usb device info\n");
		while ((edirdev = readdir(dirdev)) != NULL && config.adaptercount < MAX_ADAPTERS)
		{
			FILE *fd;
			char filename[256];
			int namelen = strlen(edirdev->d_name);

			if (namelen < 14) continue;
			if (strcmp(edirdev->d_name + (namelen - 9), "frontend0")) continue;

			sprintf(filename, "%s/%s/device/product", SYS_USB_DEVICES_DIR_OLD, edirusb->d_name);
			fd = fopen(filename, "r");
			if (!fd)
			{
				sprintf(filename, "%s/%s/device/manufacturer", SYS_USB_DEVICES_DIR_OLD, edirusb->d_name);
				fd = fopen(filename, "r");
			}

			if (fd)
			{
				char *tmp = config.adapters[config.adaptercount].tuner_def.name;
				fread(tmp, 63, 1, fd);
				tmp[63] = 0;
				while (strlen(tmp) > 0 && (tmp[strlen(tmp) - 1] == '\n' || tmp[strlen(tmp) - 1] == ' ')) tmp[strlen(tmp) - 1] = 0;
				fclose(fd);
			}
			else
			{
				strcpy(config.adapters[config.adaptercount].tuner_def.name, "unknown frontend");
			}

			config.adapters[config.adaptercount].real_usb_adapter_index = edirdev->d_name[namelen - 11] - '0';
			config.adapters[config.adaptercount].real_usb_demux_index = 0;
			config.adapters[config.adaptercount].real_usb_frontend_index = 0;
			config.adaptercount++;
		}
		closedir(dirdev);
	}
	closedir(dirusb);

	dirvtun = opendir(OTUNER_PATH);
	if (dirvtun)
	{
		while ((edirvtun = readdir(dirvtun)) != NULL)
		{
			if (strlen(edirvtun->d_name) < 7) continue;
			if (!strncmp(edirvtun->d_name, "otunerc", 6)) config.vtunercount++;
		}
		closedir(dirvtun);
	}

	sort_adapters();

	for (i = 0; i < config.adaptercount; i++)
	{
		if (i < config.vtunercount)
		{
			config.adapters[i].vtunerindex = i;
			printLog(INFO, "Usb device %s (adapter%d) assigned to otunerc%d\n", config.adapters[i].tuner_def.name, config.adapters[i].real_usb_adapter_index, i);
		}
		else
		{
			config.adapters[i].vtunerindex = -1;
			printLog(WARNING, "Usb device %s (adapter%d) not assigned\n", config.adapters[i].tuner_def.name, config.adapters[i].real_usb_adapter_index);
		}
	}
	return config.adaptercount;
}

int adapters_detect () {
    DIR *dirusb, *dirvtun, *dirdvb;
    struct dirent *edirusb, *edirvtun, *edirdvb;
    int i;
    FILE *fd;
    char filename[256];
    char devdir[256];
    char dvbdir[256];
    struct stat file_info;
	char manufacturer[128];

	/* adapters detect */
    dirusb = opendir (SYS_USB_DEVICES_DIR_NEW);

	printLog(INFO, "Searching for usb devices in %s\n", SYS_USB_DEVICES_DIR_NEW);

	if (!dirusb) {
		printLog(CRITICAL, "Could not open %s system folder\n", SYS_USB_DEVICES_DIR_NEW);
		return -1;
	}

	while ((edirusb = readdir (dirusb)) != NULL && config.adaptercount < MAX_ADAPTERS)
	{

		if (edirusb->d_name[0] == '.')
			continue;

		sprintf (devdir, "%s/%s", SYS_USB_DEVICES_DIR_NEW, edirusb->d_name);

		printLog(FINE, "Searching usb into %s/%s\n", devdir, config.dvb_subfolder_name);

        sprintf(dvbdir, "%s/%s", devdir, config.dvb_subfolder_name);
        if (stat(dvbdir, &file_info))
            continue;

        printf("FOUND: Load usb device info.\n");

        sprintf (filename, "%s/product", devdir);
        fd = fopen (filename, "r");
        if (!fd)
        {
            sprintf (filename, "%s/manufacturer", devdir);
            fd = fopen (filename, "r");
        }

        if (fd)
        {
			memset(manufacturer, 0, sizeof(manufacturer));
            fread (manufacturer, sizeof(manufacturer) - 1, 1, fd);
			manufacturer[sizeof(manufacturer) - 1] = '\0';
			while (strlen (manufacturer) > 0 && (manufacturer[strlen (manufacturer) - 1] == '\n' || manufacturer[strlen (manufacturer) - 1] == ' '))
				manufacturer[strlen (manufacturer) - 1] = '\0';

            fclose (fd);
        }
        else
			strcpy(manufacturer, "unknow tuner");

        sprintf (dvbdir, "%s/%s", devdir, config.dvb_subfolder_name);

        printLog(FINE, "Searching for frontend into %s.\n", dvbdir);

        dirdvb = opendir (dvbdir);
        if (!dirdvb)
            continue;
		while ((edirdvb = readdir (dirdvb)) != NULL && config.adaptercount < MAX_ADAPTERS)
        {
			if (strncmp(edirdvb->d_name + 5, "frontend", strlen("frontend")) == 0) {
				memset(config.adapters[config.adaptercount].tuner_def.name, 0, sizeof(config.adapters[config.adaptercount].tuner_def.name));
				strcpy(config.adapters[config.adaptercount].tuner_def.name, manufacturer);
				config.adapters[config.adaptercount].real_usb_adapter_index = edirdvb->d_name[3] - 48; // Carattere '0'
				config.adapters[config.adaptercount].real_usb_frontend_index = edirdvb->d_name[5 + strlen("frontend")] - 48;
				config.adapters[config.adaptercount].real_usb_demux_index = 0;
				config.adaptercount++;
                printLog(INFO, "New frontend found: building new adapter.\n");
            }
        }
        closedir(dirdvb);
	}
	closedir (dirusb);

	/* vtuners count */
	dirvtun = opendir (OTUNER_PATH);
	if (dirvtun)
	{
		while ((edirvtun = readdir (dirvtun)) != NULL)
		{
			if (strlen (edirvtun->d_name) < 7)
				continue;

			if (memcmp (edirvtun->d_name, "vtuner", 6) == 0)
				config.vtunercount++;
		}
		closedir (dirvtun);
	}

	sort_adapters();

	for (i = 0; i < config.adaptercount; i++)
	{
		if (i < config.vtunercount)
		{
			config.adapters[i].fd_vtuner = i;
			printLog(INFO, "Found usb device %s (adapter %d assigned to vtuner %d)\n", config.adapters[i].tuner_def.name, config.adapters[i].real_usb_adapter_index, i);
		}
		else
		{
			config.adapters[i].fd_vtuner = -1;
			printLog(INFO, "Found usb device %s (adapter %d but no vtuner free)\n", config.adapters[i].tuner_def.name, config.adapters[i].real_usb_adapter_index);
		}
	}
	return config.adaptercount;
}

ssize_t _writeall(int fd, const void *buf, size_t count)
{
	ssize_t retval;
	char *ptr = (char*)buf;
	ssize_t handledcount = 0;
	if (fd < 0) return -1;
	while (handledcount < count)
	{
		retval = write(fd, &ptr[handledcount], count - handledcount);

		if (retval == 0) return -1;
		if (retval < 0)
		{
			if (errno == EINTR) continue;
			perror("write");
			return retval;
		}
		handledcount += retval;
	}
	return handledcount;
}

ssize_t _read(int fd, void *buf, size_t count)
{
	ssize_t retval;
	char *ptr = (char*)buf;
	ssize_t handledcount = 0;
	if (fd < 0) return -1;
	while (handledcount < count)
	{
		retval = read(fd, &ptr[handledcount], count - handledcount);
		if (retval < 0)
		{
			if (errno == EINTR) continue;
			perror("read");
			return retval;
		}
		handledcount += retval;
		break; /* one read only */
	}
	return handledcount;
}

void *pump_proc(void *ptr)
{
	struct vtuner_adapter *adapter = (struct vtuner_adapter *)ptr;
	struct pollfd pfd[] = {{adapter->fd_demux, POLLIN}};

	while (config.running)
	{
		struct timeval tv;
		fd_set rset;
		FD_ZERO(&rset);
		FD_SET(adapter->fd_demux, &rset);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		poll(pfd, 1, 2000);
		if (pfd[0].revents & POLLIN)
		{
			int size = _read(adapter->fd_demux, adapter->buffer, BUFFER_SIZE);
			printLog(FINE, "Writing %d bytes to real demux (from adapter%d/demux%d)\n", size, adapter->real_usb_adapter_index, adapter->real_usb_demux_index);
			if (_writeall(adapter->fd_vtuner, adapter->buffer, size) <= 0)
			{
				printLog(ERROR, "Error writing bytes to real demux (from adapter%d/demux%d)\n", adapter->real_usb_adapter_index, adapter->real_usb_demux_index);
				break;
			}
			else {
				printLog(FINE, "Writing %d bytes to real demux done (from adapter%d/demux%d)\n", size, adapter->real_usb_adapter_index, adapter->real_usb_demux_index);
			}
		}
	}

	return NULL;
}

void *event_proc(void *ptr)
{
	int i, j;
	struct vtuner_adapter *adapter = (struct vtuner_adapter*)ptr;

	struct dtv_properties cached_prop;

	cached_prop.num = 0;
	cached_prop.props = malloc(DTV_IOCTL_MAX_MSGS * sizeof(struct dtv_property));

	struct pollfd pfd[] = {{adapter->fd_vtuner, POLLPRI}};

	while (config.running)
	{
		struct timeval tv;
		fd_set xset;
		FD_ZERO(&xset);
		FD_SET(adapter->fd_vtuner, &xset);
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		poll(pfd, 1, 1000);

		if (pfd[0].revents & POLLPRI)
		{
			struct opentuner_message message;
			cached_prop.num = 0;
			message.body.prop = &cached_prop;
			ioctl(adapter->fd_vtuner, OPENTUNER_GET_MESSAGE, &message);

			switch (message.type)
			{
			case MSG_SET_FRONTEND:
				printLog(FINE, "New message: FE_SET_FRONTEND on otunerc%d (adapter%d/frontend%d) (freq. = %d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index,
						 message.body.fe_params.frequency);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_SET_FRONTEND, &message.body.fe_params), "FE_SET_FRONTEND");
				break;
			case MSG_GET_FRONTEND:
				printLog(FINE, "New message: FE_GET_FRONTEND on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_GET_FRONTEND, &message.body.fe_params), "FE_GET_FRONTEND");
				break;
			case MSG_READ_STATUS:
				printLog(FINE, "New message: FE_READ_STATUS on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_READ_STATUS, &message.body.status), "FE_READ_STATUS");
				break;
			case MSG_READ_BER:
				printLog(FINE, "New message: FE_READ_BER on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_READ_BER, &message.body.ber), "FE_READ_BER");
				break;
			case MSG_READ_SIGNAL_STRENGTH:
				printLog(FINE, "New message: FE_READ_SIGNAL_STRENGTH on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_READ_SIGNAL_STRENGTH, &message.body.ss), "FE_READ_SIGNAL_STRENGTH");
				break;
			case MSG_READ_SNR:
				printLog(FINE, "New message: FE_READ_SNR on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_READ_SNR, &message.body.snr), "FE_READ_SNR");
				break;
			case MSG_READ_UCBLOCKS:
				printLog(FINE, "New message: FE_READ_UNCORRECTED_BLOCKS on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_READ_UNCORRECTED_BLOCKS, &message.body.ucb), "FE_READ_UNCORRECTED_BLOCKS");
				break;
			case MSG_SET_TONE:
				printLog(FINE, "New message: FE_SET_TONE on otunerc%d (adapter%d/frontend%d) [value=%d]\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index, message.body.tone);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_SET_TONE, message.body.tone), "FE_SET_TONE");
				break;
			case MSG_SEND_DISEQC_MSG:
				printLog(FINE, "New message: FE_DISEQC_SEND_MASTER_CMD on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_DISEQC_SEND_MASTER_CMD, &message.body.diseqc_master_cmd), "FE_DISEQC_SEND_MASTER_CMD");
				break;
			case MSG_SEND_DISEQC_BURST:
				printLog(FINE, "New message: FE_DISEQC_SEND_BURST on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_DISEQC_SEND_BURST, message.body.burst), "FE_DISEQC_SEND_BURST");
				break;
			case MSG_PIDLIST:
				printLog(FINE, "New message: MSG_PIDLIST on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				/* remove old pids */
				for (i = 0; i < 30; i++)
				{
					int found = 0;
					if (adapter->pidlist[i] == 0xffff) continue;
					for (j = 0; j < 30; j++)
					{
						if (adapter->pidlist[i] == message.body.pidlist[j])
						{
							found = 1;
							break;
						}
					}

					if (found) continue;

					printLog(FINE, "DMX_REMOVE_PID %x\n", adapter->pidlist[i]);
#if DVB_API_VERSION > 3
					UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_demux, DMX_REMOVE_PID, &adapter->pidlist[i]), "DMX_REMOVE_PID");
#else
					UNSAFE_IOCTL(message.exit_code, ioctl(adapter->demux, DMX_REMOVE_PID, adapter->pidlist[i]), "DMX_REMOVE_PID");
#endif
				}

				/* add new pids */
				for (i = 0; i < 30; i++)
				{
					int found = 0;
					if (message.body.pidlist[i] == 0xffff) continue;
					for (j = 0; j < 30; j++)
					{
						if (message.body.pidlist[i] == adapter->pidlist[j])
						{
							found = 1;
							break;
						}
					}

					if (found) continue;

					printLog(FINE, "DMX_ADD_PID %x\n", message.body.pidlist[i]);
#if DVB_API_VERSION > 3
					UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_demux, DMX_ADD_PID, &message.body.pidlist[i]), "DMX_ADD_PID");
#else
					UNSAFE_IOCTL(message.exit_code, ioctl(adapter->demux, DMX_ADD_PID, message.body.pidlist[i]), "DMX_ADD_PID");
#endif
				}

				/* copy pids */
				for (i = 0; i < 30; i++)
				{
					adapter->pidlist[i] = message.body.pidlist[i];
				}
				break;
			case MSG_SET_VOLTAGE:
				printLog(FINE, "New message: FE_SET_VOLTAGE on otunerc%d (adapter%d/frontend%d) [value = %d]\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index, message.body.voltage);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_SET_VOLTAGE, message.body.voltage), "FE_SET_VOLTAGE");
				break;
			case MSG_ENABLE_HIGH_VOLTAGE:
				printLog(FINE, "New message: FE_ENABLE_HIGH_LNB_VOLTAGE on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_ENABLE_HIGH_LNB_VOLTAGE, message.body.voltage), "FE_ENABLE_HIGH_LNB_VOLTAGE");
				break;
			case MSG_SET_PROPERTY:
#if DVB_API_VERSION >= 5
				{
					printLog(FINE, "New message: FE_SET_PROPERTY on otunerc%d (adapter%d/frontend%d)\n",
							 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
					debug_fe_properties(message.body.prop);
					UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_SET_PROPERTY, message.body.prop), "FE_SET_PROPERTY");
				}
#endif
				break;
			case MSG_GET_PROPERTY:
#if DVB_API_VERSION >= 5
				{
					printLog(FINE, "New message: FE_GET_PROPERTY on otunerc%d (adapter%d/frontend%d)\n",
							 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
					UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_GET_PROPERTY, message.body.prop), "FE_GET_PROPERTY");
					debug_fe_properties(message.body.prop);
				}
#endif
				break;
			case MSG_DISEQC_RESET_OVERLOAD:
			{
				printLog(FINE, "New message: FE_DISEQC_RESET_OVERLOAD on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_DISEQC_RESET_OVERLOAD), "FE_DISEQC_RESET_OVERLOAD");
			}
			break;
			case MSG_DISEQC_RECV_SLAVE_REPLY:
			{
				printLog(FINE, "New message: FE_DISEQC_RECV_SLAVE_REPLY on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_DISEQC_RECV_SLAVE_REPLY, &message.body.slave_reply), "FE_DISEQC_RECV_SLAVE_REPLY");
			}
			break;
			case MSG_ENABLE_HIGH_LNB_VOLTAGE:
			{
				printLog(FINE, "New message: FE_GET_PROPERTY on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_GET_PROPERTY, &message.body.prop), "FE_GET_PROPERTY");
			}
			break;
			case MSG_SET_FRONTEND_TUNE_MODE:
			{
				printLog(FINE, "New message: FE_SET_FRONTEND_TUNE_MODE on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_SET_FRONTEND_TUNE_MODE, message.body.tune_mode), "FE_SET_FRONTEND_TUNE_MODE");
			}
			break;
			case MSG_GET_EVENT:
			{
				printLog(FINE, "New message: FE_GET_EVENT on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_GET_EVENT, &message.body.fe_event), "FE_GET_EVENT");
				if (message.exit_code) {
					message.body.fe_event.status = 0;
					memset(&message.body.fe_event.parameters, 0, sizeof(message.body.fe_event.parameters));
					message.exit_code = -EWOULDBLOCK;
				}
			}
			break;
			case MSG_DISHNETWORK_SEND_LEGACY_CMD:
			{
				printLog(FINE, "New message: FE_DISHNETWORK_SEND_LEGACY_CMD on otunerc%d (adapter%d/frontend%d)\n",
						 adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				UNSAFE_IOCTL(message.exit_code, ioctl(adapter->fd_frontend, FE_DISHNETWORK_SEND_LEGACY_CMD, message.body.legacy_cmd), "FE_DISHNETWORK_SEND_LEGACY_CMD");
			}
			break;

			default:
				printLog(ERROR, "New unknow message: <%d> on otunerc%d (adapter%d/frontend%d)\n",
						 message.type, adapter->vtunerindex, adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
				break;
			}

			if (message.type != MSG_PIDLIST)
			{
				if (message.type != MSG_GET_PROPERTY && message.type != MSG_SET_PROPERTY)
					message.type = 0;
				int response_exit_code;
				printLog(FINE, "Send to otunerc response\n");
				UNSAFE_IOCTL(response_exit_code, ioctl(adapter->fd_vtuner, OPENTUNER_SET_RESPONSE, &message), "RESPONSE");
				message.type = 0;
			}
		}
	}

	free(cached_prop.props);

	return NULL;
}

int init_adapter(int id)
{
	struct dmx_pes_filter_params filter;
	struct dvb_frontend_info fe_info;
	char frontend_filename[256], demux_filename[256], vtuner_filename[256];

	struct vtuner_adapter *adapter = &config.adapters[id];

	adapter->eventthread = 0;
	adapter->pumpthread = 0;

	printLog(INFO, "Linking adapter%d/frontend0 to otunerc%d\n", adapter->real_usb_adapter_index, adapter->vtunerindex);

	sprintf(frontend_filename, "/dev/dvb/adapter%d/frontend%d", adapter->real_usb_adapter_index, adapter->real_usb_frontend_index);
	sprintf(demux_filename, "/dev/dvb/adapter%d/demux%d", adapter->real_usb_adapter_index, adapter->real_usb_demux_index);
	sprintf(vtuner_filename, "/dev/misc/otunerc%d", adapter->vtunerindex);

	adapter->fd_frontend = adapter->fd_demux = adapter->fd_vtuner = -1;

	adapter->fd_frontend = open(frontend_filename, O_RDWR | O_NONBLOCK);
	if (adapter->fd_frontend < 0)
	{
		perror(frontend_filename);
		goto error;
	}

	adapter->fd_demux = open(demux_filename, O_RDONLY | O_NONBLOCK);
	if (adapter->fd_demux < 0)
	{
		perror(demux_filename);
		goto error;
	}

	adapter->fd_vtuner = open(vtuner_filename, O_RDWR);
	if (adapter->fd_vtuner < 0)
	{
		perror(vtuner_filename);
		goto error;
	}

	if (ioctl(adapter->fd_frontend, FE_GET_INFO, &fe_info) < 0)
	{
		perror("FE_GET_INFO");
		goto error;
	}

	filter.input = DMX_IN_FRONTEND;
	filter.flags = 0;
#if DVB_API_VERSION > 3
	filter.pid = 0;
	filter.output = DMX_OUT_TSDEMUX_TAP;
	filter.pes_type = DMX_PES_OTHER;
#else
	filter.pid = -1;
	filter.output = DMX_OUT_TAP;
	filter.pes_type = DMX_TAP_TS;
#endif

	SAFE_IOCTL(ioctl(adapter->fd_demux, DMX_SET_BUFFER_SIZE, DEMUX_BUFFER_SIZE), "Init otunerc: DMX_SET_BUFFER_SIZE", error);
	SAFE_IOCTL(ioctl(adapter->fd_demux, DMX_SET_PES_FILTER, &filter), "Init otunerc: DMX_SET_PES_FILTER", error);
	SAFE_IOCTL(ioctl(adapter->fd_demux, DMX_START), "Init otunerc: DMX_START", error);

	adapter->tuner_def.adapter_hw_nr = 0;
	adapter->tuner_def.demux_hw_nr = 0;
	adapter->tuner_def.fe_type = fe_info.type;
	adapter->tuner_def.has_output = 0;
	memcpy(&adapter->tuner_def.real_fe_info, &fe_info, sizeof(struct dvb_frontend_info));

	SAFE_IOCTL(ioctl(adapter->fd_vtuner, OPENTUNER_SETUP_FRONTEND, &adapter->tuner_def), "Init otunerc: OPENTUNER_SETUP_FRONTEND", error);

	memset(adapter->pidlist, 0xff, sizeof(adapter->pidlist));
	adapter->buffer = malloc(BUFFER_SIZE);

	printf("init succeeded\n");
	pthread_create(&adapter->eventthread, NULL, event_proc, (void*)adapter);
	pthread_create(&adapter->pumpthread, NULL, pump_proc, (void*)adapter);
	adapter->initialized = 1;
	return 0;

error:
	if (adapter->fd_vtuner >= 0)
	{
		close(adapter->fd_vtuner);
		adapter->fd_vtuner = -1;
	}
	if (adapter->fd_demux >= 0)
	{
		close(adapter->fd_demux);
		adapter->fd_demux = -1;
	}
	if (adapter->fd_frontend >= 0)
	{
		close(adapter->fd_frontend);
		adapter->fd_frontend = -1;
	}
	adapter->initialized = 0;
	printf("init failed\n");
	return -1;
}

void daemon_init()
{
	pid_t pid;

	if ((pid = fork()) == 0) _exit(EXIT_SUCCESS);

	setsid(); /* become session leader */

	umask(0);

	/* forks, chdirs to /, closes files */
	daemon(0, 0);

	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
}

void print_version(void) {
	printf("USB Tuner Helper for Otuner-drv (c) v. %s\n(Build using DVBAPI %d.%d)\n", USBHELPER_VERSION, DVB_API_VERSION, DVB_API_VERSION_MINOR);
}

void print_help(char *prg) {
	printf("Usage %s [{--debug|-l} <debug-level>] [{--adapter|-a} <adapter-index>] [{--demux|-d} <demux-index>] [{--foreground|-f}] [{--kernel|-k} <kernel-type>] [{--dvb-folder|-b} <dvb-folder>] [{--help|-h}] [{--version|-v}]\n", prg);
	printf("\n");
	printf("where:\n");
	printf("\n");
	printf("\t--debug | -l <debug-level>        sets the <debug-level> (int value) to desidered bitwise value as following\n");
	printf("\t                                  INFO     = 1  (notice messages)\n");
	printf("\t                                  WARNING  = 2  (warning messages)\n");
	printf("\t                                  FINE     = 4  (fine details messages)\n");
	printf("\t                                  ERROR    = 8  (error messages)\n");
	printf("\t                                  CRITICAL = 16 (serious problems messages)\n");
	printf("\n");
	printf("\t--adapter | -a <adapter-index>    set the index of the embedded dvb adapter with the mpeg decoding capable (default 0)\n");
	printf("\n");
	printf("\t--demux | -d <demux-index>        set the  index of the harwdare demux corresponding the embedded adapter (default 0)\n");
	printf("\n");
	printf("\t--foreground | -f                 run the client in foreground mode (not demonize)\n");
	printf("\n");
	printf("\t--kernel | -k <kernel-type>       force discovery kernel mode subsystem:\n");
	printf("\t                                  1 = '%s'\n", SYS_USB_DEVICES_DIR_NEW);
	printf("\t                                  2 = '%s'\n", SYS_USB_DEVICES_DIR_OLD);
	printf("\t                                  0 = AUTO (default)\n");
	printf("\n");
	printf("\t--dvb-folder | -b <dvb-folder>    overwrite default subsystem folder for discovery devices (default 'it-dvb')\n");
	printf("\n");
	printf("\t--version | -v                    print the version of this client and exit\n");
	printf("\n");
	printf("\t--help | -h                       print this help and exit\n");
}

int parse_arguments(int argc, char **argv)
{
	int c;
	int exit_code;

	exit_code = 0;
	int do_parse = 1;
	while (do_parse) {
		int option_index = 0;
		static struct option long_options[] = {
			{"debug",   optional_argument, 0,  'l' },
			{"foreground",  no_argument,       0,  'f' },
			{"help",  no_argument, 0,  'h' },
			{"version",  no_argument, 0, 'v'},
			{"adapter",    required_argument, 0,  'a' },
			{"demux",    required_argument, 0,  'd' },
			{"kernel", required_argument, 0, 'k'},
			{"dvb-folder", required_argument, 0, 'b'},
			{0,         0,                 0,  0 }
		};

		c = getopt_long(argc, argv, "a:b:d:hfk:l:v", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'a':
				config.adapter_hw_nr = strtol(optarg, NULL, 10);
				if (errno) {
					exit_code = errno;
					printf("Invalid adapter nr. %s\n", optarg);
					do_parse = 0;
				}
				break;

			case 'b':
				if (optarg != NULL && strlen(optarg) > 0) {
					config.dvb_subfolder_name = malloc(strlen(optarg) + 1);
					if (config.dvb_subfolder_name == NULL) {
						exit_code = -ENOMEM;
						printf("Out ot memory\n");
						do_parse = 0;
					}
					else {
						memset(config.dvb_subfolder_name, 0, strlen(optarg) + 1);
						strcpy(config.dvb_subfolder_name, optarg);
					}
				}
				break;

			case 'd':
				config.demux_hw_nr = strtol(optarg, NULL, 10);
				if (errno) {
					exit_code = errno;
					printf("Invalid demux nr. %s\n", optarg);
					do_parse = 0;
				}
				break;

			case 'f':
				config.demonize = 0;
				break;

			case 'h':
				print_help(argv[0]);
				exit_code = 1;
				break;

			case 'k':
				config.forced_kernel_version = strtol(optarg, NULL, 10);
				if (errno) {
					exit_code = errno;
					printf("Invalid kernel discovery mode: %s\n", optarg);
					do_parse = 0;
				}
				else if (config.forced_kernel_version < 0 || config.forced_kernel_version > 2) {
					exit_code = -EINVAL;
					printf("Invalid kernel discovery mode (exptected an int between 0 and 2)\n");
					do_parse = 0;
				}
				break;

			case 'l':
				if (optarg != NULL) {
					config.debugLevel = strtol(optarg, NULL, 10);
					if (errno) {
						exit_code = errno;
						printf("Invalid debug level %s\n", optarg);
						do_parse = 0;
					}
					else
						printf("DEBUG level changed to %d\n", config.debugLevel);
				}
				break;

			case 'v':
				print_version();
				exit_code = 1;
				break;

			default:
				printf("?? Unknow option 0%o ??\n", c);
				exit_code = -EINVAL;
				break;
		}
	}

	if (optind < argc) {
		printf("Unknow options: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
		exit_code = -EINVAL;
	}

	return exit_code;
}

int main(int argc, char *argv[])
{
	print_version();

	struct stat file_info;
	int i;
	int ok = 0;
	int useNewKernelPath = 0;

	i = parse_arguments(argc, argv);
	if (i) {
		if (i > 0)
			exit(0);
		else
			exit (i);
	}

	setLevelLog(&config.debugLevel);

	if (config.demonize)
		daemon_init();

	signal(SIGTERM, sigint_handler);
	signal(SIGINT, sigint_handler);

	if (config.forced_kernel_version == 0) {
		if (stat(SYS_USB_DEVICES_DIR_NEW, &file_info))
			useNewKernelPath = 1;
		else
			useNewKernelPath = 0;
	}
	else {
		if (config.forced_kernel_version == 1)
			useNewKernelPath = 1;
		else
			useNewKernelPath = 0;
	}

	if (config.dvb_subfolder_name == NULL) {
		if (useNewKernelPath)
			config.dvb_subfolder_name = SYS_USB_DEVICES_DIR_NEW;
		else
			config.dvb_subfolder_name = SYS_USB_DEVICES_DIR_OLD;
	}

	while (config.running)
	{
	    if (useNewKernelPath && adapters_detect() > 0)
		break;
	    else if (!useNewKernelPath && scan_adapters() > 0)
		break;

	    sleep(5);
	}

	for (i = 0; i < config.adaptercount; i++)
	{
		if (config.adapters[i].vtunerindex >= 0)
			init_adapter(i);
	}

	for (i = 0; i < config.adaptercount; i++)
	{
		if (config.adapters[i].vtunerindex >= 0 && config.adapters[i].initialized)
		{
			ok = 1;
			if (config.adapters[i].eventthread && config.adapters[i].pumpthread)
			{
				pthread_join(config.adapters[i].eventthread, NULL);
				pthread_join(config.adapters[i].pumpthread, NULL);

				free(config.adapters[i].buffer);
				close(config.adapters[i].fd_vtuner);
				close(config.adapters[i].fd_demux);
				close(config.adapters[i].fd_frontend);
			}
		}
	}

	exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
}
