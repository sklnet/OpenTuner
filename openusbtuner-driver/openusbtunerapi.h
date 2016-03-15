#include <linux/ioctl.h>
#include <linux/dvb/version.h>
#include <linux/dvb/frontend.h>
#include <linux/dvb/dmx.h>

#ifndef _OPENUSBTUNERAPI_H
#define _OPENUSBTUNERAPI_H

#define MSG_SET_FRONTEND            1
#define MSG_GET_FRONTEND            2
#define MSG_READ_STATUS             3
#define MSG_READ_BER                4
#define MSG_READ_SIGNAL_STRENGTH	5
#define MSG_READ_SNR                6
#define MSG_READ_UCBLOCKS           7
#define MSG_SET_TONE                8
#define MSG_SET_VOLTAGE             9
#define MSG_ENABLE_HIGH_VOLTAGE		10
#define MSG_SEND_DISEQC_MSG         11
#define MSG_SEND_DISEQC_BURST		13
#define MSG_PIDLIST                 14
#define MSG_SET_PROPERTY            15
#define MSG_GET_PROPERTY            16
#define MSG_DISEQC_RESET_OVERLOAD   17
#define MSG_DISEQC_RECV_SLAVE_REPLY 18
#define MSG_ENABLE_HIGH_LNB_VOLTAGE 19
#define MSG_SET_FRONTEND_TUNE_MODE  20
#define MSG_GET_EVENT               21
#define MSG_DISHNETWORK_SEND_LEGACY_CMD 22


#define MSG_NULL                    1024
#define MSG_DISCOVER                1025
#define MSG_UPDATE                  1026

/**
 * OpenTuner settings for one-shot driver setup.
 */
typedef struct opentuner_def {
    char name[128];		// The name for frontend [NULL to use real_fe_info.name
    fe_type_t fe_type;		// The type of the frontend (if different from real_fe_info.type a conversion algorithm is used, if it's available)
    int has_output;		// Set the Has_Output flag of frontend (0 = no, otherwise = yes)
    int num_modes;		// Set the number of modes of the tuners (default 0)
    char **modes;		// The list of names for modes (DVB-T, DVB-T2, DVB-S, DVB-S2, DVB-C)
    int adapter_hw_nr;		// The hardware adapter for decoding mpeg-ts stream (default 0)
    int demux_hw_nr;		// The hardware demux of the hardware adapter with the demux capabilities (default 0)
    struct dvb_frontend_info real_fe_info;	// Frontend Info of the USB device.
} opentuner_def_t;

typedef struct opentuner_message {
	int type;
	union {
		struct dvb_frontend_parameters fe_params;
		struct dtv_properties *prop;
		fe_status_t status;
		__u32 ber;
		__u16 ss;
		__u16 snr;
		__u32 ucb;
		__u8 tone;
		__u8 voltage;
		struct dvb_diseqc_master_cmd diseqc_master_cmd;
		__u8 burst;
		__u16 pidlist[30];
		__u8  pad[72];
		__u32 type_changed;
		struct dvb_frontend_event fe_event;
		struct dvb_diseqc_slave_reply slave_reply;
		int high_voltage;
		unsigned int tune_mode;
		unsigned int legacy_cmd;
	} body;
	int exit_code;
} opentuner_message_t;

#define OPENTUNER_MAJOR		11

#define OPENTUNER_GET_MESSAGE       _IOR(OPENTUNER_MAJOR, 1, opentuner_message_t *)
#define OPENTUNER_SET_RESPONSE      _IOW(OPENTUNER_MAJOR, 2, opentuner_message_t *)
#define OPENTUNER_SETUP_FRONTEND    _IOW(OPENTUNER_MAJOR, 3, opentuner_def_t *)

#endif