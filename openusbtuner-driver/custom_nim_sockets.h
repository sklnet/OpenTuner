/*
 * File:   custom_nim_sockets.h
 * Author: discovery
 *
 * Created on 31 gennaio 2012, 17.32
 */

#ifndef CUSTOM_NIM_SOCKETS_H
#define	CUSTOM_NIM_SOCKETS_H

#include <linux/types.h>
#include <asm/types.h>

#define MAX_SOCKET_NAME 127
#define MAX_MODES_TYPE 5
#define MAX_MODE_NAME 6

/**
 * Define a nim socket entry (DVB type, name, modes, etc.)
 */
typedef struct nim_socket_entry {
    int verdor;                                                 // 0 for custom socket. 1 for vendor socket.
    int socket_no;                                              // Socket index. For read only use. May change. Internal use.
    char dvb_type_str[10];                                      // DVB-Type (es DVB-S, DVB-S2, DVB-T, DVB-T2, DVB-C).
    char name[MAX_SOCKET_NAME + 1];                             // Socket name (customizable).
    int has_outputs;                                            // Flag has outputs.
    int frontendIndex;                                          // Frontend index. For read only use. May change. Internal use.
    int i2cDevice;                                              // i2c device index.
    int internally_connectable;                                 // Flag internally connectable
    char modes[MAX_MODES_TYPE][MAX_MODE_NAME + 1];              // List of compatible modes
} nim_socket_entry_t;

#define NIM_SOCKET_PROC_IOCTL "nim_sockets"

#define GET_NIM_SOCKETS_ENTRIES_COUNT _IOR('o', 1, int)                         // Return the number of registered sockets
#define GET_NIM_SOCKET_ENTRY          _IOR('o', 2, nim_socket_entry_t)          // Read current socket entry
#define SET_NIM_SOCKET_ENTRY          _IOWR('o', 3, nim_socket_entry_t)         // Write current socket entry
#define DEL_NIM_SOCKET_ENTRY          _IO('o', 4)                               // Delete current socket entry
#define RESTORE_ORIGINAL_NIM_SOCKETS  _IO('o', 5)                               // Force to use original nim_sockets
#define RESTORE_CUSTOM_NIM_SOCKETS    _IO('o', 6)                               // Patch the nim_sockets

#endif	/* CUSTOM_NIM_SOCKETS_H */

