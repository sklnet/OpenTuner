/* 
 * File:   proc_module.h
 * Author: discovery
 *
 * Created on 3 febbraio 2012, 17.30
 */

#ifndef PROC_MODULE_H
#define	PROC_MODULE_H

#include "custom_nim_sockets.h"
#include "linux/module.h"

/**
 * Shared nim_socket struct data between kernel modules. Used when a kernel module (dvb driver) wants
 * to register a new nim_socket entry by itself, without interfacing with vendor nim_socket proc.
 */
typedef struct nim_socket_module_entry {
    void *private;              // private use
    struct module *owner;       // nim_socket owner module
} nim_socket_module_entry_t;

/**
 * Register new nim_socket entry, according ENTRY data. The MODULE_ENTRY param will contain the link
 * between kernel module and custom nim socket proc. MODULE_ENTRY is required.
 * @param module_entry The link with nim_socket proc.
 * @param entry The nim_socket entry to register.
 * @return 0 on SUCCESS.
 */
int registerNimSocketForModule(nim_socket_module_entry_t *module_entry, nim_socket_entry_t *entry);

/**
 * Remove the registered nim_socket entry for the linked module MODULE_ENTRY.
 * @param module_entry The socket to remove.
 * @return 0 on SUCCESS.
 */
int unregisterNimSocketForModule(nim_socket_module_entry_t *module_entry);

#endif	/* PROC_MODULE_H */

