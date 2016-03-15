#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/delay.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)
#define NIM_SOCKETS_OLD_KERNEL
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif

#include "nim_sockets_proc.h"
#include "logs.h"

#define NIM_SOCKET_TOKEN "NIM Socket "
#define NIM_SOCKET_TOKEN_LEN strlen(NIM_SOCKET_TOKEN)
#define TYPE_TOKEN "Type"
#define TYPE_TOKEN_LEN strlen(TYPE_TOKEN)
#define NAME_TOKEN "Name"
#define NAME_TOKEN_LEN strlen(NAME_TOKEN)
#define HAS_OUTPUTS_TOKEN "Has_Outputs"
#define HAS_OUTPUTS_TOKEN_LEN strlen(HAS_OUTPUTS_TOKEN)
#define FRONTEND_DEVICE_TOKEN "Frontend_Device"
#define FRONTEND_DEVICE_TOKEN_LEN strlen(FRONTEND_DEVICE_TOKEN)
#define I2C_DEVICE_TOKEN "I2C_Device"
#define I2C_DEVICE_TOKEN_LEN strlen(I2C_DEVICE_TOKEN)
#define INTERNALLY_CONNECTABLE_TOKEN "Internally_Connectable"
#define INTERNALLY_CONNECTABLE_TOKEN_LEN strlen(INTERNALLY_CONNECTABLE_TOKEN)
#define MODE_TYPE_TOKEN "Mode "
#define MODE_TYPE_TOKEN_LEN strlen(MODE_TYPE_TOKEN)

// Sintassi Mode: Mode XX:type

#define NIM_SOCKET_PROC_FAKE "bus/nim_sockets_fake"
#define NIM_SOCKET_PROC_NAME "nim_sockets"

#define MAJOR_CHDEV_NUMBER 221

//#define do_sleep msleep(5 * 1000);
#define do_sleep do {} while (0);

/**
 * The structure defines a socket entry connected with a dvb device,
 * both when registered by a systemcall to kernel module or by opening
 * a new special device that accesses to THIS via IOCTL calls.
 */
typedef struct nim_socket_entry_list {
    struct list_head nim_entry; // nim socket'e entry list
    nim_socket_entry_t *entry;  // nim socket infos
    // Only one between ifile and imodule
    struct file *ifile;         // [optional] file poiter to the opened special device, connected to nim socket
    struct module *imodule;     // [optional] calling kernel module conneted to nim socket
} nim_socket_entry_list_t;
#define NIM_ENTRY(entries) list_entry(entries, struct nim_socket_entry_list, nim_entry)

/**
 * Internal process status.
 */
typedef struct proc_module_internal_status {
    struct list_head vendor_nim_entries;        // vendor nim sockets list
    int vendor_nim_socket_entry_count;          // vendor nim sockets count

    struct list_head custom_nim_entries;        // custom nim sockets list
    int custom_nim_socket_entry_count;          // custom nim sockets count

    int useOriginal;                            // if 0 use patched nim_sockets proc content; not 0 use original proc content
    struct proc_dir_entry *current_nim_proc;    // current pointer to nim_sockets proc
    int owner_nim_proc;                         // if not 0 proc is created by THIS module. Otherwise the proc is vendor.
    struct semaphore *lockEntry;                // concurrent access control to internal state struct
    struct semaphore *lockRebuild;              // concurrent access control when rebuild proc content

    int debugLevel;                             // bitwise flag for debug verbose level

    int request_revalidate;                     // flag: not 0 request vendor nim socket revalidate

    void *proc_buffer_content;                  // the content of the proc
    ssize_t proc_buffer_size;                   // the size of the proc content

    ssize_t (*original_file_read) (struct file *ifile, char __user *buffer, size_t count, loff_t * offset); // Original callback for read proc file.
    read_proc_t *original_proc_read;            // original proc read callback if proxy_proc_ops is NULL. NULL otherwise.
    int (*original_file_open) (struct inode *node, struct file *ifile); // original proc open file (perform request for revalidate data)

    int skip_original_nim_proc;                 // Not 0 value for ignore not existing original proc (and then create it). 0 required existing original proc.
} proc_module_internal_status_t;

// Initializing default internal status
static proc_module_internal_status_t p_status = {
    .request_revalidate = 1,
    .vendor_nim_socket_entry_count = 0,
    .custom_nim_socket_entry_count = 0,
    .useOriginal = 0,
    .current_nim_proc = NULL,
    .original_file_read = NULL,
    .original_proc_read = NULL,
    .original_file_open = NULL,
    .lockEntry = NULL,
    .lockRebuild = NULL,
    .proc_buffer_content = NULL,
    .proc_buffer_size = 0,
    .skip_original_nim_proc = 1,
    .debugLevel = INFO | WARNING | ERROR | CRITICAL
};

static int readOldProcFile(struct file *ifile, char **output, ssize_t *size);
static int parseProcContent(char *procContent, ssize_t procContentLen);
static int addNimSocket(struct file *file, nim_socket_entry_t *socket);
static int removeNimSocket(struct file *file);
static nim_socket_entry_t *findNimSocketEntry(int socket_id);
static int revalidateProcData(struct file *ifile);

static long ioctl_proc_module(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param);
static ssize_t read_proc_module(char *page, char **start, off_t off, int count, int *eof, void *data);
static long ioctl_proc_module(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param);
static int open_proc_module(struct inode *inode, struct file *file);
static int close_proc_module(struct inode *inode, struct file *file);
static ssize_t read_patched_nim_sockets(struct file *ifile, char __user *buffer, size_t count, loff_t * offset);

static int proxy_original_proc_open(struct inode *node, struct file *ifile);


// IOCTL device file_operations
struct file_operations ioctl_proc_ops = {
	.unlocked_ioctl = ioctl_proc_module,
	.compat_ioctl = ioctl_proc_module,
	.open = open_proc_module,
	.release = close_proc_module
};

/**
 * Initialize the proc module:
 * 1. Allocate lock semaphore
 * 2. Search the original proc
 * 3. Replace original read with patch
 * @return 0 on success, -ENOMEM if no available memory, -EPERM if can't create fake proc, -EINVAL on error
 */
static __init int initialize_proc_module(void) {
    int check;
    struct file_operations *dummy_fop;
    struct proc_dir_entry *fake_entry, *fake_entry_parent, *item_entry;

    INIT_LIST_HEAD(&p_status.vendor_nim_entries);
    INIT_LIST_HEAD(&p_status.custom_nim_entries);

    setLevelLog(&p_status.debugLevel);

    p_status.lockEntry = kzalloc(sizeof(struct semaphore), GFP_KERNEL);
    if (p_status.lockEntry == NULL) {
        printLog(ERROR, "No available memory to allocate lock semaphore\n");
        check = -ENOMEM;
        goto out_init;
    }
    sema_init(p_status.lockEntry, 1);
    p_status.lockRebuild = kzalloc(sizeof(struct semaphore), GFP_KERNEL);
    if (p_status.lockRebuild == NULL) {
        printLog(ERROR, "No available memory to allocate lock semaphore\n");
        check = -ENOMEM;
        goto out_init_lock2;
    }
    sema_init(p_status.lockRebuild, 1);

    // Search original proc file
    printLog(FINE, "Searching default nim_sockets proc.\nCreate fake proc\n");
    fake_entry = create_proc_entry(NIM_SOCKET_PROC_FAKE, 0, NULL);
    if (fake_entry == NULL) {
        printLog(ERROR, "Error creating fake proc. Aborted\n");
        check = -EPERM;
        goto out_init_lock2;
    }
    fake_entry_parent = fake_entry->parent;
    printLog(FINE, "Searching nim into %s\n", fake_entry_parent->name);
    for (item_entry = fake_entry_parent->subdir; item_entry; item_entry = item_entry->next) {
        printLog(FINE, "Searching nim into %s\n", item_entry->name);
        if (strcmp(item_entry->name, NIM_SOCKET_PROC_NAME) == 0) {
            printLog(FINE, "read_proc is %s\n", (item_entry->read_proc == NULL? "NULL" : "NOT NULL"));
            if (item_entry->proc_fops != NULL) {
                printLog(FINE, "file_ops is NOT NULL\n");
                printLog(FINE, "read file ops is %s\n", item_entry->proc_fops->read != NULL ? "NOT NULL" : "NULL");
                printLog(FINE, "open file ops is %s\n", item_entry->proc_fops->open != NULL ? "NOT NULL" : "NULL");
                printLog(FINE, "release file ops is %s\n", item_entry->proc_fops->release != NULL ? "NOT NULL" : "NULL");
            }
            else
                printLog(FINE, "file_ops is NULL\n");

            if (item_entry->read_proc == NULL && (item_entry->proc_fops == NULL || item_entry->proc_fops->read == NULL)) {
                item_entry = NULL;
                printLog(ERROR, "No read method available for vendor nim_sockets\n");
            }

            break;
        }
    }
    p_status.owner_nim_proc = 0;
    if (item_entry == NULL && !p_status.skip_original_nim_proc) {
        printLog(CRITICAL, "Original nim_sockets not found. Aborted\n");
        check = -EINVAL;
    }
    else if (item_entry == NULL) {
        item_entry = create_proc_entry(NIM_SOCKET_PROC_NAME, S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH, fake_entry_parent);
        if (item_entry == NULL) {
            printLog(CRITICAL, "Error creating new nim_sockets proc. Aborted\n");
            check = -EINVAL;
        }
        else {
            check = 0;
            p_status.owner_nim_proc = 1;
        }
    }
    else {
        p_status.owner_nim_proc = 0;
        check = 0;
    }

    remove_proc_entry(fake_entry->name, fake_entry->parent);
    fake_entry = NULL;
    fake_entry_parent = NULL;
    if (check)
        goto out_init_err_create_proc;

    p_status.current_nim_proc = item_entry;

    check = register_chrdev(MAJOR_CHDEV_NUMBER, NIM_SOCKET_PROC_IOCTL, &ioctl_proc_ops);
    if (!check) {
        p_status.original_proc_read = p_status.current_nim_proc->read_proc;
        p_status.original_file_read = p_status.current_nim_proc->proc_fops->read;
        p_status.original_file_open = p_status.current_nim_proc->proc_fops->open;

        dummy_fop = (struct file_operations *) p_status.current_nim_proc->proc_fops;
        dummy_fop->read = read_patched_nim_sockets;
        dummy_fop->open = proxy_original_proc_open;

        printLog(INFO, "nim sockets proc installed.\n");
        check = 0;
        goto out_init;
    }
    else {
        printLog(ERROR, "Error registering nim_socket ioctl device. Exit code %d\n", check);
        goto out_init_err_create_proc;
    }

out_init_err_create_proc:
    if (p_status.owner_nim_proc && item_entry != NULL)
        remove_proc_entry(item_entry->name, item_entry->parent);
out_init_lock2:
    kfree(p_status.lockEntry);
out_init:
    item_entry = NULL;
    return check;
}

/*
 * Release proc modules. Delete all created proc and restore
 * original bun/nim_sockets.
 */
static __exit void release_proc_module(void) {
    struct list_head *pos, *tmp;
    nim_socket_entry_list_t *entry;
    struct file_operations *fops_tmp;

    fops_tmp = (struct file_operations*) p_status.current_nim_proc->proc_fops;
	//if (p_status.original_proc_read != NULL)
	//	p_status.current_nim_proc->read_proc = p_status.original_proc_read;
    fops_tmp->read = p_status.original_file_read;
    fops_tmp->open = p_status.original_file_open;

    if (p_status.owner_nim_proc) {
        remove_proc_entry(p_status.current_nim_proc->name, p_status.current_nim_proc->parent);
    }

    p_status.current_nim_proc = NULL;

    if (p_status.lockEntry != NULL) {
        kfree(p_status.lockEntry);
        p_status.lockEntry = NULL;
    }
    if (p_status.lockRebuild != NULL) {
        kfree(p_status.lockRebuild);
        p_status.lockRebuild = NULL;
    }

    list_for_each_safe(pos, tmp, &p_status.vendor_nim_entries) {
        entry = NIM_ENTRY(pos);
        if (entry->ifile != NULL) {
            kfree(entry->entry);
        }
        list_del(pos);
    }

    list_for_each_safe(pos, tmp, &p_status.custom_nim_entries) {
        entry = NIM_ENTRY(pos);
        if (entry->ifile != NULL) {
            kfree(entry->entry);
        }
        list_del(pos);
    }

    p_status.vendor_nim_socket_entry_count = 0;
    p_status.custom_nim_socket_entry_count = 0;

    unregister_chrdev(MAJOR_CHDEV_NUMBER, NIM_SOCKET_PROC_IOCTL);
}

/**
 * Callback method for read proc content. Append the custom proc content at the end of the original proc.
 * @param page Output buffer to user space
 * @param start Unused
 * @param off Offset to start read
 * @param count Nubmber of request bytes (maximum)
 * @param eof Callback for EOF flag [optional]
 * @param data NULL
 * @return The number of bytes readed, 0 if no bytes.
 */
static ssize_t read_proc_module(char *page, char **start, off_t off, int count, int *eof, void *data) {
    ssize_t res;

    printLog(FINE, "Read proc file by proc_read\n");
	if (p_status.request_revalidate) {
		res = -EINVAL;
		if (eof)
			*eof = 1;
		return res;
	}

    if (off + count > p_status.proc_buffer_size) {
        res = p_status.proc_buffer_size - off;
        if (eof)
            *eof = 1;
    }
    else {
        res = count;
        if (eof)
            *eof = 0;
    }

    if (res < 0)
        res = 0;
    memcpy(page, p_status.proc_buffer_content + off, res);

    return res;
}

/**
 * Perform an IOCTL command on device.
 * @param file The file
 * @param ioctl_num The command
 * @param ioctl_param The param
 * @return 0 on success, -EINVAL on error
 */
static long ioctl_proc_module(struct file *file, unsigned int ioctl_num, unsigned long ioctl_param) {
    nim_socket_entry_t socket;
    nim_socket_entry_t *socket_res;
    ssize_t bytes;
    long res;
    int dummy;

    printLog(FINE, "Request %iu IOCTL. Param = %lu\n", ioctl_num, ioctl_param);

    switch (ioctl_num) {
        case GET_NIM_SOCKETS_ENTRIES_COUNT: //_IOR('o', 1, int)
        {
            dummy = p_status.vendor_nim_socket_entry_count + p_status.custom_nim_socket_entry_count;
            bytes = copy_to_user((int *) ioctl_param, &dummy,
                    sizeof(int));
            res = -bytes;
        }
        break;
        case GET_NIM_SOCKET_ENTRY:          //_IOR('o', 2, nim_socket_entry_t)
        {
            if (copy_from_user(&socket, (void *) ioctl_param, sizeof(nim_socket_entry_t)) == 0) {
                socket_res = findNimSocketEntry(socket.socket_no);
                if (socket_res != NULL) {
                    bytes = copy_to_user((void *) ioctl_param, socket_res, sizeof(nim_socket_entry_t));
                    res = -bytes;
                }
                else {
                    printLog(ERROR, "Nim socket not found: %d\n", socket.socket_no);
                    res = -EINVAL;
                }
            }
            else
                res = -EINVAL;
        }
        break;
        case SET_NIM_SOCKET_ENTRY:          //_IOWR('o', 3, nim_socket_entry_t)
        {
            if (copy_from_user(&socket, (void *) ioctl_param, sizeof(nim_socket_entry_t)) == 0) {
                socket.verdor = 0;
                res = addNimSocket(file, &socket);
                if (!res) {
                    res = copy_to_user((void *) ioctl_param, &socket, sizeof(nim_socket_entry_t));
                }
            }
            else
                res = -EINVAL;
        }
        break;
        case DEL_NIM_SOCKET_ENTRY:          //_IO('o', 4)
        {
            res = removeNimSocket(file);
        }
        break;
        case RESTORE_ORIGINAL_NIM_SOCKETS:  //_IOW('o', 5, void)
        {
            p_status.useOriginal = 1;
            res = 0;
        }
        break;
        case RESTORE_CUSTOM_NIM_SOCKETS:    //_IOW('o', 6, void)
        {
            p_status.useOriginal = 0;
            res = 0;
        }
        break;
        default:
        {
            printLog(ERROR, "Unknow ioctl command: %d\n", ioctl_num);
            res = -EINVAL;
        }
        break;
    }

    return res;
}

/**
 * Open IOCTL device to create new socket entry
 * @param inode The inode
 * @param file The file
 * @return 0 on success
 */
static int open_proc_module(struct inode *inode, struct file *file) {
    file->private_data = NULL;
    return 0;
}

/**
 * Close the IOCTL device, destroing the socket entry.
 * @param inode The inode
 * @param file The file
 * @return 0 on success
 */
static int close_proc_module(struct inode *inode, struct file *file) {
    int res;
    if (file->private_data != NULL) {
        res = down_interruptible(p_status.lockEntry);
        if (!res) {
            res = removeNimSocket(file);
            up(p_status.lockEntry);
        }

        return res;
    }
    else
        return 0;
}

/**
 * Read the content of the original proc. Return it in the OUTPUT address.
 * @param output [required] The output of the buffer
 * @param size [required] The output size
 * @return -EINVAL on error -ENOMEM if not available memory
 */
static int readOldProcFile(struct file *ifile, char **output, ssize_t *size) {
    // Create variables
    char *buf;
    ssize_t bytes;
    ssize_t length;
    ssize_t lengthMax;
    char *buffer;
    mm_segment_t old_fs;
#ifdef NIM_SOCKETS_OLD_KERNEL
    char *dummy;
#endif

#define MAX_BUFFER_SIZE 512 * 10

    if (output == NULL)
        return -EINVAL;

    lengthMax = 256;
    buffer = kzalloc(lengthMax, GFP_KERNEL);
	if (buffer == NULL)
		return -ENOMEM;
    length = 0;

	if (p_status.original_proc_read == NULL) {
		printLog(WARNING, "No original proc read found\n");
		//return -EINVAL;
	}

	buf = kzalloc(MAX_BUFFER_SIZE, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	p_status.current_nim_proc->read_proc = p_status.original_proc_read;
    do {
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		printLog(FINE, "Read original nim_sockets from file_read\n");
		bytes = p_status.original_file_read(ifile, buf, (size_t) MAX_BUFFER_SIZE, &ifile->f_pos);
		printLog(FINE, "Read original nim_sockets from file_read: readed %d bytes\n", bytes);
		set_fs(old_fs);

        if (bytes <= 0)
            bytes = 0;

		if (bytes > 0) {
			if (length + bytes >= lengthMax) {
				lengthMax += 256;
#ifndef NIM_SOCKETS_OLD_KERNEL
				buffer = krealloc(buffer, lengthMax, GFP_KERNEL);
#else
				dummy = kzalloc(lengthMax, GFP_KERNEL);
				if (dummy == NULL) {
					kfree(buffer);
					return -ENOMEM;
				}
				memcpy(dummy, buffer, length + bytes);
				kfree(buffer);
				buffer = dummy;
#endif
				if (buffer == NULL)
					return -EINVAL;
			}

			memcpy(buffer + length, buf, bytes);
			length += bytes;
		}
    } while (bytes > 0);

	p_status.current_nim_proc->read_proc = read_proc_module;

	if (length == 0) {
        kfree(buffer);
        buffer = NULL;
    }

    kfree(buf);
	buf = NULL;

    *output = buffer;
    *size = length;

    printLog(FINE, "Vendor proc read successfully. Readed %d bytes\n", length);

    return 0;
}

/**
 * Parse the proc content, looking for vendor socket definitions.
 * @param procContent The original proc content
 * @param procContentLen The size of the proc content
 * @return 0 on success, -ENOMEM if not available memory, -EINVAL on error
 */
static int parseProcContent(char *procContent, ssize_t procContentLen) {
    int index;
    int indexMode;
    ssize_t tokenLen;
    int keyStart, keyEnd, valueStart, valueEnd;
    char dummy[256];
    nim_socket_entry_t *currentSocket;
    int tokenFound;

    if (procContent == NULL || procContentLen <= 0) {
        printLog(ERROR, "Vendor proc content invalid: pointer = %p, size = %d\n", procContent, procContentLen);
        return -EINVAL;
    }

    keyStart = valueStart = 0;
    keyEnd = valueStart = -1;
    tokenLen = 0;
    tokenFound = 0;
    currentSocket = NULL;

    for (index = 0; index < procContentLen; index++) {
        char c = procContent[index];
        switch (c) {
            case ' ':
            case '\t':
            {
                if (keyEnd < 0 && !tokenFound)
                    keyStart = index + 1;
                else if (!tokenFound)
                    valueStart = index + 1;
            }
            break;
            case ':':
            {
                keyEnd = index - 1;
                tokenFound = 0;
            }
            break;
            case '\n':
            case '\r':
            {
                tokenFound = 0;
                valueEnd = index - 1;

                if (keyEnd >= keyStart) {
                    memset(dummy, 0, sizeof(dummy));
                    tokenLen = keyEnd - keyStart + 1;

                    if (tokenLen < 0) {
                        printLog(ERROR, "Parsing error: keyStart = %d, keyEnd = %d\n", keyStart, keyEnd);
                        return -EINVAL;
                    }
                    else if (tokenLen < sizeof(dummy))
                        memcpy(dummy, procContent + keyStart, keyEnd - keyStart + 1);
                    else {
                        printLog(ERROR, "No available space in dummy space.\n");
                        return -EINVAL;
                    }
                    printLog(FINE, "Parsing token >%s<, value = ", dummy);

					if (valueStart < 0 || valueEnd < valueStart) {
						if (valueEnd > keyEnd)
							valueStart = keyEnd + 2;
					}

                    if (valueStart <= valueEnd && valueStart >= 0)
                        printLog(FINE, ">%.*s<\n", valueEnd - valueStart + 1, &procContent[valueStart]);
                    else
                        printLog(FINE, "(NULL)\n");
                    if (tokenLen > NIM_SOCKET_TOKEN_LEN && strncmp(NIM_SOCKET_TOKEN, dummy, NIM_SOCKET_TOKEN_LEN) == 0) {
                        if (currentSocket != NULL) {
                            printLog(FINE, "Parsering new vendor nim socket.\n");
                            if (addNimSocket(NULL, currentSocket))
                                return -EINVAL;
                        }
                        currentSocket = kmalloc(sizeof(nim_socket_entry_t), 0);
                        memset(dummy, 0, sizeof(dummy));
                        memcpy(dummy, procContent + keyStart + NIM_SOCKET_TOKEN_LEN, keyEnd - keyStart + 1  + NIM_SOCKET_TOKEN_LEN);
                        currentSocket->socket_no = simple_strtol(dummy, NULL, 10);
                        memset(currentSocket->dvb_type_str, 0, sizeof(currentSocket->dvb_type_str));
                        memset(currentSocket->name, 0, sizeof(currentSocket->name));
                        currentSocket->frontendIndex = -1;
                        currentSocket->has_outputs = -1;
                        currentSocket->i2cDevice = -1;
                        currentSocket->internally_connectable = -1;
                        currentSocket->verdor = 1;

                        for (indexMode = 0; indexMode < MAX_MODES_TYPE; indexMode++) {
                            memset(currentSocket->modes[indexMode], 0, sizeof(currentSocket->modes[indexMode]));
                        }
                    }
                    else if (tokenLen >= TYPE_TOKEN_LEN && strncmp(TYPE_TOKEN, dummy, TYPE_TOKEN_LEN) == 0) {
                        if (currentSocket != NULL && valueEnd > 0 && valueStart <= valueEnd && (valueEnd - valueStart + 1) < sizeof(currentSocket->dvb_type_str)) {
                            memcpy(currentSocket->dvb_type_str, procContent + valueStart, valueEnd - valueStart + 1);
                        }
                        else {
                            printLog(ERROR, "Found token %s, but not a nim_socket entry, or invalid value (start = %d, end = %d)\n", TYPE_TOKEN, valueStart, valueEnd);
                            return -EINVAL;
                        }
                    }
                    else if (tokenLen >= NAME_TOKEN_LEN && strncmp(NAME_TOKEN, dummy, NAME_TOKEN_LEN) == 0) {
                        if (currentSocket != NULL && valueEnd > 0 && valueStart <= valueEnd && (valueEnd - valueStart + 1) < sizeof(currentSocket->name)) {
                            memcpy(currentSocket->name, procContent + valueStart, valueEnd - valueStart + 1);
                        }
                        else {
                            printLog(ERROR, "Found token %s, but not a nim_socket entry, or invalid value (start = %d, end = %d)\n", NAME_TOKEN, valueStart, valueEnd);
                            return -EINVAL;
                        }
                    }
                    else if (tokenLen >= HAS_OUTPUTS_TOKEN_LEN && strncmp(HAS_OUTPUTS_TOKEN, dummy, HAS_OUTPUTS_TOKEN_LEN) == 0) {
                        if (currentSocket != NULL && valueEnd > 0 && valueStart <= valueEnd && (valueEnd - valueStart + 1) < sizeof(dummy)) {
                            memset(dummy, 0, sizeof(dummy));
                            memcpy(dummy, procContent + valueStart, valueEnd - valueStart + 1);
                            currentSocket->has_outputs = strncmp("yes", dummy, strlen(dummy)) == 0? 1 : 0;
                        }
                        else {
                            printLog(ERROR, "Found token %s, but not a nim_socket entry, or invalid value (start = %d, end = %d)\n", HAS_OUTPUTS_TOKEN, valueStart, valueEnd);
                            return -EINVAL;
                        }
                    }
                    else if (tokenLen >= FRONTEND_DEVICE_TOKEN_LEN && strncmp(FRONTEND_DEVICE_TOKEN, dummy, FRONTEND_DEVICE_TOKEN_LEN) == 0) {
                        if (currentSocket != NULL && valueEnd > 0 && valueStart <= valueEnd && (valueEnd - valueStart + 1) < sizeof(dummy)) {
                            memset(dummy, 0, sizeof(dummy));
                            memcpy(dummy, procContent + valueStart, valueEnd - valueStart + 1);
                            currentSocket->frontendIndex = simple_strtol(dummy, NULL, 10);
                        }
                        else {
                            printLog(ERROR, "Found token %s, but not a nim_socket entry, or invalid value (start = %d, end = %d)\n", FRONTEND_DEVICE_TOKEN, valueStart, valueEnd);
                            return -EINVAL;
                        }
                    }
                    else if (tokenLen >= I2C_DEVICE_TOKEN_LEN && strncmp(I2C_DEVICE_TOKEN, dummy, I2C_DEVICE_TOKEN_LEN) == 0) {
                        if (currentSocket != NULL && valueEnd > 0 && valueStart <= valueEnd && (valueEnd - valueStart + 1) < sizeof(dummy)) {
                            memset(dummy, 0, sizeof(dummy));
                            memcpy(dummy, procContent + valueStart, valueEnd - valueStart + 1);
                            currentSocket->i2cDevice = simple_strtol(dummy, NULL, 10);
                        }
                        else {
                            printLog(ERROR, "Found token %s, but not a nim_socket entry, or invalid value (start = %d, end = %d)\n", I2C_DEVICE_TOKEN, valueStart, valueEnd);
                            return -EINVAL;
                        }
                    }
                    else if (tokenLen >= INTERNALLY_CONNECTABLE_TOKEN_LEN && strncmp(INTERNALLY_CONNECTABLE_TOKEN, dummy, INTERNALLY_CONNECTABLE_TOKEN_LEN) == 0) {
                        if (currentSocket != NULL && valueEnd > 0 && valueStart <= valueEnd && (valueEnd - valueStart + 1) < sizeof(dummy)) {
                            memset(dummy, 0, sizeof(dummy));
                            memcpy(dummy, procContent + valueStart, valueEnd - valueStart + 1);
                            currentSocket->internally_connectable = simple_strtol(dummy, NULL, 10);
                        }
                        else {
                            printLog(ERROR, "Found token %s, but not a nim_socket entry, or invalid value (start = %d, end = %d)\n", INTERNALLY_CONNECTABLE_TOKEN, valueStart, valueEnd);
                            return -EINVAL;
                        }
                    }
                    else if (tokenLen >= MODE_TYPE_TOKEN_LEN && strncmp(MODE_TYPE_TOKEN, dummy, MODE_TYPE_TOKEN_LEN) == 0) {
						if (currentSocket != NULL && valueEnd > 0 && valueStart <= valueEnd && (valueEnd - valueStart + 1) < sizeof(dummy)) {
							indexMode = simple_strtol(dummy + MODE_TYPE_TOKEN_LEN, NULL, 10);

							memset(dummy, 0, sizeof(dummy));
							memcpy(dummy, procContent + valueStart, valueEnd - valueStart + 1);
							strcpy(currentSocket->modes[indexMode], dummy);
						}
						else {
							printLog(ERROR, "Found token %s, but not a nim_socket entry, or invalid value (start = %d, end = %d)\n", MODE_TYPE_TOKEN, valueStart, valueEnd);
							return -EINVAL;
						}
                    }
                    else if (tokenLen > 0) {
                        printLog(ERROR, "Found unknow token %s. Skipped.\n", dummy);
                    }
                }
                keyStart = keyEnd = valueStart = valueEnd = -1;
            }
            break;
            default:
            {
                tokenFound = 1;
                if (keyStart < 0)
                    keyStart = index;
            }
            break;
        }
    }

    if (currentSocket != NULL)
        return addNimSocket(NULL, currentSocket);
    else
        return 0;
}

/**
 * Add new nim sockets, according to vendor flag, into the nim list.
 * @param file [optional] The file for nim via IOCTL protocol.
 * @param socket The socket to add
 * @return 0 on success, -ENOMEM if not available memory, -EINVAL on error
 */
static int addNimSocket(struct file *file, nim_socket_entry_t *socket) {
    nim_socket_entry_t *tmp;
    nim_socket_entry_list_t *entry;
    int freeSocketNum;
    int freeFrontendNum;
    int found;
    struct list_head *nim_list;
    int *nim_list_count;
    int res;

    if (socket == NULL)
        return -EINVAL;
    else {
        if (file != NULL && file->private_data != NULL) {
            tmp = (nim_socket_entry_t *) file->private_data;
            socket->socket_no = tmp->socket_no;
            socket->frontendIndex = tmp->frontendIndex;
        }
        else if (file != NULL) {
            socket->socket_no = -1;
            socket->frontendIndex = -1;
        }

        freeSocketNum = 0;
        freeFrontendNum = 0;
        found = 0;

        if (socket->verdor) {
            printLog(FINE, "Adding vendor nim_socket\n");
            nim_list = &p_status.vendor_nim_entries;
            nim_list_count = &p_status.vendor_nim_socket_entry_count;
        }
        else {
            printLog(FINE, "Adding custom nim_socket\n");
            nim_list = &p_status.custom_nim_entries;
            nim_list_count = &p_status.custom_nim_socket_entry_count;
        }

        res = down_interruptible(p_status.lockEntry);
        if (res)
            return res;

        printLog(FINE, "Searching for existing socket from %d sockets\n", *nim_list_count);
        list_for_each_entry(entry, nim_list, nim_entry) {
            if (entry->entry->socket_no == socket->socket_no) {
                found = 1;
                printLog(FINE, "Searching for existing socket: found\n");
                break;
            }
            else {
                freeSocketNum++;
                if (entry->entry->frontendIndex + 1 > freeFrontendNum)
                    freeFrontendNum = entry->entry->frontendIndex + 1;
            }
        }
        if (!found) {
            printLog(FINE, "Searching for existing socket: not found\n");
            if (socket->socket_no < 0)
                socket->socket_no = freeSocketNum;
            if (socket->frontendIndex < 0)
                socket->frontendIndex = freeFrontendNum;

            entry = kzalloc(sizeof(nim_socket_entry_list_t), GFP_KERNEL);
            if (entry == NULL) {
                up(p_status.lockEntry);
                return -ENOMEM;
            }
            entry->entry = kzalloc(sizeof(nim_socket_entry_t), GFP_KERNEL);
            if (entry->entry == NULL) {
                kfree(entry);
                up(p_status.lockEntry);
                return -ENOMEM;
            }
            memcpy(entry->entry, socket, sizeof(nim_socket_entry_t));
            entry->ifile = file;

            (*nim_list_count)++;
            printLog(FINE, "Insert nim_socket into list\n");
            list_add_tail(&entry->nim_entry, nim_list);
            do_sleep;
        }
        up(p_status.lockEntry);

        if (file != NULL)
            file->private_data = entry->entry;

        return 0;
    }
}

/**
 * Remove a nim socket from its list (non vendor one).
 * @param file File opened for IOCTL protocol.
 * @return 0 on success, -EINVAL on error or if the entry was not found.
 */
static int removeNimSocket(struct file *file) {
    nim_socket_entry_t *tmp;
    nim_socket_entry_list_t *entry;
    nim_socket_entry_list_t *entryFix;
    struct list_head *pos;
    int found;
    struct list_head *nim_list;
    int *nim_list_count;
    int res;

    found = 0;
    if (file == NULL || file->private_data == NULL)
        return -EINVAL;
    else {
        tmp = (nim_socket_entry_t *) file->private_data;

        if (tmp->verdor) {
            nim_list = &p_status.vendor_nim_entries;
            nim_list_count = &p_status.vendor_nim_socket_entry_count;
        }
        else {
            nim_list = &p_status.custom_nim_entries;
            nim_list_count = &p_status.custom_nim_socket_entry_count;
        }

        res = down_interruptible(p_status.lockEntry);
        if (res)
            return res;

        list_for_each(pos, nim_list) {
            if (!found) {
                entry = NIM_ENTRY(pos);
                if (entry->entry->socket_no == tmp->socket_no)
                    found = 1;
            }
            else {
                entryFix = NIM_ENTRY(pos);
                entryFix->entry->socket_no--;
                entryFix->entry->frontendIndex--;
            }
        }

        if (!found)
            return -EINVAL;

        list_del(&entry->nim_entry);
        (*nim_list_count)--;
        up(p_status.lockEntry);

        file->private_data = NULL;
        kfree(entry->entry);
        entry->entry = NULL;
        kfree(entry);

        return 0;
    }
}

/**
 * Add new custom nim socket entry, requeste by an other kernel module via registerNimSocketForModule exported symbol.
 * @param module_entry Reference to socket entry owner module.
 * @param entry The socket entry to add
 * @return 0 on success, -ENOMEM if not available memory, -EPERM if the socket already exists, -EINVAL on error
 */
int registerNimSocketForModule(nim_socket_module_entry_t *module_entry, nim_socket_entry_t *entry) {
    nim_socket_entry_list_t *new_entry, *tmp_entry;
    int res;
    struct list_head *pos;

    if (module_entry == NULL || entry == NULL || module_entry->owner == NULL)
        res = -EINVAL;
    else if (module_entry->private != NULL)
        res = -EPERM;
    else if (!down_interruptible(p_status.lockEntry)) {
        new_entry = kzalloc(sizeof(nim_socket_entry_list_t), GFP_KERNEL);
        if (new_entry == NULL) {
            res = -ENOMEM;
            goto release_register;
        }
        entry->verdor = 0;
        new_entry->entry = entry;
        new_entry->ifile = NULL;
        new_entry->imodule = module_entry->owner;
        module_entry->private = new_entry;

        if (list_empty(&p_status.custom_nim_entries)) {
            entry->frontendIndex = 0;
            entry->socket_no = 0;
        }
        else {
            tmp_entry = NULL;
            list_for_each_prev(pos, &p_status.custom_nim_entries) {
                tmp_entry = NIM_ENTRY(pos);
                break;
            }
            if (tmp_entry != NULL) {
                entry->frontendIndex = tmp_entry->entry->frontendIndex + 1;
                entry->socket_no = tmp_entry->entry->socket_no + 1;
            }
            else {
                entry->frontendIndex = 0;
                entry->socket_no = 0;
            }
        }

        list_add_tail(&new_entry->nim_entry, &p_status.custom_nim_entries);
        p_status.custom_nim_socket_entry_count++;
        res = 0;
        goto release_register;
    }
    else
        res = -ERESTARTSYS;

out_register:
    return res;
release_register:
    up(p_status.lockEntry);
    goto out_register;
}
EXPORT_SYMBOL(registerNimSocketForModule);

/**
 * Remove the nim socket entry registered by an other kernel module.
 * @param module_entry The previous registered socket entry.
 * @return 0 on success, -EINVAL on error
 */
int unregisterNimSocketForModule(nim_socket_module_entry_t *module_entry) {
    nim_socket_entry_list_t *entry, *tmp_entry;
    struct list_head *pos, *tmp_pos;
    int found;

    if (module_entry == NULL || module_entry->owner == NULL || module_entry->private == NULL)
        return -EINVAL;

    entry = (nim_socket_entry_list_t *) module_entry->private;

    if (down_interruptible(p_status.lockEntry))
        return -ERESTARTSYS;

    found = 0;
    list_for_each_safe(pos, tmp_pos, &p_status.custom_nim_entries) {
        tmp_entry = NIM_ENTRY(pos);
        if (!found && tmp_entry == entry) {
            found = 1;
            module_entry->private = NULL;
            entry->imodule = NULL;
            entry->entry = NULL;
            list_del(&entry->nim_entry);
            kfree(entry);
            p_status.custom_nim_socket_entry_count--;
            entry = NULL;
        }
        else if (found) {
            tmp_entry->entry->socket_no--;
            tmp_entry->entry->frontendIndex--;
        }
    }
    up(p_status.lockEntry);
    return 0;
}
EXPORT_SYMBOL(unregisterNimSocketForModule);

/**
 * Search nim socket by id.
 * @param socket_id The socket id.
 * @return The socket found, NULL otherwise.
 */
static nim_socket_entry_t *findNimSocketEntry(int socket_id) {
    nim_socket_entry_list_t *entry;
    struct list_head *pos;
    int found;
    int last_socket_id;
    int res;

    res = down_interruptible(p_status.lockEntry);
    if (res)
        return NULL;
    found = 0;
    last_socket_id = -1;
    list_for_each(pos, &p_status.vendor_nim_entries) {
        entry = NIM_ENTRY(pos);
        last_socket_id = entry->entry->socket_no;
        if (entry->entry->socket_no == socket_id) {
            found = 1;
            break;
        }
    }

    if (!found) {
        list_for_each(pos, &p_status.custom_nim_entries) {
            entry = NIM_ENTRY(pos);
            if (entry->entry->socket_no + last_socket_id == socket_id) {
                found = 1;
                break;
            }
        }
    }
    up(p_status.lockEntry);
    if (found)
        return entry->entry;
    else
        return NULL;
}

/**
 * Proxy the read file of the vendor nim_sockets
 * @param ifile The proc file
 * @param buffer The output buffer
 * @param count The number of bytes to read
 * @param offset The offset
 * @return The number of bytes readed, negative value on error
 */
static ssize_t read_patched_nim_sockets(struct file *ifile, char __user *buffer, size_t count, loff_t * offset) {
    ssize_t res;
	ssize_t bytes_to_copy;
	int off;

    printLog(FINE, "Reading proc file by file_read\n");

    res = revalidateProcData(ifile);
    if (res)
        return res;

	if (p_status.original_proc_read != NULL) {
		printLog(FINE, "Dump proc content by vendor code\n");
		ifile->f_pos = 0;
		res = p_status.original_file_read(ifile, buffer, count, offset);
	}
	if (res == 0 && p_status.proc_buffer_size > 0) {
		printLog(FINE, "Dump proc content by manual dump\n");
		if (offset != NULL) {
			off = *offset;
			if (off)
				return 0;
		}

		bytes_to_copy = count;
		if (p_status.proc_buffer_size < bytes_to_copy)
			bytes_to_copy = p_status.proc_buffer_size;
		if (bytes_to_copy > 0) {
			memcpy(buffer, p_status.proc_buffer_content, bytes_to_copy);
			res = bytes_to_copy;
		}
		else
			res = 0;

		if (offset != NULL)
			*offset = 1;

		printLog(FINE, "Copied %d byte to user buffer", res);
	}

	return res;
}

/**
 * Revalidate the proc content (both vendor and custom sockets).
 * @return 0 on success, -EINVAL on error, -ENOMEM if not available memory
 */
static int revalidateProcData(struct file *ifile) {
    int indexMode;
    int modeFound;
    nim_socket_entry_t *nim_entry;
    nim_socket_entry_list_t *entry;
    nim_socket_entry_list_t *pos;
    int last_socket_no;
    int last_frontend_no;
    int res;

    char *buffer;
    ssize_t buffer_len;
    ssize_t totalBytes;

    if (!p_status.request_revalidate)
        return 0;


    res = down_interruptible(p_status.lockRebuild);
    if (res)
        return res;

    if (p_status.proc_buffer_content != NULL) {
        kfree(p_status.proc_buffer_content);
        p_status.proc_buffer_content = NULL;
    }
    p_status.proc_buffer_size = 0;

	buffer_len = 0;
	buffer = NULL;

	if (!p_status.owner_nim_proc) {
		buffer = NULL;
		buffer_len = 0;
		printLog(FINE, "Read original nim_sockets\n");
		res = readOldProcFile(ifile, &buffer, &buffer_len);
		if (res)
			goto out_rebuild;
		if (p_status.useOriginal) {
			p_status.proc_buffer_size = buffer_len;
			p_status.proc_buffer_content = kzalloc(buffer_len, GFP_KERNEL);
			memcpy(p_status.proc_buffer_content, buffer, buffer_len);
			p_status.request_revalidate = 0;
			res = 0;
			kfree(buffer);
			goto out_rebuild;
		}
	}

    res = down_interruptible(p_status.lockEntry);
    if (res)
        goto out_rebuild;

	if (!p_status.owner_nim_proc) {
		printLog(FINE, "Rebuild original nim_sockets entries\n");
		list_for_each_entry_safe(entry, pos, &p_status.vendor_nim_entries, nim_entry) {
			list_del(&entry->nim_entry);
			kfree(entry->entry);
			entry->imodule = NULL;
			entry->ifile = NULL;
			kfree(entry);
		}
		p_status.vendor_nim_socket_entry_count = 0;
		up(p_status.lockEntry);

		printLog(FINE, "Parsing original nim_sockets\n");
		res = parseProcContent(buffer, buffer_len);
		if (res)
			goto out_rebuild;

		do_sleep;

		kfree(buffer);
	}
	else
		p_status.vendor_nim_socket_entry_count = 0;

    buffer = kzalloc(sizeof(nim_socket_entry_t) * (p_status.vendor_nim_socket_entry_count + p_status.custom_nim_socket_entry_count), GFP_KERNEL);
    if (buffer == NULL) {
        res = -ENOMEM;
        goto out_rebuild;
    }

    printLog(FINE, "Building proc content buffer\n");

    last_socket_no = -1;
    last_frontend_no = -1;
    totalBytes = 0;
    do_sleep;
    printLog(FINE, "Building vendor sockets\n");
    list_for_each_entry(entry, &p_status.vendor_nim_entries, nim_entry) {
        nim_entry = entry->entry;
        if (last_frontend_no < nim_entry->frontendIndex)
            last_frontend_no = nim_entry->frontendIndex;
        if (last_socket_no < nim_entry->socket_no)
            last_socket_no = nim_entry->socket_no;

        totalBytes += sprintf((char *) buffer + totalBytes, "%s%d:\n", NIM_SOCKET_TOKEN, nim_entry->socket_no);
        totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %s\n", TYPE_TOKEN, nim_entry->dvb_type_str);
        totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %s\n", NAME_TOKEN, nim_entry->name);
        if (nim_entry->has_outputs >= 0)
            totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %s\n", HAS_OUTPUTS_TOKEN, nim_entry->has_outputs? "yes" : "no");
        if (nim_entry->frontendIndex >= 0)
            totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %d\n", FRONTEND_DEVICE_TOKEN, nim_entry->frontendIndex);
        if (nim_entry->i2cDevice > 0)
            totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %d\n", I2C_DEVICE_TOKEN, nim_entry->i2cDevice);
        if (nim_entry->internally_connectable > 0)
            totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %d\n", INTERNALLY_CONNECTABLE_TOKEN, nim_entry->internally_connectable);
        modeFound = 0;
        for (indexMode = 0; indexMode < MAX_MODES_TYPE; indexMode++) {
            if (nim_entry->modes[indexMode][MAX_MODE_NAME] == 0 && strlen(nim_entry->modes[indexMode]) > 0) {
                totalBytes += sprintf((char *) buffer + totalBytes, "\tMode %d: %s\n", modeFound, nim_entry->modes[indexMode]);
                modeFound++;
            }
        }
    }

    last_socket_no++;
    last_frontend_no++;
    printLog(FINE, "Building custom sockets\n");
    do_sleep;
    list_for_each_entry(entry, &p_status.custom_nim_entries, nim_entry) {
        nim_entry = entry->entry;
        totalBytes += sprintf((char *) buffer + totalBytes, "%s%d:\n", NIM_SOCKET_TOKEN, nim_entry->socket_no + last_socket_no);
        totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %s\n", TYPE_TOKEN, nim_entry->dvb_type_str);
        totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %s\n", NAME_TOKEN, nim_entry->name);
        if (nim_entry->has_outputs >= 0)
            totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %s\n", HAS_OUTPUTS_TOKEN, nim_entry->has_outputs? "yes" : "no");
        if (nim_entry->frontendIndex >= 0)
            totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %d\n", FRONTEND_DEVICE_TOKEN, nim_entry->frontendIndex + last_frontend_no);
        if (nim_entry->i2cDevice > 0)
            totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %d\n", I2C_DEVICE_TOKEN, nim_entry->i2cDevice);
        if (nim_entry->internally_connectable > 0)
            totalBytes += sprintf((char *) buffer + totalBytes, "\t%s: %d\n", INTERNALLY_CONNECTABLE_TOKEN, nim_entry->internally_connectable);
        modeFound = 0;
        for (indexMode = 0; indexMode < MAX_MODES_TYPE; indexMode++) {
            if (nim_entry->modes[indexMode][MAX_MODE_NAME] == 0 && strlen(nim_entry->modes[indexMode]) > 0) {
                totalBytes += sprintf((char *) buffer + totalBytes, "\tMode %d: %s\n", modeFound, nim_entry->modes[indexMode]);
                modeFound++;
            }
        }
    }

    printLog(FINE, "Proc content ready: %d bytes to read\n", totalBytes);
    do_sleep;

    p_status.proc_buffer_size = totalBytes;
    p_status.proc_buffer_content = kzalloc(totalBytes, GFP_KERNEL);
    if (p_status.proc_buffer_content == NULL) {
        p_status.proc_buffer_size = 0;
        p_status.request_revalidate = 1;
        res = -ENOMEM;
        goto out_rebuild;
    }
    memcpy(p_status.proc_buffer_content, buffer, totalBytes);
    p_status.request_revalidate = 0;
    res = 0;
    kfree(buffer);

out_rebuild:
    up(p_status.lockRebuild);
    return res;
}

/**
 * Proxy callback open of original nim_sockets proc
 * @param node opened inode
 * @param ifile opened file
 * @return 0 on success, negative value on error
 */
static int proxy_original_proc_open(struct inode *node, struct file *ifile) {
    int res;

    printLog(FINE, "Open proxy proc file\n");

    p_status.request_revalidate = 1;
    if (p_status.original_file_open != NULL) {
        res = p_status.original_file_open(node, ifile);
		if (p_status.original_proc_read == NULL && p_status.current_nim_proc->read_proc != NULL) {
			p_status.original_proc_read = p_status.current_nim_proc->read_proc;
			p_status.current_nim_proc->read_proc = read_proc_module;
		}
	}
    else
        res = 0;

    printLog(FINE, "Opened\n");

    return res;
}

module_init(initialize_proc_module);
module_exit(release_proc_module);

MODULE_AUTHOR("Discovery & Prz Italy");
MODULE_DESCRIPTION("Custom nim_sockets manager");
MODULE_LICENSE("GPL");
MODULE_VERSION("3.0");

module_param_named(debugLevel, p_status.debugLevel, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(debugLevel, "Debug level (default 11 = INFO | WARNING | ERROR)");

module_param_named(skipOriginalNim, p_status.skip_original_nim_proc, int, S_IRUSR | S_IRGRP);
MODULE_PARM_DESC(skipOriginalNim, "When not 0 a new nim_socket proc will be created if no one");

module_param_named(useOriginalNim, p_status.useOriginal, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(useOriginalNim, "When not 0 only vendor nim is enabled");