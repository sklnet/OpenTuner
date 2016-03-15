#include "logs.h"
#include <stdarg.h>
#include <linux/types.h>
#ifdef INSIDE_USER_SPACE
#include <stddef.h>
#endif

#define GET_BYTE_FROM_BUFFER(buffer, row, col, col_size, size) (row * col_size + col < size ? (*(buffer + row * col_size + col)) : ' ')
#define LOG_PREFIX "OTuner Driver: "

static int *log_level = NULL;
static const int default_log_level = INFO | WARNING | ERROR | CRITICAL;

// If INSIDE_KERNEL_SPACE macro exists vprintk is used to print log entries.
#ifdef INSIDE_KERNEL_SPACE
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>

static void vprintklog(ELogLevel_t level, const char *format, va_list va) {
    char *newFmt;
    char *prefix;
    int gap;

    switch(level) {
    case INFO:
    {
        prefix = KERN_INFO;
    }
    break;
    case WARNING:
    {
        prefix = KERN_ALERT;
    }
    break;
    case FINE:
    case STREAM:
    {
        prefix = KERN_NOTICE;
    }
    break;
    case ERROR:
    {
        prefix = KERN_ERR;
    }
    break;
    case CRITICAL:
    {
        prefix = KERN_CRIT;
    }
    break;
    default:
    {
        prefix = KERN_INFO;
    }
    break;
    }
    gap = 0;
    newFmt = kmalloc(strlen(prefix) + strlen(LOG_PREFIX) + strlen(format) + 1, 0);
    memcpy(newFmt + gap, prefix, strlen(prefix));
    gap += strlen(prefix);
    memcpy(newFmt + gap, LOG_PREFIX, strlen(LOG_PREFIX));
    gap += strlen(LOG_PREFIX);
    memcpy(newFmt + gap, format, strlen(format));
    gap += strlen(format);
    newFmt[gap] = 0;
    vprintk(newFmt, va);
    kfree(newFmt);
}
#endif

// If INSIDE_USER_SPACE macro exists then printf is used to print log entries.
#ifdef INSIDE_USER_SPACE
#include <stdio.h>
static void vprintflog(ELogLevel_t level, const char *format, va_list va) {
    switch(level) {
    case INFO:
    {
        printf("[INFO] " LOG_PREFIX);
    }
    break;
    case WARNING:
    {
        printf("[WARNING] " LOG_PREFIX);
    }
    break;
    case FINE:
    {
        printf("[FINE] " LOG_PREFIX);
    }
    break;
    case STREAM:
    {
        printf("[STREAM] " LOG_PREFIX);
    }
    break;
    case ERROR:
    {
        printf("[ERROR] " LOG_PREFIX);
    }
    break;
    case CRITICAL:
    {
        printf("[CRITICAL] " LOG_PREFIX);
    }
    break;
    default:
    {
        printf("[INFO] " LOG_PREFIX);
    }
    break;
    }
    vprintf(format, va);
}
#endif

#if !defined(INSIDE_KERNEL_SPACE) && !defined(INSIDE_USER_SPACE)
// If no macro defined, no logs
static void noprintlog(const char *format, va_list va) {

}
#endif

/**
 * Call log method implementation.
 * @param level Filter log level
 * @param format Format string
 * @param ... Parameters
 */
void printLog(ELogLevel_t level, const char *format, ...) {
    va_list argp;
    if ((level & getLevelLog()) == level) {
#ifdef INSIDE_KERNEL_SPACE
        va_start(argp, format);
        vprintklog(level, format, argp);
        va_end(argp);
#elif defined INSIDE_USER_SPACE
        va_start(argp, format);
        vprintflog(level, format, argp);
        va_end(argp);
#else
        //va_start(argp, fmt);
        noprintlog(format, argp);
        //va_end(argp);
#endif
    }
}

/**
 * Extract from BUFFER the printable byte (char) to print at row ROW, column COL, in a grid with COL_SIZE
 * maminum columns. If the byte position is greater then BUFFER_LEN, a blank char (' ') is returned. If the
 * extracted byte is not a printable character, then a '?' char is returned.
 * @param buffer The source buffer.
 * @param row The row in the grid.
 * @param col The col in the grid
 * @param col_size The maximun column of the grid.
 * @param buffer_len The buffer's length.
 * @return The printable character of the buffer.
 */
static char getPrintableCharAt(void *buffer, int row, int col, int col_size, int buffer_len) {
    char res;
    if (row * col_size + col < buffer_len) {
        res = *(((char *)buffer) + (row * col_size + col));
        if ((res < 32 || res > 126) && res != '\n' && res != '\r' && res != '\t')
            res = '?';
    }
    else
        res = ' ';
    return res;
}

/**
 * Extract from BUFFER the casting of the byte into char to print at row ROW, column COL, in a grid with COL_SIZE
 * maminum columns. If the byte position is greater then BUFFER_LEN, a ZERO char (0) is returned. The byte to
 * extract is bitwised with 0xFF.
 * @param buffer The source buffer.
 * @param row The row in the grid.
 * @param col The col in the grid
 * @param col_size The maximun column of the grid.
 * @param buffer_len The buffer's length.
 * @return The character of the buffer.
 */
static char getCharAt(void *buffer, int row, int col, int col_size, int buffer_len) {
    char res;
    if (row * col_size + col < buffer_len) {
        res = *(((char *)buffer) + (row * col_size + col));
    }
    else
        res = 0;
    return (char) (res & 0xFF);
}

/**
 * Print "printable" BUFFER_LEN bytes of BUFFER in a grid and same one in hex format.
 * @param buffer The buffer to print.
 * @param buffer_len The number of bytes to print.
 */
void printLogBuffer(void *buffer, int buffer_len) {
    int rows;
    int row;

    if ((STREAM & getLevelLog()) == STREAM) {
        rows = buffer_len / 16;
        if (rows * 16 < buffer_len)
            rows++;

        for (row = 0; row < rows; row++) {
            printLog(STREAM, "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
                     getPrintableCharAt(buffer, row,  0, 16, buffer_len),
                     getPrintableCharAt(buffer, row,  1, 16, buffer_len),
                     getPrintableCharAt(buffer, row,  2, 16, buffer_len),
                     getPrintableCharAt(buffer, row,  3, 16, buffer_len),
                     getPrintableCharAt(buffer, row,  4, 16, buffer_len),
                     getPrintableCharAt(buffer, row,  5, 16, buffer_len),
                     getPrintableCharAt(buffer, row,  6, 16, buffer_len),
                     getPrintableCharAt(buffer, row,  7, 16, buffer_len),
                     getPrintableCharAt(buffer, row,  8, 16, buffer_len),
                     getPrintableCharAt(buffer, row,  9, 16, buffer_len),
                     getPrintableCharAt(buffer, row, 10, 16, buffer_len),
                     getPrintableCharAt(buffer, row, 11, 16, buffer_len),
                     getPrintableCharAt(buffer, row, 12, 16, buffer_len),
                     getPrintableCharAt(buffer, row, 13, 16, buffer_len),
                     getPrintableCharAt(buffer, row, 14, 16, buffer_len),
                     getPrintableCharAt(buffer, row, 15, 16, buffer_len)
                    );
        }
        for (row = 0; row < rows; row++) {
            printLog(STREAM, "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                     getCharAt(buffer, row,  0, 16, buffer_len),
                     getCharAt(buffer, row,  1, 16, buffer_len),
                     getCharAt(buffer, row,  2, 16, buffer_len),
                     getCharAt(buffer, row,  3, 16, buffer_len),
                     getCharAt(buffer, row,  4, 16, buffer_len),
                     getCharAt(buffer, row,  5, 16, buffer_len),
                     getCharAt(buffer, row,  6, 16, buffer_len),
                     getCharAt(buffer, row,  7, 16, buffer_len),
                     getCharAt(buffer, row,  8, 16, buffer_len),
                     getCharAt(buffer, row,  9, 16, buffer_len),
                     getCharAt(buffer, row, 10, 16, buffer_len),
                     getCharAt(buffer, row, 11, 16, buffer_len),
                     getCharAt(buffer, row, 12, 16, buffer_len),
                     getCharAt(buffer, row, 13, 16, buffer_len),
                     getCharAt(buffer, row, 14, 16, buffer_len),
                     getCharAt(buffer, row, 15, 16, buffer_len)
                    );
        }
    }
}

/**
 * Bitmask of enabled log levels (ELogLevel values).
 * @return The enabled log levels.
 */
int getLevelLog(void) {
    if (log_level == NULL)
        return default_log_level;
    else
        return *log_level;
}

/**
 * Set the enabled log levels accordind the parameter bitmask (ELogLevel values).
 * @param levelLog The new log levels bitmask.
 */
void setLevelLog(int *levelLog) {
    log_level = levelLog;
}