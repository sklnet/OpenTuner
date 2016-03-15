/*
 * File:   logs.h
 * Author: discovery
 *
 * Created on 28 gennaio 2012, 10.51
 */

#ifndef LOGS_H
#define	LOGS_H

/**
 * Level log filter.
 */
typedef enum ELogLevel {
	INFO = 1,
	WARNING = 2,
	FINE = 4,
	ERROR = 8,
	CRITICAL = 16,
	STREAM = 32,

	ALL = INFO | WARNING | FINE | ERROR | CRITICAL | STREAM,
	DEFAULT = INFO | ERROR | CRITICAL
} ELogLevel_t;

/**
 * Print a log entry, if LEVEL log is enabled. Log entry consists of a formatted text according FORMAT string and VARARGS parameters.
 * @param level The level log. If level is enabled, a new log entry will create. The level log name is prefixed before log entry.
 * @param format The format like printf, etc.
 * @param ... Parameters
 */
void printLog(ELogLevel_t level, const char *format, ...) __attribute__ ((__format__(printf, 2, 3)));

/**
 * Bitmask of enabled log levels (ELogLevel values).
 * @return The enabled log levels.
 */
int getLevelLog(void);

/**
 * Set the enabled log levels accordind the parameter bitmask (ELogLevel values).
 * @param levelLog The new log levels bitmask.
 */
void setLevelLog(int *levelLog);

/**
 * Print "printable" BUFFER_LEN bytes of BUFFER in a grid and same one in hex format.
 * @param buffer The buffer to print.
 * @param buffer_len The number of bytes to print.
 */
void printLogBuffer(void *buffer, int buffer_len);

#endif	/* LOGS_H */

