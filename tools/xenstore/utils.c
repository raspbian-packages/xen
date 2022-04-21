#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include "utils.h"

static void default_xprintf(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fflush(stderr);
}

void (*xprintf)(const char *fmt, ...) = default_xprintf;

void barf(const char *fmt, ...)
{
	char *str;
	int bytes;
	va_list arglist;

	xprintf("FATAL: ");

	va_start(arglist, fmt);
	bytes = vasprintf(&str, fmt, arglist);
	va_end(arglist);

 	if (bytes >= 0) {
		syslog(LOG_CRIT, "%s\n", str);
		xprintf("%s\n", str);
		free(str);
	}
	exit(1);
}

void barf_perror(const char *fmt, ...)
{
	char *str;
	int bytes, err = errno;
	va_list arglist;

	xprintf("FATAL: ");

	va_start(arglist, fmt);
	bytes = vasprintf(&str, fmt, arglist);
	va_end(arglist);

 	if (bytes >= 0) {
		syslog(LOG_CRIT, "%s: %s\n", str, strerror(err));
		xprintf("%s: %s\n", str, strerror(err));
		free(str);
	}
	exit(1);
}

const char *dump_state_align(FILE *fp)
{
	long len;
	static char nul[8] = {};

	len = ftell(fp);
	if (len < 0)
		return "Dump state align error";
	len &= 7;
	if (!len)
		return NULL;

	if (fwrite(nul, 8 - len, 1, fp) != 1)
		return "Dump state align error";
	return NULL;
}
