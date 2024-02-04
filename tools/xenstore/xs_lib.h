/*
    Common routines between Xen store user library and daemon.
    Copyright (C) 2005 Rusty Russell IBM Corporation

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef XS_LIB_H
#define XS_LIB_H

#include "xenstore_lib.h"

const char *xs_daemon_rootdir(void);
const char *xs_domain_dev(void);
const char *xs_daemon_tdb(void);

/* Convert permissions to a string (up to len MAX_STRLEN(unsigned int)+1). */
bool xs_perm_to_string(const struct xs_permissions *perm,
		       char *buffer, size_t buf_len);

/* Given a string and a length, count how many strings (nul terms). */
unsigned int xs_count_strings(const char *strings, unsigned int len);

/* Sanitising (quoting) possibly-binary strings. */
struct expanding_buffer {
	char *buf;
	int avail;
};

/* Ensure that given expanding buffer has at least min_avail characters. */
char *expanding_buffer_ensure(struct expanding_buffer *, int min_avail);

/* sanitise_value() may return NULL if malloc fails. */
char *sanitise_value(struct expanding_buffer *, const char *val, unsigned len);

/* *out_len_r on entry is ignored; out must be at least strlen(in)+1 bytes. */
void unsanitise_value(char *out, unsigned *out_len_r, const char *in);

#endif /* XS_LIB_H */
