/*
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FSIMAGE_H
#define	_FSIMAGE_H

#ifdef __cplusplus
extern C {
#endif

#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>

typedef struct fsi fsi_t;
typedef struct fsi_file fsi_file_t;

/*
 * Optional initialization function. If invoked it loads the associated
 * dynamic libraries for the backends ahead of time. This is required if
 * the library is to run as part of a highly deprivileged executable, as
 * the libraries may not be reachable after depriv.
 */
int fsi_init(void);

fsi_t *fsi_open_fsimage(const char *, uint64_t, const char *);
void fsi_close_fsimage(fsi_t *);

int fsi_file_exists(fsi_t *, const char *);
fsi_file_t *fsi_open_file(fsi_t *, const char *);
int fsi_close_file(fsi_file_t *);

ssize_t fsi_read_file(fsi_file_t *, void *, size_t);
ssize_t fsi_pread_file(fsi_file_t *, void *, size_t, uint64_t);

char *fsi_bootstring_alloc(fsi_t *, size_t);
void fsi_bootstring_free(fsi_t *);
char *fsi_fs_bootstring(fsi_t *);

#ifdef __cplusplus
};
#endif

#endif /* _FSIMAGE_H */
