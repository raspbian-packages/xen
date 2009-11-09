/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Stefano Stabellini <stefano.stabellini@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_utils.h"
#include "libxl_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <xs.h>
#include <xenctrl.h>
#include <ctype.h>
#include <errno.h>



unsigned long libxl_get_required_shadow_memory(unsigned long maxmem_kb, unsigned int smp_cpus)
{
    /* 256 pages (1MB) per vcpu,
       plus 1 page per MiB of RAM for the P2M map,
       plus 1 page per MiB of RAM to shadow the resident processes.
       This is higher than the minimum that Xen would allocate if no value
       were given (but the Xen minimum is for safety, not performance).
     */
    return 4 * (256 * smp_cpus + 2 * (maxmem_kb / 1024));
}

char *libxl_domid_to_name(struct libxl_ctx *ctx, uint32_t domid)
{
    unsigned int len;
    char path[strlen("/local/domain") + 12];
    char *s;

    snprintf(path, sizeof(path), "/local/domain/%d/name", domid);
    s = xs_read(ctx->xsh, XBT_NULL, path, &len);
    libxl_ptr_add(ctx, s);
    return s;
}

int libxl_name_to_domid(struct libxl_ctx *ctx, char *name, uint32_t *domid)
{
    unsigned int num, len;
    char path[strlen("/local/domain") + 12];
    int i;
    char *domname, **l;

    l = xs_directory(ctx->xsh, XBT_NULL, "/local/domain", &num);
    for (i = 0; i < num; i++) {
        snprintf(path, sizeof(path), "/local/domain/%s/name", l[i]);
        domname = xs_read(ctx->xsh, XBT_NULL, path, &len);
        if (domname != NULL && !strncmp(domname, name, len)) {
            *domid = atoi(l[i]);
            free(l);
            free(domname);
            return 0;
        }
        free(domname);
    }
    free(l);
    return -1;
}

int libxl_uuid_to_domid(struct libxl_ctx *ctx, uint8_t *uuid, uint32_t *domid)
{
    int nb_domain, i;
    struct libxl_dominfo *info = libxl_domain_list(ctx, &nb_domain);
    for (i = 0; i < nb_domain; i++) {
        if (!memcmp(info[i].uuid, uuid, 16)) {
            *domid = info[i].domid;
            return 0;
        }
    }
    return -1;
}

int libxl_domid_to_uuid(struct libxl_ctx *ctx, uint8_t **uuid, uint32_t domid)
{
    int nb_domain, i;
    struct libxl_dominfo *info = libxl_domain_list(ctx, &nb_domain);
    for (i = 0; i < nb_domain; i++) {
        if (domid == info[i].domid) {
            *uuid = libxl_zalloc(ctx, 16);
            memcpy(*uuid, info[i].uuid, 16);
            return 0;
        }
    }
    return -1;
}

int libxl_is_uuid(char *s)
{
    int i;
    if (!s || strlen(s) != 36)
        return 0;
    for (i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-')
                return 0;
        } else {
            if (!isxdigit(s[i]))
                return 0;
        }
    }
    return 1;
}

uint8_t *string_to_uuid(struct libxl_ctx *ctx, char *s)
{
    uint8_t *buf;
    if (!s || !ctx)
        return NULL;

    buf = libxl_zalloc(ctx, 16);
    sscanf(s, UUID_FMT, &buf[0], &buf[1], &buf[2], &buf[3], &buf[4], &buf[5],
           &buf[6], &buf[7], &buf[8], &buf[9], &buf[10], &buf[11], &buf[12],
           &buf[13], &buf[14], &buf[15]);
    return buf;
}

char *uuid_to_string(struct libxl_ctx *ctx, uint8_t *uuid)
{
    if (!uuid)
        return NULL;
    return libxl_sprintf(ctx, UUID_FMT,
                         uuid[0], uuid[1], uuid[2], uuid[3],
                         uuid[4], uuid[5], uuid[6], uuid[7],
                         uuid[8], uuid[9], uuid[10], uuid[11],
                         uuid[12], uuid[13], uuid[14], uuid[15]);
}

int libxl_param_to_domid(struct libxl_ctx *ctx, char *p, uint32_t *domid)
{
    uint8_t *uuid;
    uint32_t d;

    if (libxl_is_uuid(p)) {
        uuid = string_to_uuid(ctx, p);
        return libxl_uuid_to_domid(ctx, uuid, domid);
    }
    errno = 0;
    d = strtol(p, (char **) NULL, 10);
    if (!errno && d != 0 && d != LONG_MAX && d != LONG_MIN) {
        *domid = d;
        return 0;
    }
    return libxl_name_to_domid(ctx, p, domid);
}
