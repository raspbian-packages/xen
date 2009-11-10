/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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

#include <string.h>
#include "libxl.h"
#include "libxl_internal.h"
#include <sys/time.h> /* for struct timeval */

char *string_of_kinds[] = {
    [DEVICE_VIF] = "vif",
    [DEVICE_VBD] = "vbd",
    [DEVICE_TAP] = "tap",
    [DEVICE_PCI] = "pci",
    [DEVICE_VFB] = "vfb",
    [DEVICE_VKBD] = "vkbd",
};

int libxl_device_generic_add(struct libxl_ctx *ctx, libxl_device *device,
                             char **bents, char **fents)
{
    char *dom_path_backend, *dom_path, *frontend_path, *backend_path, *hotplug_path;
    xs_transaction_t t;
    struct xs_permissions frontend_perms[2];
    struct xs_permissions backend_perms[2];
    struct xs_permissions hotplug_perms[1];

    dom_path_backend = xs_get_domain_path(ctx->xsh, device->backend_domid);
    dom_path = xs_get_domain_path(ctx->xsh, device->domid);

    frontend_path = libxl_sprintf(ctx, "%s/device/%s/%d",
                                  dom_path, string_of_kinds[device->kind], device->devid);
    backend_path = libxl_sprintf(ctx, "%s/backend/%s/%u/%d",
                                 dom_path_backend, string_of_kinds[device->backend_kind], device->domid, device->devid);
    hotplug_path = libxl_sprintf(ctx, "/xapi/%d/hotplug/%s/%d",
                                  device->domid, string_of_kinds[device->kind], device->devid);

    frontend_perms[0].id = device->domid;
    frontend_perms[0].perms = XS_PERM_NONE;
    frontend_perms[1].id = device->backend_domid;
    frontend_perms[1].perms = XS_PERM_READ;

    backend_perms[0].id = device->backend_domid;
    backend_perms[0].perms = XS_PERM_NONE;
    backend_perms[1].id = device->domid;
    backend_perms[1].perms = XS_PERM_READ;

    hotplug_perms[0].id = device->backend_domid;
    hotplug_perms[0].perms = XS_PERM_NONE;

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    /* FIXME: read frontend_path and check state before removing stuff */

    xs_rm(ctx->xsh, t, frontend_path);
    xs_rm(ctx->xsh, t, backend_path);

    xs_mkdir(ctx->xsh, t, frontend_path);
    xs_set_permissions(ctx->xsh, t, frontend_path, frontend_perms, ARRAY_SIZE(frontend_perms));

    xs_mkdir(ctx->xsh, t, backend_path);
    xs_set_permissions(ctx->xsh, t, backend_path, backend_perms, ARRAY_SIZE(backend_perms));

    xs_mkdir(ctx->xsh, t, hotplug_path);
    xs_set_permissions(ctx->xsh, t, hotplug_path, hotplug_perms, ARRAY_SIZE(hotplug_perms));

    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/backend", frontend_path), backend_path, strlen(backend_path));
    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/frontend", backend_path), frontend_path, strlen(frontend_path));

    /* and write frontend kvs and backend kvs */
    libxl_xs_writev(ctx, t, backend_path, bents);
    libxl_xs_writev(ctx, t, frontend_path, fents);

    if (!xs_transaction_end(ctx->xsh, t, 0))
        if (errno == EAGAIN)
            goto retry_transaction;
    return 0;
}

char *device_disk_string_of_phystype(libxl_disk_phystype phystype)
{
    switch (phystype) {
        case PHYSTYPE_QCOW: return "qcow";
        case PHYSTYPE_QCOW2: return "qcow2";
        case PHYSTYPE_VHD: return "vhd";
        case PHYSTYPE_AIO: return "aio";
        case PHYSTYPE_FILE: return "file";
        case PHYSTYPE_PHY: return "phy";
        default: return NULL;
    }
}

char *device_disk_backend_type_of_phystype(libxl_disk_phystype phystype)
{
    switch (phystype) {
        case PHYSTYPE_QCOW: return "tap";
        case PHYSTYPE_VHD: return "tap";
        case PHYSTYPE_AIO: return "tap";
        case PHYSTYPE_FILE: return "file";
        case PHYSTYPE_PHY: return "phy";
        default: return NULL;
    }
}

int device_disk_major_minor(char *virtpath, int *major, int *minor)
{
    if (strstr(virtpath, "sd") == virtpath) {
        return -1;
    } else if (strstr(virtpath, "xvd") == virtpath) {
        return -1;
    } else if (strstr(virtpath, "hd") == virtpath) {
        char letter, letter2;

        *major = 0; *minor = 0;
        letter = virtpath[2];
        if (letter < 'a' || letter > 't')
            return -1;
        letter2 = virtpath[3];

        *major = letter - 'a';
        *minor = atoi(virtpath + 3);
        return 0;
    } else {
        return -1;
    }
}

int device_disk_dev_number(char *virtpath)
{
    int majors_table[] = { 3, 22, 33, 34, 56, 57, 88, 89, 90, 91 };
    int major, minor;

    if (device_disk_major_minor(virtpath, &major, &minor))
        return -1;
    return majors_table[major / 2] * 256 + (64 * (major % 2)) + minor;
}

int libxl_device_destroy(struct libxl_ctx *ctx, char *be_path, int force)
{
    xs_transaction_t t;
    char *state_path = libxl_sprintf(ctx, "%s/state", be_path);
    char *state = libxl_xs_read(ctx, XBT_NULL, state_path);
    if (!state)
        return 0;
    if (atoi(state) <= 3) {
        xs_rm(ctx->xsh, XBT_NULL, be_path);
        return 0;
    }

retry_transaction:
    t = xs_transaction_start(ctx->xsh);
    xs_write(ctx->xsh, t, libxl_sprintf(ctx, "%s/online", be_path), "0", strlen("0"));
    xs_write(ctx->xsh, t, state_path, "5", strlen("5"));
    if (!xs_transaction_end(ctx->xsh, t, 0)) {
        if (errno == EAGAIN)
            goto retry_transaction;
        else
            return -1;
    }
    if (!force) {
        xs_watch(ctx->xsh, state_path, be_path);
        return 1;
    } else
        return 0;
}

int libxl_devices_destroy(struct libxl_ctx *ctx, uint32_t domid, int force)
{
    char *path, *be_path, *fe_path;
    unsigned int num1, num2;
    char **l1 = NULL, **l2 = NULL;
    int i, j, nfds, n = 0, n_watches = 0;
    fd_set rfds;
    struct timeval tv;
    flexarray_t *toremove;

    toremove = flexarray_make(16, 1);
    path = libxl_sprintf(ctx, "/local/domain/%d/device", domid);
    l1 = libxl_xs_directory(ctx, XBT_NULL, path, &num1);
    if (!l1) {
        XL_LOG(ctx, XL_LOG_ERROR, "%s is empty\n", path);
        return -1;
    }
    for (i = 0; i < num1; i++) {
        path = libxl_sprintf(ctx, "/local/domain/%d/device/%s", domid, l1[i]);
        l2 = libxl_xs_directory(ctx, XBT_NULL, path, &num2);
        if (!l2)
            continue;
        for (j = 0; j < num2; j++) {
            fe_path = libxl_sprintf(ctx, "/local/domain/%d/device/%s/%s", domid, l1[i], l2[j]);
            be_path = libxl_xs_read(ctx, XBT_NULL, libxl_sprintf(ctx, "%s/backend", fe_path));
            if (be_path != NULL) {
                if (libxl_device_destroy(ctx, be_path, force) > 0)
                    n_watches++;
                flexarray_set(toremove, n++, libxl_dirname(ctx, be_path));
            } else {
                xs_rm(ctx->xsh, XBT_NULL, path);
            }
        }
    }
    if (!force) {
        nfds = xs_fileno(ctx->xsh) + 1;
        /* Linux-ism */
        tv.tv_sec = LIBXL_DESTROY_TIMEOUT;
        tv.tv_usec = 0;
        while (n_watches > 0 && tv.tv_sec > 0) {
            FD_ZERO(&rfds);
            FD_SET(xs_fileno(ctx->xsh), &rfds);
            if (select(nfds, &rfds, NULL, NULL, &tv) > 0) {
                l1 = xs_read_watch(ctx->xsh, &num1);
                if (l1 != NULL) {
                    char *state = libxl_xs_read(ctx, XBT_NULL, l1[0]);
                    if (!state || atoi(state) == 6) {
                        xs_unwatch(ctx->xsh, l1[0], l1[1]);
                        xs_rm(ctx->xsh, XBT_NULL, l1[1]);
                        XL_LOG(ctx, XL_LOG_DEBUG, "Destroyed device backend at %s\n", l1[1]);
                        n_watches--;
                    }
                }
            } else
                break;
        }
    }
    for (i = 0; i < n; i++) {
        flexarray_get(toremove, i, (void**) &path);
        xs_rm(ctx->xsh, XBT_NULL, path);
    }
    flexarray_free(toremove);
    return 0;
}
