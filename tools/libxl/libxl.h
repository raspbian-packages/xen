/*
 * Copyright (C) 2009      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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
#ifndef LIBXL_H
#define LIBXL_H

#include <stdint.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <xenctrl.h>
#include <xs.h>

#include "xen_uuid.h"

#define XL_LOGGING_ENABLED

typedef void (*libxl_log_callback)(void *userdata, int loglevel, const char *file,
                                   int line, const char *func, char *s);
struct libxl_dominfo {
    xen_uuid_t uuid[16];
    uint32_t domid;
};

struct libxl_ctx {
    int xch;
    struct xs_handle *xsh;
    /* errors/debug buf */
    void *log_userdata;
    libxl_log_callback log_callback;

    /* mini-GC */
    int alloc_maxsize;
    void **alloc_ptrs;

    /* for callers who reap children willy-nilly; caller must only
     * set this after libxl_init and before any other call - or
     * may leave them untouched */
    int (*waitpid_instead)(pid_t pid, int *status, int flags);
};

typedef struct {
    bool hvm;
    bool hap;
    int ssidref;
    char *name;
    xen_uuid_t *uuid;
    char **xsdata;
    char **platformdata;
} libxl_domain_create_info;

typedef struct {
    int timer_mode;
    int hpet;
    int vpt_align;
    int max_vcpus;
    uint32_t max_memkb;
    uint32_t video_memkb;
    uint32_t shadow_memkb;
    const char *kernel;
    int hvm;
    union {
        struct {
            bool pae;
            bool apic;
            bool acpi;
            bool nx;
            bool viridian;
            char *timeoffset;
        } hvm;
        struct {
            const char *cmdline;
            const char *ramdisk;
            const char *features;
        } pv;
    } u;
} libxl_domain_build_info;

typedef struct {
    uint32_t store_port;
    unsigned long store_mfn;
    uint32_t console_port;
    unsigned long console_mfn;
} libxl_domain_build_state;

typedef struct {
    int flags;
    int (*suspend_callback)(void *, int);
} libxl_domain_suspend_info;

typedef enum {
    XENFV,
    XENPV,
} libxl_qemu_machine_type;

typedef struct {
    int domid;
    char *dom_name;
    char *device_model;
    libxl_qemu_machine_type type;
    int videoram; /* size of the videoram in MB */
    bool stdvga; /* stdvga enabled or disabled */
    bool vnc; /* vnc enabled or disabled */
    char *vnclisten; /* address:port that should be listened on for the VNC server if vnc is set */
    int vncdisplay; /* set VNC display number */
    bool vncunused; /* try to find an unused port for the VNC server */
    char *keymap; /* set keyboard layout, default is en-us keyboard */
    bool sdl; /* sdl enabled or disabled */
    bool opengl; /* opengl enabled or disabled (if enabled requires sdl enabled) */
    bool nographic; /* no graphics, use serial port */
    char *serial; /* serial port re-direct to pty deivce */
    char *boot; /* boot order, for example dca */
    bool usb; /* usb support enabled or disabled */
    char *usbdevice; /* enable usb mouse: tablet for absolute mouse, mouse for PS/2 protocol relative mouse */
    bool apic; /* apic enabled or disabled */
    char **extra; /* extra parameters pass directly to qemu, NULL terminated */
    /* Network is missing */
} libxl_device_model_info;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
    bool vnc; /* vnc enabled or disabled */
    char *vnclisten; /* address:port that should be listened on for the VNC server if vnc is set */
    int vncdisplay; /* set VNC display number */
    bool vncunused; /* try to find an unused port for the VNC server */
    char *keymap; /* set keyboard layout, default is en-us keyboard */
    bool sdl; /* sdl enabled or disabled */
    bool opengl; /* opengl enabled or disabled (if enabled requires sdl enabled) */
    char *display;
    char *xauthority;
} libxl_device_vfb;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
} libxl_device_vkb;

typedef enum {
    CONSTYPE_XENCONSOLED,
    CONSTYPE_IOEMU,
} libxl_console_constype;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
    libxl_console_constype constype;
    libxl_domain_build_state *build_state;
} libxl_device_console;

typedef enum {
    PHYSTYPE_QCOW,
    PHYSTYPE_QCOW2,
    PHYSTYPE_VHD,
    PHYSTYPE_AIO,
    PHYSTYPE_FILE,
    PHYSTYPE_PHY,
} libxl_disk_phystype;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    char *physpath;
    libxl_disk_phystype phystype;
    char *virtpath;
    int unpluggable;
    int readwrite;
    int is_cdrom;
} libxl_device_disk;

typedef enum {
    NICTYPE_IOEMU,
    NICTYPE_VIF,
} libxl_nic_type;

typedef struct {
    uint32_t backend_domid;
    uint32_t domid;
    int devid;
    int mtu;
    char *model;
    uint8_t mac[6];
    char *smac;
    struct in_addr ip;
    char *bridge;
    char *ifname;
    char *script;
    libxl_nic_type nictype;
} libxl_device_nic;

typedef struct  {
    union {
        unsigned int value;
        struct {
            unsigned int reserved1:2;
            unsigned int reg:6;
            unsigned int func:3;
            unsigned int dev:5;
            unsigned int bus:8;
            unsigned int reserved2:7;
            unsigned int enable:1;
        };
    };
    unsigned int domain;
    unsigned int vdevfn;
    bool msitranslate;
    bool power_mgmt;
} libxl_device_pci;

#define ERROR_FAIL (-2)
#define ERROR_NI (-101)
#define ERROR_NOMEM (-1032)
#define ERROR_INVAL (-1245)

/* logging */
void xl_logv(struct libxl_ctx *ctx, int errnoval, int loglevel, const char *file, int line, const char *func, char *fmt, va_list al);
void xl_log(struct libxl_ctx *ctx, int errnoval, int loglevel, const char *file, int line, const char *func, char *fmt, ...);

#ifdef XL_LOGGING_ENABLED
#define XL_LOG(ctx, loglevel, _f, _a...)   xl_log(ctx, loglevel, -1, __FILE__, __LINE__, __func__, _f, ##_a)
#define XL_LOG_ERRNO(ctx, loglevel, _f, _a...)   xl_log(ctx, loglevel, errno, __FILE__, __LINE__, __func__, _f, ##_a)
#define XL_LOG_ERRNOVAL(ctx, errnoval, loglevel, _f, _a...)   xl_log(ctx, loglevel, errnoval, __FILE__, __LINE__, __func__, _f, ##_a)
#else
#define XL_LOG(ctx, loglevel, _f, _a...)
#define XL_LOG_ERRNO(ctx, loglevel, _f, _a...)
#define XL_LOG_ERRNOVAL(ctx, loglevel, errnoval, _f, _a...)
#endif

#define XL_LOG_DEBUG 3
#define XL_LOG_INFO 2
#define XL_LOG_WARNING 1
#define XL_LOG_ERROR 0

/* context functions */
int libxl_ctx_init(struct libxl_ctx *ctx);
int libxl_ctx_free(struct libxl_ctx *ctx);
int libxl_ctx_close(struct libxl_ctx *ctx);
int libxl_ctx_set_log(struct libxl_ctx *ctx, libxl_log_callback log_callback, void *log_data);

/* domain related functions */
int libxl_domain_make(struct libxl_ctx *ctx, libxl_domain_create_info *info, uint32_t *domid);
int libxl_domain_build(struct libxl_ctx *ctx, libxl_domain_build_info *info, uint32_t domid, /* out */ libxl_domain_build_state *state);
int libxl_domain_restore(struct libxl_ctx *ctx, libxl_domain_build_info *info,
                          uint32_t domid, int fd);
int libxl_domain_suspend(struct libxl_ctx *ctx, libxl_domain_suspend_info *info,
                          uint32_t domid, int fd);
int libxl_domain_shutdown(struct libxl_ctx *ctx, uint32_t domid, int req);
int libxl_domain_destroy(struct libxl_ctx *ctx, uint32_t domid, int force);

int libxl_wait_for_domain_death(struct libxl_ctx *ctx, uint32_t domid, int *fd);
int libxl_is_domain_dead(struct libxl_ctx *ctx, uint32_t domid, xc_dominfo_t *info);

int libxl_domain_pause(struct libxl_ctx *ctx, uint32_t domid);
int libxl_domain_unpause(struct libxl_ctx *ctx, uint32_t domid);

int libxl_console_attach(struct libxl_ctx *ctx, uint32_t domid, int cons_num);

struct libxl_dominfo * libxl_domain_list(struct libxl_ctx *ctx, int *nb_domain);
xc_dominfo_t * libxl_domain_infolist(struct libxl_ctx *ctx, int *nb_domain);

typedef struct libxl_device_model_starting libxl_device_model_starting;
int libxl_create_device_model(struct libxl_ctx *ctx,
                              libxl_device_model_info *info,
                              libxl_device_disk *disk, int num_disks,
                              libxl_device_nic *vifs, int num_vifs,
                              libxl_device_model_starting **starting_r);
int libxl_create_xenpv_qemu(struct libxl_ctx *ctx, libxl_device_vfb *vfb,
                            int num_console, libxl_device_console *console,
                            libxl_device_model_starting **starting_r);
  /* Caller must either: pass starting_r==0, or on successful
   * return pass *starting_r (which will be non-0) to
   * libxl_confirm_device_model or libxl_detach_device_model. */
int libxl_confirm_device_model_startup(struct libxl_ctx *ctx,
                              libxl_device_model_starting *starting);
int libxl_detach_device_model(struct libxl_ctx *ctx,
                              libxl_device_model_starting *starting);
  /* DM is detached even if error is returned */

int libxl_device_disk_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk);
int libxl_device_disk_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid);
int libxl_device_disk_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid);

int libxl_device_nic_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_nic *nic);
int libxl_device_nic_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid);
int libxl_device_nic_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid);

int libxl_device_console_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_console *console);

int libxl_device_vkb_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb);
int libxl_device_vkb_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid);
int libxl_device_vkb_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid);

int libxl_device_vfb_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_vfb *vfb);
int libxl_device_vfb_clean_shutdown(struct libxl_ctx *ctx, uint32_t domid);
int libxl_device_vfb_hard_shutdown(struct libxl_ctx *ctx, uint32_t domid);

#define PCI_BDF                "%04x:%02x:%02x.%01x"
#define PCI_BDF_VDEVFN         "%04x:%02x:%02x.%01x@%02x"
int libxl_device_pci_add(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev);
int libxl_device_pci_remove(struct libxl_ctx *ctx, uint32_t domid, libxl_device_pci *pcidev);
int libxl_device_pci_shutdown(struct libxl_ctx *ctx, uint32_t domid);
libxl_device_pci *libxl_device_pci_list(struct libxl_ctx *ctx, uint32_t domid, int *num);
int libxl_device_pci_init(libxl_device_pci *pcidev, unsigned int domain,
                          unsigned int bus, unsigned int dev,
                          unsigned int func, unsigned int vdevfn);

void nic_info_domid_fixup(libxl_device_nic *nic_info, int domid);
void disk_info_domid_fixup(libxl_device_disk *disk_info, int domid);
void vfb_info_domid_fixup(libxl_device_vfb *vfb, int domid);
void vkb_info_domid_fixup(libxl_device_vkb *vkb, int domid);
void console_info_domid_fixup(libxl_device_console *console, int domid);
void device_model_info_domid_fixup(libxl_device_model_info *dm_info, int domid);

void init_create_info(libxl_domain_create_info *c_info);
void init_build_info(libxl_domain_build_info *b_info, libxl_domain_create_info *c_info);
void init_dm_info(libxl_device_model_info *dm_info,
        libxl_domain_create_info *c_info, libxl_domain_build_info *b_info);
void init_nic_info(libxl_device_nic *nic_info, int devnum);
void init_vfb_info(libxl_device_vfb *vfb, int dev_num);
void init_vkb_info(libxl_device_vkb *vkb, int dev_num);
void init_console_info(libxl_device_console *console, int dev_num, libxl_domain_build_state *state);

#endif
