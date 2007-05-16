/*
 * QEMU USB OHCI Emulation
 * Copyright (c) 2004 Gianni Tedesco
 * Copyright (c) 2006 CodeSourcery
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * TODO:
 *  o Isochronous transfers
 *  o Allocate bandwidth in frames properly
 *  o Disable timers when nothing needs to be done, or remove timer usage
 *    all together.
 *  o Handle unrecoverable errors properly
 *  o BIOS work to boot from USB storage
*/

#include "vl.h"

//#define DEBUG_OHCI
/* Dump packet contents.  */
//#define DEBUG_PACKET
/* This causes frames to occur 1000x slower */
//#define OHCI_TIME_WARP 1

#ifdef DEBUG_OHCI
#define dprintf printf
#else
#define dprintf(...)
#endif

/* Number of Downstream Ports on the root hub.  */

#define OHCI_MAX_PORTS 15

static int64_t usb_frame_time;
static int64_t usb_bit_time;

typedef struct OHCIPort {
    USBPort port;
    uint32_t ctrl;
} OHCIPort;

typedef struct {
    struct PCIDevice pci_dev;
    target_phys_addr_t mem_base;
    int mem;
    int num_ports;

    QEMUTimer *eof_timer;
    int64_t sof_time;

    /* OHCI state */
    /* Control partition */
    uint32_t ctl, status;
    uint32_t intr_status;
    uint32_t intr;

    /* memory pointer partition */
    uint32_t hcca;
    uint32_t ctrl_head, ctrl_cur;
    uint32_t bulk_head, bulk_cur;
    uint32_t per_cur;
    uint32_t done;
    int done_count;

    /* Frame counter partition */
    uint32_t fsmps:15;
    uint32_t fit:1;
    uint32_t fi:14;
    uint32_t frt:1;
    uint16_t frame_number;
    uint16_t padding;
    uint32_t pstart;
    uint32_t lst;

    /* Root Hub partition */
    uint32_t rhdesc_a, rhdesc_b;
    uint32_t rhstatus;
    OHCIPort rhport[OHCI_MAX_PORTS];

    /* Active packets.  */
    uint32_t old_ctl;
    USBPacket usb_packet;
    uint8_t usb_buf[8192];
    uint32_t async_td;
    int async_complete;

} OHCIState;

/* Host Controller Communications Area */
struct ohci_hcca {
    uint32_t intr[32];
    uint16_t frame, pad;
    uint32_t done;
};

/* Bitfields for the first word of an Endpoint Desciptor.  */
#define OHCI_ED_FA_SHIFT  0
#define OHCI_ED_FA_MASK   (0x7f<<OHCI_ED_FA_SHIFT)
#define OHCI_ED_EN_SHIFT  7
#define OHCI_ED_EN_MASK   (0xf<<OHCI_ED_EN_SHIFT)
#define OHCI_ED_D_SHIFT   11
#define OHCI_ED_D_MASK    (3<<OHCI_ED_D_SHIFT)
#define OHCI_ED_S         (1<<13)
#define OHCI_ED_K         (1<<14)
#define OHCI_ED_F         (1<<15)
#define OHCI_ED_MPS_SHIFT 7
#define OHCI_ED_MPS_MASK  (0xf<<OHCI_ED_FA_SHIFT)

/* Flags in the head field of an Endpoint Desciptor.  */
#define OHCI_ED_H         1
#define OHCI_ED_C         2

/* Bitfields for the first word of a Transfer Desciptor.  */
#define OHCI_TD_R         (1<<18)
#define OHCI_TD_DP_SHIFT  19
#define OHCI_TD_DP_MASK   (3<<OHCI_TD_DP_SHIFT)
#define OHCI_TD_DI_SHIFT  21
#define OHCI_TD_DI_MASK   (7<<OHCI_TD_DI_SHIFT)
#define OHCI_TD_T0        (1<<24)
#define OHCI_TD_T1        (1<<24)
#define OHCI_TD_EC_SHIFT  26
#define OHCI_TD_EC_MASK   (3<<OHCI_TD_EC_SHIFT)
#define OHCI_TD_CC_SHIFT  28
#define OHCI_TD_CC_MASK   (0xf<<OHCI_TD_CC_SHIFT)

#define OHCI_DPTR_MASK    0xfffffff0

#define OHCI_BM(val, field) \
  (((val) & OHCI_##field##_MASK) >> OHCI_##field##_SHIFT)

#define OHCI_SET_BM(val, field, newval) do { \
    val &= ~OHCI_##field##_MASK; \
    val |= ((newval) << OHCI_##field##_SHIFT) & OHCI_##field##_MASK; \
    } while(0)

/* endpoint descriptor */
struct ohci_ed {
    uint32_t flags;
    uint32_t tail;
    uint32_t head;
    uint32_t next;
};

/* General transfer descriptor */
struct ohci_td {
    uint32_t flags;
    uint32_t cbp;
    uint32_t next;
    uint32_t be;
};

#define USB_HZ                      12000000

/* OHCI Local stuff */
#define OHCI_CTL_CBSR         ((1<<0)|(1<<1))
#define OHCI_CTL_PLE          (1<<2)
#define OHCI_CTL_IE           (1<<3)
#define OHCI_CTL_CLE          (1<<4)
#define OHCI_CTL_BLE          (1<<5)
#define OHCI_CTL_HCFS         ((1<<6)|(1<<7))
#define  OHCI_USB_RESET       0x00
#define  OHCI_USB_RESUME      0x40
#define  OHCI_USB_OPERATIONAL 0x80
#define  OHCI_USB_SUSPEND     0xc0
#define OHCI_CTL_IR           (1<<8)
#define OHCI_CTL_RWC          (1<<9)
#define OHCI_CTL_RWE          (1<<10)

#define OHCI_STATUS_HCR       (1<<0)
#define OHCI_STATUS_CLF       (1<<1)
#define OHCI_STATUS_BLF       (1<<2)
#define OHCI_STATUS_OCR       (1<<3)
#define OHCI_STATUS_SOC       ((1<<6)|(1<<7))

#define OHCI_INTR_SO          (1<<0) /* Scheduling overrun */
#define OHCI_INTR_WD          (1<<1) /* HcDoneHead writeback */
#define OHCI_INTR_SF          (1<<2) /* Start of frame */
#define OHCI_INTR_RD          (1<<3) /* Resume detect */
#define OHCI_INTR_UE          (1<<4) /* Unrecoverable error */
#define OHCI_INTR_FNO         (1<<5) /* Frame number overflow */
#define OHCI_INTR_RHSC        (1<<6) /* Root hub status change */
#define OHCI_INTR_OC          (1<<30) /* Ownership change */
#define OHCI_INTR_MIE         (1<<31) /* Master Interrupt Enable */

#define OHCI_HCCA_SIZE        0x100
#define OHCI_HCCA_MASK        0xffffff00

#define OHCI_EDPTR_MASK       0xfffffff0

#define OHCI_FMI_FI           0x00003fff
#define OHCI_FMI_FSMPS        0xffff0000
#define OHCI_FMI_FIT          0x80000000

#define OHCI_FR_RT            (1<<31)

#define OHCI_LS_THRESH        0x628

#define OHCI_RHA_RW_MASK      0x00000000 /* Mask of supported features.  */
#define OHCI_RHA_PSM          (1<<8)
#define OHCI_RHA_NPS          (1<<9)
#define OHCI_RHA_DT           (1<<10)
#define OHCI_RHA_OCPM         (1<<11)
#define OHCI_RHA_NOCP         (1<<12)
#define OHCI_RHA_POTPGT_MASK  0xff000000

#define OHCI_RHS_LPS          (1<<0)
#define OHCI_RHS_OCI          (1<<1)
#define OHCI_RHS_DRWE         (1<<15)
#define OHCI_RHS_LPSC         (1<<16)
#define OHCI_RHS_OCIC         (1<<17)
#define OHCI_RHS_CRWE         (1<<31)

#define OHCI_PORT_CCS         (1<<0)
#define OHCI_PORT_PES         (1<<1)
#define OHCI_PORT_PSS         (1<<2)
#define OHCI_PORT_POCI        (1<<3)
#define OHCI_PORT_PRS         (1<<4)
#define OHCI_PORT_PPS         (1<<8)
#define OHCI_PORT_LSDA        (1<<9)
#define OHCI_PORT_CSC         (1<<16)
#define OHCI_PORT_PESC        (1<<17)
#define OHCI_PORT_PSSC        (1<<18)
#define OHCI_PORT_OCIC        (1<<19)
#define OHCI_PORT_PRSC        (1<<20)
#define OHCI_PORT_WTC         (OHCI_PORT_CSC|OHCI_PORT_PESC|OHCI_PORT_PSSC \
                               |OHCI_PORT_OCIC|OHCI_PORT_PRSC)

#define OHCI_TD_DIR_SETUP     0x0
#define OHCI_TD_DIR_OUT       0x1
#define OHCI_TD_DIR_IN        0x2
#define OHCI_TD_DIR_RESERVED  0x3

#define OHCI_CC_NOERROR             0x0
#define OHCI_CC_CRC                 0x1
#define OHCI_CC_BITSTUFFING         0x2
#define OHCI_CC_DATATOGGLEMISMATCH  0x3
#define OHCI_CC_STALL               0x4
#define OHCI_CC_DEVICENOTRESPONDING 0x5
#define OHCI_CC_PIDCHECKFAILURE     0x6
#define OHCI_CC_UNDEXPETEDPID       0x7
#define OHCI_CC_DATAOVERRUN         0x8
#define OHCI_CC_DATAUNDERRUN        0x9
#define OHCI_CC_BUFFEROVERRUN       0xc
#define OHCI_CC_BUFFERUNDERRUN      0xd

/* Update IRQ levels */
static inline void ohci_intr_update(OHCIState *ohci)
{
    int level = 0;

    if ((ohci->intr & OHCI_INTR_MIE) &&
        (ohci->intr_status & ohci->intr))
        level = 1;

    pci_set_irq(&ohci->pci_dev, 0, level);
}

/* Set an interrupt */
static inline void ohci_set_interrupt(OHCIState *ohci, uint32_t intr)
{
    ohci->intr_status |= intr;
    ohci_intr_update(ohci);
}

/* Attach or detach a device on a root hub port.  */
static void ohci_attach(USBPort *port1, USBDevice *dev)
{
    OHCIState *s = port1->opaque;
    OHCIPort *port = &s->rhport[port1->index];
    uint32_t old_state = port->ctrl;

    if (dev) {
        if (port->port.dev) {
            usb_attach(port1, NULL);
        }
        /* set connect status */
        port->ctrl |= OHCI_PORT_CCS | OHCI_PORT_CSC;

        /* update speed */
        if (dev->speed == USB_SPEED_LOW)
            port->ctrl |= OHCI_PORT_LSDA;
        else
            port->ctrl &= ~OHCI_PORT_LSDA;
        port->port.dev = dev;
        /* send the attach message */
        usb_send_msg(dev, USB_MSG_ATTACH);
        dprintf("usb-ohci: Attached port %d\n", port1->index);
    } else {
        /* set connect status */
        if (port->ctrl & OHCI_PORT_CCS) {
            port->ctrl &= ~OHCI_PORT_CCS;
            port->ctrl |= OHCI_PORT_CSC;
        }
        /* disable port */
        if (port->ctrl & OHCI_PORT_PES) {
            port->ctrl &= ~OHCI_PORT_PES;
            port->ctrl |= OHCI_PORT_PESC;
        }
        dev = port->port.dev;
        if (dev) {
            /* send the detach message */
            usb_send_msg(dev, USB_MSG_DETACH);
        }
        port->port.dev = NULL;
        dprintf("usb-ohci: Detached port %d\n", port1->index);
    }

    if (old_state != port->ctrl)
        ohci_set_interrupt(s, OHCI_INTR_RHSC);
}

/* Reset the controller */
static void ohci_reset(OHCIState *ohci)
{
    OHCIPort *port;
    int i;

    ohci->ctl = 0;
    ohci->old_ctl = 0;
    ohci->status = 0;
    ohci->intr_status = 0;
    ohci->intr = OHCI_INTR_MIE;

    ohci->hcca = 0;
    ohci->ctrl_head = ohci->ctrl_cur = 0;
    ohci->bulk_head = ohci->bulk_cur = 0;
    ohci->per_cur = 0;
    ohci->done = 0;
    ohci->done_count = 7;

    /* FSMPS is marked TBD in OCHI 1.0, what gives ffs?
     * I took the value linux sets ...
     */
    ohci->fsmps = 0x2778;
    ohci->fi = 0x2edf;
    ohci->fit = 0;
    ohci->frt = 0;
    ohci->frame_number = 0;
    ohci->pstart = 0;
    ohci->lst = OHCI_LS_THRESH;

    ohci->rhdesc_a = OHCI_RHA_NPS | ohci->num_ports;
    ohci->rhdesc_b = 0x0; /* Impl. specific */
    ohci->rhstatus = 0;

    for (i = 0; i < ohci->num_ports; i++)
      {
        port = &ohci->rhport[i];
        port->ctrl = 0;
        if (port->port.dev)
            ohci_attach(&port->port, port->port.dev);
      }
    if (ohci->async_td) {
        usb_cancel_packet(&ohci->usb_packet);
        ohci->async_td = 0;
    }
    dprintf("usb-ohci: Reset %s\n", ohci->pci_dev.name);
}

/* Get an array of dwords from main memory */
static inline int get_dwords(uint32_t addr, uint32_t *buf, int num)
{
    int i;

    for (i = 0; i < num; i++, buf++, addr += sizeof(*buf)) {
        cpu_physical_memory_rw(addr, (uint8_t *)buf, sizeof(*buf), 0);
        *buf = le32_to_cpu(*buf);
    }

    return 1;
}

/* Put an array of dwords in to main memory */
static inline int put_dwords(uint32_t addr, uint32_t *buf, int num)
{
    int i;

    for (i = 0; i < num; i++, buf++, addr += sizeof(*buf)) {
        uint32_t tmp = cpu_to_le32(*buf);
        cpu_physical_memory_rw(addr, (uint8_t *)&tmp, sizeof(tmp), 1);
    }

    return 1;
}

static inline int ohci_read_ed(uint32_t addr, struct ohci_ed *ed)
{
    return get_dwords(addr, (uint32_t *)ed, sizeof(*ed) >> 2);
}

static inline int ohci_read_td(uint32_t addr, struct ohci_td *td)
{
    return get_dwords(addr, (uint32_t *)td, sizeof(*td) >> 2);
}

static inline int ohci_put_ed(uint32_t addr, struct ohci_ed *ed)
{
    return put_dwords(addr, (uint32_t *)ed, sizeof(*ed) >> 2);
}

static inline int ohci_put_td(uint32_t addr, struct ohci_td *td)
{
    return put_dwords(addr, (uint32_t *)td, sizeof(*td) >> 2);
}

/* Read/Write the contents of a TD from/to main memory.  */
static void ohci_copy_td(struct ohci_td *td, uint8_t *buf, int len, int write)
{
    uint32_t ptr;
    uint32_t n;

    ptr = td->cbp;
    n = 0x1000 - (ptr & 0xfff);
    if (n > len)
        n = len;
    cpu_physical_memory_rw(ptr, buf, n, write);
    if (n == len)
        return;
    ptr = td->be & ~0xfffu;
    buf += n;
    cpu_physical_memory_rw(ptr, buf, len - n, write);
}

static void ohci_process_lists(OHCIState *ohci);

static void ohci_async_complete_packet(USBPacket * packet, void *opaque)
{
    OHCIState *ohci = opaque;
#ifdef DEBUG_PACKET
    dprintf("Async packet complete\n");
#endif
    ohci->async_complete = 1;
    ohci_process_lists(ohci);
}

/* Service a transport descriptor.
   Returns nonzero to terminate processing of this endpoint.  */

static int ohci_service_td(OHCIState *ohci, struct ohci_ed *ed)
{
    int dir;
    size_t len = 0;
    char *str = NULL;
    int pid;
    int ret;
    int i;
    USBDevice *dev;
    struct ohci_td td;
    uint32_t addr;
    int flag_r;
    int completion;

    addr = ed->head & OHCI_DPTR_MASK;
    /* See if this TD has already been submitted to the device.  */
    completion = (addr == ohci->async_td);
    if (completion && !ohci->async_complete) {
#ifdef DEBUG_PACKET
        dprintf("Skipping async TD\n");
#endif
        return 1;
    }
    if (!ohci_read_td(addr, &td)) {
        fprintf(stderr, "usb-ohci: TD read error at %x\n", addr);
        return 0;
    }

    dir = OHCI_BM(ed->flags, ED_D);
    switch (dir) {
    case OHCI_TD_DIR_OUT:
    case OHCI_TD_DIR_IN:
        /* Same value.  */
        break;
    default:
        dir = OHCI_BM(td.flags, TD_DP);
        break;
    }

    switch (dir) {
    case OHCI_TD_DIR_IN:
        str = "in";
        pid = USB_TOKEN_IN;
        break;
    case OHCI_TD_DIR_OUT:
        str = "out";
        pid = USB_TOKEN_OUT;
        break;
    case OHCI_TD_DIR_SETUP:
        str = "setup";
        pid = USB_TOKEN_SETUP;
        break;
    default:
        fprintf(stderr, "usb-ohci: Bad direction\n");
        return 1;
    }
    if (td.cbp && td.be) {
        if ((td.cbp & 0xfffff000) != (td.be & 0xfffff000)) {
            len = (td.be & 0xfff) + 0x1001 - (td.cbp & 0xfff);
        } else {
            len = (td.be - td.cbp) + 1;
        }

        if (len && dir != OHCI_TD_DIR_IN && !completion) {
            ohci_copy_td(&td, ohci->usb_buf, len, 0);
        }
    }

    flag_r = (td.flags & OHCI_TD_R) != 0;
#ifdef DEBUG_PACKET
    dprintf(" TD @ 0x%.8x %u bytes %s r=%d cbp=0x%.8x be=0x%.8x\n",
            addr, len, str, flag_r, td.cbp, td.be);

    if (len >= 0 && dir != OHCI_TD_DIR_IN) {
        dprintf("  data:");
        for (i = 0; i < len; i++)
            printf(" %.2x", ohci->usb_buf[i]);
        dprintf("\n");
    }
#endif
    if (completion) {
        ret = ohci->usb_packet.len;
        ohci->async_td = 0;
        ohci->async_complete = 0;
    } else {
        ret = USB_RET_NODEV;
        for (i = 0; i < ohci->num_ports; i++) {
            dev = ohci->rhport[i].port.dev;
            if ((ohci->rhport[i].ctrl & OHCI_PORT_PES) == 0)
                continue;

            if (ohci->async_td) {
                /* ??? The hardware should allow one active packet per
                   endpoint.  We only allow one active packet per controller.
                   This should be sufficient as long as devices respond in a
                   timely manner.
                 */
#ifdef DEBUG_PACKET
                dprintf("Too many pending packets\n");
#endif
                return 1;
            }
            ohci->usb_packet.pid = pid;
            ohci->usb_packet.devaddr = OHCI_BM(ed->flags, ED_FA);
            ohci->usb_packet.devep = OHCI_BM(ed->flags, ED_EN);
            ohci->usb_packet.data = ohci->usb_buf;
            ohci->usb_packet.len = len;
            ohci->usb_packet.complete_cb = ohci_async_complete_packet;
            ohci->usb_packet.complete_opaque = ohci;
            ret = dev->handle_packet(dev, &ohci->usb_packet);
            if (ret != USB_RET_NODEV)
                break;
        }
#ifdef DEBUG_PACKET
        dprintf("ret=%d\n", ret);
#endif
        if (ret == USB_RET_ASYNC) {
            ohci->async_td = addr;
            return 1;
        }
    }
    if (ret >= 0) {
        if (dir == OHCI_TD_DIR_IN) {
            ohci_copy_td(&td, ohci->usb_buf, ret, 1);
#ifdef DEBUG_PACKET
            dprintf("  data:");
            for (i = 0; i < ret; i++)
                printf(" %.2x", ohci->usb_buf[i]);
            dprintf("\n");
#endif
        } else {
            ret = len;
        }
    }

    /* Writeback */
    if (ret == len || (dir == OHCI_TD_DIR_IN && ret >= 0 && flag_r)) {
        /* Transmission succeeded.  */
        if (ret == len) {
            td.cbp = 0;
        } else {
            td.cbp += ret;
            if ((td.cbp & 0xfff) + ret > 0xfff) {
                td.cbp &= 0xfff;
                td.cbp |= td.be & ~0xfff;
            }
        }
        td.flags |= OHCI_TD_T1;
        td.flags ^= OHCI_TD_T0;
        OHCI_SET_BM(td.flags, TD_CC, OHCI_CC_NOERROR);
        OHCI_SET_BM(td.flags, TD_EC, 0);

        ed->head &= ~OHCI_ED_C;
        if (td.flags & OHCI_TD_T0)
            ed->head |= OHCI_ED_C;
    } else {
        if (ret >= 0) {
            dprintf("usb-ohci: Underrun\n");
            OHCI_SET_BM(td.flags, TD_CC, OHCI_CC_DATAUNDERRUN);
        } else {
            switch (ret) {
            case USB_RET_NODEV:
                OHCI_SET_BM(td.flags, TD_CC, OHCI_CC_DEVICENOTRESPONDING);
            case USB_RET_NAK:
                dprintf("usb-ohci: got NAK\n");
                return 1;
            case USB_RET_STALL:
                dprintf("usb-ohci: got STALL\n");
                OHCI_SET_BM(td.flags, TD_CC, OHCI_CC_STALL);
                break;
            case USB_RET_BABBLE:
                dprintf("usb-ohci: got BABBLE\n");
                OHCI_SET_BM(td.flags, TD_CC, OHCI_CC_DATAOVERRUN);
                break;
            default:
                fprintf(stderr, "usb-ohci: Bad device response %d\n", ret);
                OHCI_SET_BM(td.flags, TD_CC, OHCI_CC_UNDEXPETEDPID);
                OHCI_SET_BM(td.flags, TD_EC, 3);
                break;
            }
        }
        ed->head |= OHCI_ED_H;
    }

    /* Retire this TD */
    ed->head &= ~OHCI_DPTR_MASK;
    ed->head |= td.next & OHCI_DPTR_MASK;
    td.next = ohci->done;
    ohci->done = addr;
    i = OHCI_BM(td.flags, TD_DI);
    if (i < ohci->done_count)
        ohci->done_count = i;
    ohci_put_td(addr, &td);
    return OHCI_BM(td.flags, TD_CC) != OHCI_CC_NOERROR;
}

/* Service an endpoint list.  Returns nonzero if active TD were found.  */
static int ohci_service_ed_list(OHCIState *ohci, uint32_t head)
{
    struct ohci_ed ed;
    uint32_t next_ed;
    uint32_t cur;
    int active;

    active = 0;

    if (head == 0)
        return 0;

    for (cur = head; cur; cur = next_ed) {
        if (!ohci_read_ed(cur, &ed)) {
            fprintf(stderr, "usb-ohci: ED read error at %x\n", cur);
            return 0;
        }

        next_ed = ed.next & OHCI_DPTR_MASK;

        if ((ed.head & OHCI_ED_H) || (ed.flags & OHCI_ED_K)) {
            uint32_t addr;
            /* Cancel pending packets for ED that have been paused.  */
            addr = ed.head & OHCI_DPTR_MASK;
            if (ohci->async_td && addr == ohci->async_td) {
                usb_cancel_packet(&ohci->usb_packet);
                ohci->async_td = 0;
            }
            continue;
        }

        /* Skip isochronous endpoints.  */
        if (ed.flags & OHCI_ED_F)
          continue;

        while ((ed.head & OHCI_DPTR_MASK) != ed.tail) {
#ifdef DEBUG_PACKET
            dprintf("ED @ 0x%.8x fa=%u en=%u d=%u s=%u k=%u f=%u mps=%u "
                    "h=%u c=%u\n  head=0x%.8x tailp=0x%.8x next=0x%.8x\n", cur,
                    OHCI_BM(ed.flags, ED_FA), OHCI_BM(ed.flags, ED_EN),
                    OHCI_BM(ed.flags, ED_D), (ed.flags & OHCI_ED_S)!= 0,
                    (ed.flags & OHCI_ED_K) != 0, (ed.flags & OHCI_ED_F) != 0,
                    OHCI_BM(ed.flags, ED_MPS), (ed.head & OHCI_ED_H) != 0,
                    (ed.head & OHCI_ED_C) != 0, ed.head & OHCI_DPTR_MASK,
                    ed.tail & OHCI_DPTR_MASK, ed.next & OHCI_DPTR_MASK);
#endif
            active = 1;

            if (ohci_service_td(ohci, &ed))
                break;
        }

        ohci_put_ed(cur, &ed);
    }

    return active;
}

/* Generate a SOF event, and set a timer for EOF */
static void ohci_sof(OHCIState *ohci)
{
    ohci->sof_time = qemu_get_clock(vm_clock);
    qemu_mod_timer(ohci->eof_timer, ohci->sof_time + usb_frame_time);
    ohci_set_interrupt(ohci, OHCI_INTR_SF);
}

/* Process Control and Bulk lists.  */
static void ohci_process_lists(OHCIState *ohci)
{
    if ((ohci->ctl & OHCI_CTL_CLE) && (ohci->status & OHCI_STATUS_CLF)) {
        if (ohci->ctrl_cur && ohci->ctrl_cur != ohci->ctrl_head)
          dprintf("usb-ohci: head %x, cur %x\n", ohci->ctrl_head, ohci->ctrl_cur);
        if (!ohci_service_ed_list(ohci, ohci->ctrl_head)) {
            ohci->ctrl_cur = 0;
            ohci->status &= ~OHCI_STATUS_CLF;
        }
    }

    if ((ohci->ctl & OHCI_CTL_BLE) && (ohci->status & OHCI_STATUS_BLF)) {
        if (!ohci_service_ed_list(ohci, ohci->bulk_head)) {
            ohci->bulk_cur = 0;
            ohci->status &= ~OHCI_STATUS_BLF;
        }
    }
}

/* Do frame processing on frame boundary */
static void ohci_frame_boundary(void *opaque)
{
    OHCIState *ohci = opaque;
    struct ohci_hcca hcca;

    cpu_physical_memory_rw(ohci->hcca, (uint8_t *)&hcca, sizeof(hcca), 0);

    /* Process all the lists at the end of the frame */
    if (ohci->ctl & OHCI_CTL_PLE) {
        int n;

        n = ohci->frame_number & 0x1f;
        ohci_service_ed_list(ohci, le32_to_cpu(hcca.intr[n]));
    }

    /* Cancel all pending packets if either of the lists has been disabled.  */
    if (ohci->async_td &&
        ohci->old_ctl & (~ohci->ctl) & (OHCI_CTL_BLE | OHCI_CTL_CLE)) {
        usb_cancel_packet(&ohci->usb_packet);
        ohci->async_td = 0;
    }
    ohci->old_ctl = ohci->ctl;
    ohci_process_lists(ohci);

    /* Frame boundary, so do EOF stuf here */
    ohci->frt = ohci->fit;

    /* XXX: endianness */
    ohci->frame_number = (ohci->frame_number + 1) & 0xffff;
    hcca.frame = cpu_to_le32(ohci->frame_number);

    if (ohci->done_count == 0 && !(ohci->intr_status & OHCI_INTR_WD)) {
        if (!ohci->done)
            abort();
        if (ohci->intr & ohci->intr_status)
            ohci->done |= 1;
        hcca.done = cpu_to_le32(ohci->done);
        ohci->done = 0;
        ohci->done_count = 7;
        ohci_set_interrupt(ohci, OHCI_INTR_WD);
    }

    if (ohci->done_count != 7 && ohci->done_count != 0)
        ohci->done_count--;

    /* Do SOF stuff here */
    ohci_sof(ohci);

    /* Writeback HCCA */
    cpu_physical_memory_rw(ohci->hcca, (uint8_t *)&hcca, sizeof(hcca), 1);
}

/* Start sending SOF tokens across the USB bus, lists are processed in
 * next frame
 */
static int ohci_bus_start(OHCIState *ohci)
{
    ohci->eof_timer = qemu_new_timer(vm_clock,
                    ohci_frame_boundary,
                    ohci);

    if (ohci->eof_timer == NULL) {
        fprintf(stderr, "usb-ohci: %s: qemu_new_timer failed\n",
            ohci->pci_dev.name);
        /* TODO: Signal unrecoverable error */
        return 0;
    }

    dprintf("usb-ohci: %s: USB Operational\n", ohci->pci_dev.name);

    ohci_sof(ohci);

    return 1;
}

/* Stop sending SOF tokens on the bus */
static void ohci_bus_stop(OHCIState *ohci)
{
    if (ohci->eof_timer)
        qemu_del_timer(ohci->eof_timer);
}

/* Sets a flag in a port status register but only set it if the port is
 * connected, if not set ConnectStatusChange flag. If flag is enabled
 * return 1.
 */
static int ohci_port_set_if_connected(OHCIState *ohci, int i, uint32_t val)
{
    int ret = 1;

    /* writing a 0 has no effect */
    if (val == 0)
        return 0;

    /* If CurrentConnectStatus is cleared we set
     * ConnectStatusChange
     */
    if (!(ohci->rhport[i].ctrl & OHCI_PORT_CCS)) {
        ohci->rhport[i].ctrl |= OHCI_PORT_CSC;
        if (ohci->rhstatus & OHCI_RHS_DRWE) {
            /* TODO: CSC is a wakeup event */
        }
        return 0;
    }

    if (ohci->rhport[i].ctrl & val)
        ret = 0;

    /* set the bit */
    ohci->rhport[i].ctrl |= val;

    return ret;
}

/* Set the frame interval - frame interval toggle is manipulated by the hcd only */
static void ohci_set_frame_interval(OHCIState *ohci, uint16_t val)
{
    val &= OHCI_FMI_FI;

    if (val != ohci->fi) {
        dprintf("usb-ohci: %s: FrameInterval = 0x%x (%u)\n",
            ohci->pci_dev.name, ohci->fi, ohci->fi);
    }

    ohci->fi = val;
}

static void ohci_port_power(OHCIState *ohci, int i, int p)
{
    if (p) {
        ohci->rhport[i].ctrl |= OHCI_PORT_PPS;
    } else {
        ohci->rhport[i].ctrl &= ~(OHCI_PORT_PPS|
                    OHCI_PORT_CCS|
                    OHCI_PORT_PSS|
                    OHCI_PORT_PRS);
    }
}

/* Set HcControlRegister */
static void ohci_set_ctl(OHCIState *ohci, uint32_t val)
{
    uint32_t old_state;
    uint32_t new_state;

    old_state = ohci->ctl & OHCI_CTL_HCFS;
    ohci->ctl = val;
    new_state = ohci->ctl & OHCI_CTL_HCFS;

    /* no state change */
    if (old_state == new_state)
        return;

    switch (new_state) {
    case OHCI_USB_OPERATIONAL:
        ohci_bus_start(ohci);
        break;
    case OHCI_USB_SUSPEND:
        ohci_bus_stop(ohci);
        dprintf("usb-ohci: %s: USB Suspended\n", ohci->pci_dev.name);
        break;
    case OHCI_USB_RESUME:
        dprintf("usb-ohci: %s: USB Resume\n", ohci->pci_dev.name);
        break;
    case OHCI_USB_RESET:
        dprintf("usb-ohci: %s: USB Reset\n", ohci->pci_dev.name);
        break;
    }
}

static uint32_t ohci_get_frame_remaining(OHCIState *ohci)
{
    uint16_t fr;
    int64_t tks;

    if ((ohci->ctl & OHCI_CTL_HCFS) != OHCI_USB_OPERATIONAL)
        return (ohci->frt << 31);

    /* Being in USB operational state guarnatees sof_time was
     * set already.
     */
    tks = qemu_get_clock(vm_clock) - ohci->sof_time;

    /* avoid muldiv if possible */
    if (tks >= usb_frame_time)
        return (ohci->frt << 31);

    tks = muldiv64(1, tks, usb_bit_time);
    fr = (uint16_t)(ohci->fi - tks);

    return (ohci->frt << 31) | fr;
}


/* Set root hub status */
static void ohci_set_hub_status(OHCIState *ohci, uint32_t val)
{
    uint32_t old_state;

    old_state = ohci->rhstatus;

    /* write 1 to clear OCIC */
    if (val & OHCI_RHS_OCIC)
        ohci->rhstatus &= ~OHCI_RHS_OCIC;

    if (val & OHCI_RHS_LPS) {
        int i;

        for (i = 0; i < ohci->num_ports; i++)
            ohci_port_power(ohci, i, 0);
        dprintf("usb-ohci: powered down all ports\n");
    }

    if (val & OHCI_RHS_LPSC) {
        int i;

        for (i = 0; i < ohci->num_ports; i++)
            ohci_port_power(ohci, i, 1);
        dprintf("usb-ohci: powered up all ports\n");
    }

    if (val & OHCI_RHS_DRWE)
        ohci->rhstatus |= OHCI_RHS_DRWE;

    if (val & OHCI_RHS_CRWE)
        ohci->rhstatus &= ~OHCI_RHS_DRWE;

    if (old_state != ohci->rhstatus)
        ohci_set_interrupt(ohci, OHCI_INTR_RHSC);
}

/* Set root hub port status */
static void ohci_port_set_status(OHCIState *ohci, int portnum, uint32_t val)
{
    uint32_t old_state;
    OHCIPort *port;

    port = &ohci->rhport[portnum];
    old_state = port->ctrl;

    /* Write to clear CSC, PESC, PSSC, OCIC, PRSC */
    if (val & OHCI_PORT_WTC)
        port->ctrl &= ~(val & OHCI_PORT_WTC);

    if (val & OHCI_PORT_CCS)
        port->ctrl &= ~OHCI_PORT_PES;

    ohci_port_set_if_connected(ohci, portnum, val & OHCI_PORT_PES);

    if (ohci_port_set_if_connected(ohci, portnum, val & OHCI_PORT_PSS))
        dprintf("usb-ohci: port %d: SUSPEND\n", portnum);

    if (ohci_port_set_if_connected(ohci, portnum, val & OHCI_PORT_PRS)) {
        dprintf("usb-ohci: port %d: RESET\n", portnum);
        usb_send_msg(port->port.dev, USB_MSG_RESET);
        port->ctrl &= ~OHCI_PORT_PRS;
        /* ??? Should this also set OHCI_PORT_PESC.  */
        port->ctrl |= OHCI_PORT_PES | OHCI_PORT_PRSC;
    }

    /* Invert order here to ensure in ambiguous case, device is
     * powered up...
     */
    if (val & OHCI_PORT_LSDA)
        ohci_port_power(ohci, portnum, 0);
    if (val & OHCI_PORT_PPS)
        ohci_port_power(ohci, portnum, 1);

    if (old_state != port->ctrl)
        ohci_set_interrupt(ohci, OHCI_INTR_RHSC);

    return;
}

static uint32_t ohci_mem_read(void *ptr, target_phys_addr_t addr)
{
    OHCIState *ohci = ptr;

    addr -= ohci->mem_base;

    /* Only aligned reads are allowed on OHCI */
    if (addr & 3) {
        fprintf(stderr, "usb-ohci: Mis-aligned read\n");
        return 0xffffffff;
    }

    if (addr >= 0x54 && addr < 0x54 + ohci->num_ports * 4) {
        /* HcRhPortStatus */
        return ohci->rhport[(addr - 0x54) >> 2].ctrl | OHCI_PORT_PPS;
    }

    switch (addr >> 2) {
    case 0: /* HcRevision */
        return 0x10;

    case 1: /* HcControl */
        return ohci->ctl;

    case 2: /* HcCommandStatus */
        return ohci->status;

    case 3: /* HcInterruptStatus */
        return ohci->intr_status;

    case 4: /* HcInterruptEnable */
    case 5: /* HcInterruptDisable */
        return ohci->intr;

    case 6: /* HcHCCA */
        return ohci->hcca;

    case 7: /* HcPeriodCurrentED */
        return ohci->per_cur;

    case 8: /* HcControlHeadED */
        return ohci->ctrl_head;

    case 9: /* HcControlCurrentED */
        return ohci->ctrl_cur;

    case 10: /* HcBulkHeadED */
        return ohci->bulk_head;

    case 11: /* HcBulkCurrentED */
        return ohci->bulk_cur;

    case 12: /* HcDoneHead */
        return ohci->done;

    case 13: /* HcFmInterval */
        return (ohci->fit << 31) | (ohci->fsmps << 16) | (ohci->fi);

    case 14: /* HcFmRemaining */
        return ohci_get_frame_remaining(ohci);

    case 15: /* HcFmNumber */
        return ohci->frame_number;

    case 16: /* HcPeriodicStart */
        return ohci->pstart;

    case 17: /* HcLSThreshold */
        return ohci->lst;

    case 18: /* HcRhDescriptorA */
        return ohci->rhdesc_a;

    case 19: /* HcRhDescriptorB */
        return ohci->rhdesc_b;

    case 20: /* HcRhStatus */
        return ohci->rhstatus;

    default:
        fprintf(stderr, "ohci_read: Bad offset %x\n", (int)addr);
        return 0xffffffff;
    }
}

static void ohci_mem_write(void *ptr, target_phys_addr_t addr, uint32_t val)
{
    OHCIState *ohci = ptr;

    addr -= ohci->mem_base;

    /* Only aligned reads are allowed on OHCI */
    if (addr & 3) {
        fprintf(stderr, "usb-ohci: Mis-aligned write\n");
        return;
    }

    if (addr >= 0x54 && addr < 0x54 + ohci->num_ports * 4) {
        /* HcRhPortStatus */
        ohci_port_set_status(ohci, (addr - 0x54) >> 2, val);
        return;
    }

    switch (addr >> 2) {
    case 1: /* HcControl */
        ohci_set_ctl(ohci, val);
        break;

    case 2: /* HcCommandStatus */
        /* SOC is read-only */
        val = (val & ~OHCI_STATUS_SOC);

        /* Bits written as '0' remain unchanged in the register */
        ohci->status |= val;

        if (ohci->status & OHCI_STATUS_HCR)
            ohci_reset(ohci);
        break;

    case 3: /* HcInterruptStatus */
        ohci->intr_status &= ~val;
        ohci_intr_update(ohci);
        break;

    case 4: /* HcInterruptEnable */
        ohci->intr |= val;
        ohci_intr_update(ohci);
        break;

    case 5: /* HcInterruptDisable */
        ohci->intr &= ~val;
        ohci_intr_update(ohci);
        break;

    case 6: /* HcHCCA */
        ohci->hcca = val & OHCI_HCCA_MASK;
        break;

    case 8: /* HcControlHeadED */
        ohci->ctrl_head = val & OHCI_EDPTR_MASK;
        break;

    case 9: /* HcControlCurrentED */
        ohci->ctrl_cur = val & OHCI_EDPTR_MASK;
        break;

    case 10: /* HcBulkHeadED */
        ohci->bulk_head = val & OHCI_EDPTR_MASK;
        break;

    case 11: /* HcBulkCurrentED */
        ohci->bulk_cur = val & OHCI_EDPTR_MASK;
        break;

    case 13: /* HcFmInterval */
        ohci->fsmps = (val & OHCI_FMI_FSMPS) >> 16;
        ohci->fit = (val & OHCI_FMI_FIT) >> 31;
        ohci_set_frame_interval(ohci, val);
        break;

    case 16: /* HcPeriodicStart */
        ohci->pstart = val & 0xffff;
        break;

    case 17: /* HcLSThreshold */
        ohci->lst = val & 0xffff;
        break;

    case 18: /* HcRhDescriptorA */
        ohci->rhdesc_a &= ~OHCI_RHA_RW_MASK;
        ohci->rhdesc_a |= val & OHCI_RHA_RW_MASK;
        break;

    case 19: /* HcRhDescriptorB */
        break;

    case 20: /* HcRhStatus */
        ohci_set_hub_status(ohci, val);
        break;

    default:
        fprintf(stderr, "ohci_write: Bad offset %x\n", (int)addr);
        break;
    }
}

/* Only dword reads are defined on OHCI register space */
static CPUReadMemoryFunc *ohci_readfn[3]={
    ohci_mem_read,
    ohci_mem_read,
    ohci_mem_read
};

/* Only dword writes are defined on OHCI register space */
static CPUWriteMemoryFunc *ohci_writefn[3]={
    ohci_mem_write,
    ohci_mem_write,
    ohci_mem_write
};

static void ohci_mapfunc(PCIDevice *pci_dev, int i,
            uint32_t addr, uint32_t size, int type)
{
    OHCIState *ohci = (OHCIState *)pci_dev;
    ohci->mem_base = addr;
    cpu_register_physical_memory(addr, size, ohci->mem);
}

static void ohci_usb_save(QEMUFile *f, void *opaque)
{
    OHCIState *ohci = opaque;

    pci_device_save(&ohci->pci_dev, f);
}

static int ohci_usb_load(QEMUFile *f, void *opaque, int version_id)
{
    OHCIState *ohci = opaque;

    return pci_device_load(&ohci->pci_dev, f);
}

void usb_ohci_init(struct PCIBus *bus, int num_ports, int devfn)
{
    OHCIState *ohci;
    int vid = 0x106b;
    int did = 0x003f;
    int i;


    if (usb_frame_time == 0) {
#if OHCI_TIME_WARP
        usb_frame_time = ticks_per_sec;
        usb_bit_time = muldiv64(1, ticks_per_sec, USB_HZ/1000);
#else
        usb_frame_time = muldiv64(1, ticks_per_sec, 1000);
        if (ticks_per_sec >= USB_HZ) {
            usb_bit_time = muldiv64(1, ticks_per_sec, USB_HZ);
        } else {
            usb_bit_time = 1;
        }
#endif
        dprintf("usb-ohci: usb_bit_time=%lli usb_frame_time=%lli\n",
                usb_frame_time, usb_bit_time);
    }

    ohci = (OHCIState *)pci_register_device(bus, "OHCI USB", sizeof(*ohci),
                                            devfn, NULL, NULL);
    if (ohci == NULL) {
        fprintf(stderr, "usb-ohci: Failed to register PCI device\n");
        return;
    }

    ohci->pci_dev.config[0x00] = vid & 0xff;
    ohci->pci_dev.config[0x01] = (vid >> 8) & 0xff;
    ohci->pci_dev.config[0x02] = did & 0xff;
    ohci->pci_dev.config[0x03] = (did >> 8) & 0xff;
    ohci->pci_dev.config[0x09] = 0x10; /* OHCI */
    ohci->pci_dev.config[0x0a] = 0x3;
    ohci->pci_dev.config[0x0b] = 0xc;
    ohci->pci_dev.config[0x3d] = 0x01; /* interrupt pin 1 */

    ohci->mem = cpu_register_io_memory(0, ohci_readfn, ohci_writefn, ohci);

    pci_register_io_region((struct PCIDevice *)ohci, 0, 256,
                           PCI_ADDRESS_SPACE_MEM, ohci_mapfunc);

    ohci->num_ports = num_ports;
    for (i = 0; i < num_ports; i++) {
        qemu_register_usb_port(&ohci->rhport[i].port, ohci, i, ohci_attach);
    }

    register_savevm("OHCI USB", 0, 1, ohci_usb_save, ohci_usb_load, ohci);

    ohci->async_td = 0;
    ohci_reset(ohci);
}
