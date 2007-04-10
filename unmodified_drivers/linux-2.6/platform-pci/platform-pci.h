/******************************************************************************
 * platform-pci.h
 * 
 * Xen platform PCI device driver
 * Copyright (c) 2004, Intel Corporation. <xiaofeng.ling@intel.com>
 * Copyright (c) 2007, XenSource Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#ifndef _XEN_PLATFORM_PCI_H
#define _XEN_PLATFORM_PCI_H

#include <linux/interrupt.h>

unsigned long alloc_xen_mmio(unsigned long len);
int gnttab_init(void);
irqreturn_t evtchn_interrupt(int irq, void *dev_id, struct pt_regs *regs);
void irq_suspend(void);
void irq_suspend_cancel(void);

void platform_pci_suspend(void);
void platform_pci_suspend_cancel(void);
void platform_pci_resume(void);

#endif /* _XEN_PLATFORM_PCI_H */
