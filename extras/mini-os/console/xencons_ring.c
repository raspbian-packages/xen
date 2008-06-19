#include <types.h>
#include <wait.h>
#include <mm.h>
#include <hypervisor.h>
#include <events.h>
#include <os.h>
#include <lib.h>
#include <xenbus.h>
#include <xen/io/console.h>

DECLARE_WAIT_QUEUE_HEAD(console_queue);

static inline struct xencons_interface *xencons_interface(void)
{
    return mfn_to_virt(start_info.console.domU.mfn);
}

static inline void notify_daemon(void)
{
    /* Use evtchn: this is called early, before irq is set up. */
    notify_remote_via_evtchn(start_info.console.domU.evtchn);
}

int xencons_ring_send_no_notify(const char *data, unsigned len)
{	
    int sent = 0;
	struct xencons_interface *intf = xencons_interface();
	XENCONS_RING_IDX cons, prod;
	cons = intf->out_cons;
	prod = intf->out_prod;
	mb();
	BUG_ON((prod - cons) > sizeof(intf->out));

	while ((sent < len) && ((prod - cons) < sizeof(intf->out)))
		intf->out[MASK_XENCONS_IDX(prod++, intf->out)] = data[sent++];

	wmb();
	intf->out_prod = prod;
    
    return sent;
}

int xencons_ring_send(const char *data, unsigned len)
{
    int sent;
    sent = xencons_ring_send_no_notify(data, len);
	notify_daemon();

	return sent;
}	



static void handle_input(evtchn_port_t port, struct pt_regs *regs, void *ign)
{
#ifdef HAVE_LIBC
        wake_up(&console_queue);
#else
	struct xencons_interface *intf = xencons_interface();
	XENCONS_RING_IDX cons, prod;

	cons = intf->in_cons;
	prod = intf->in_prod;
	mb();
	BUG_ON((prod - cons) > sizeof(intf->in));

	while (cons != prod) {
		xencons_rx(intf->in+MASK_XENCONS_IDX(cons,intf->in), 1, regs);
		cons++;
	}

	mb();
	intf->in_cons = cons;

	notify_daemon();

	xencons_tx();
#endif
}

#ifdef HAVE_LIBC
int xencons_ring_avail(void)
{
	struct xencons_interface *intf = xencons_interface();
	XENCONS_RING_IDX cons, prod;

	cons = intf->in_cons;
	prod = intf->in_prod;
	mb();
	BUG_ON((prod - cons) > sizeof(intf->in));

        return prod - cons;
}

int xencons_ring_recv(char *data, unsigned len)
{
	struct xencons_interface *intf = xencons_interface();
	XENCONS_RING_IDX cons, prod;
        unsigned filled = 0;

	cons = intf->in_cons;
	prod = intf->in_prod;
	mb();
	BUG_ON((prod - cons) > sizeof(intf->in));

        while (filled < len && cons + filled != prod) {
                data[filled] = *(intf->in + MASK_XENCONS_IDX(cons + filled, intf->in));
                filled++;
	}

	mb();
        intf->in_cons = cons + filled;

	notify_daemon();

        return filled;
}
#endif

int xencons_ring_init(void)
{
	int err;

	if (!start_info.console.domU.evtchn)
		return 0;

	err = bind_evtchn(start_info.console.domU.evtchn, handle_input,
			  NULL);
	if (err <= 0) {
		printk("XEN console request chn bind failed %i\n", err);
		return err;
	}
        unmask_evtchn(start_info.console.domU.evtchn);

	/* In case we have in-flight data after save/restore... */
	notify_daemon();

	return 0;
}

void xencons_resume(void)
{
	(void)xencons_ring_init();
}

