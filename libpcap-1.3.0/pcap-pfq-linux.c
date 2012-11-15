
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <pcap-int.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <linux/filter.h>
#include <stdlib.h>

#include <pcap.h>

// pfq
#include <linux/if_ether.h>

#include <linux/pf_q.h>
#include <pfq/pfq.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/mman.h>
#include <poll.h>

/*
	typedef int	(*activate_op_t)(pcap_t *);				
	typedef int	(*can_set_rfmon_op_t)(pcap_t *);			
	typedef int	(*read_op_t)(pcap_t *, int cnt, pcap_handler, u_char *);
	typedef int	(*inject_op_t)(pcap_t *, const void *, size_t);		
	typedef int	(*setfilter_op_t)(pcap_t *, struct bpf_program *);	
	typedef int	(*setdirection_op_t)(pcap_t *, pcap_direction_t);	
	typedef int	(*set_datalink_op_t)(pcap_t *, int);			
	typedef int	(*getnonblock_op_t)(pcap_t *, char *);			
	typedef int	(*setnonblock_op_t)(pcap_t *, int, char *);		
	typedef int	(*stats_op_t)(pcap_t *, struct pcap_stat *);		
	typedef void	(*cleanup_op_t)(pcap_t *);				
*/


static 	int pfq_activate_linux(pcap_t *);
static 	int pfq_inject_linux(pcap_t *, const void *, size_t);
static	int pfq_setdirection_linux(pcap_t *, pcap_direction_t);
//static int pfq_getnonblock_fd(pcap_t *, char *);
//static int pfq_setnonblock_fd(pcap_t *, char *);
static  void pfq_cleanup_linux(pcap_t *);
static 	int pfq_read_linux(pcap_t *, int, pcap_handler, u_char *);
static 	int pfq_stats_linux(pcap_t *, struct pcap_stat *);


pcap_t *pfq_create(const char *device, char *ebuf)
{
	pcap_t *p;

	p = pcap_create_common(device, ebuf);
	if (p == NULL)
		return NULL;
	
	p->activate_op = pfq_activate_linux;
	return p;
}


static int pfq_setfilter_linux(pcap_t *p, struct bpf_program *fp)
{
	return 0;
}


static int pfq_activate_linux(pcap_t *p)
{
	const char *device;
	int queue  = Q_ANY_QUEUE;
	int caplen = p->snapshot; 
	int slots  = 256;
	int offset = 0;
	int status = 0;

	char *opt;

	p->linktype = DLT_EN10MB;
	p->offset = 0;

	if (opt = getenv("PFQ_OFFSET"))
	{
		offset = p->offset = atoi(opt);
	}
	if (opt = getenv("PFQ_QUEUE_SLOTS"))
	{
		slots = atoi(opt);
	}
	if (opt = getenv("PFQ_CAPLEN"))
	{
		caplen = atoi(opt);
	}

	device = p->opt.source;

	p->read_op 		= pfq_read_linux;
	p->inject_op 		= pfq_inject_linux;
	p->setfilter_op 	= pfq_setfilter_linux; 
	p->setdirection_op 	= pfq_setdirection_linux;
	p->getnonblock_op 	= pcap_getnonblock_fd;
	p->setnonblock_op 	= pcap_setnonblock_fd;
	p->stats_op 		= pfq_stats_linux;
	p->cleanup_op 		= pfq_cleanup_linux;
	p->set_datalink_op 	= NULL;	/* can't change data link type */

	/*
	 * The "any" device is a special device which causes us not
	 * to bind to a particular device and thus to look at all
	 * devices.
	 */

	if (strcmp(device, "any") == 0) { 
		if (p->opt.promisc) {
			p->opt.promisc = 0;
			/* Just a warning. */
			snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			    "Promiscuous mode not supported on the \"any\" device");
			status = PCAP_WARNING_PROMISC_NOTSUP;
		}
	}

	p->md.device = strdup(device);
	if (p->md.device == NULL) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "strdup: %s",
			 pcap_strerror(errno) );
		return PCAP_ERROR;
	}
	
	/*
	 * If we're in promiscuous mode, then we probably want 
	 * to see when the interface drops packets too, so get an
	 * initial count from /proc/net/dev
	 */

	// if (p->opt.promisc)
	//	p->md.proc_dropped = linux_if_drops(p->md.device);

	p->handler.q = pfq_open_group(Q_CLASS_DEFAULT, Q_GROUP_SHARED, caplen, offset, slots);
	if (p->handler.q == NULL)
	{
		fprintf(stderr, "[PFQ] could not open group!\n");
		goto fail;
	}

	if (pfq_bind(p->handler.q, device, queue) == -1) 
	{	
		fprintf(stderr, "[PFQ] bind: could not bind device %s (queue=%d)!\n", device, queue);
		goto fail;
	}

	if (pfq_set_timestamp(p->handler.q, 1) == -1) 
	{
		fprintf(stderr, "[PFQ] could not enable timestamps!\n");
		goto fail;
	}

	if (pfq_enable(p->handler.q) == -1)
	{
		fprintf(stderr, "[PFQ] could not enable socket!\n");
		goto fail;
	}

	p->selectable_fd = pfq_get_fd(p->handler.q);

	status = 1;
	return status;

fail:
	pfq_cleanup_linux(p);
	status = -1;
	return status;
}


static int pfq_inject_linux(pcap_t *p, const void * buf, size_t size)
{
	snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "inject not supported");
	return (-1);
}


void pfq_cleanup_linux(pcap_t *p)
{
	if(p->handler.q)
		pfq_close(p->handler.q);

	pcap_cleanup_live_common(p);
}


void pfq_callback (char *user, const struct pfq_hdr *pfq_h, const char *data)
{
	struct pcap_pkthdr pcap_h;
	
	pcap_h.ts.tv_sec  = pfq_h->tstamp.tv.sec;
	pcap_h.ts.tv_usec = pfq_h->tstamp.tv.nsec / 1000;
	pcap_h.caplen     = pfq_h->caplen;
	pcap_h.len        = pfq_h->len;

	pcap_handler cb  = ((pcap_t*)user)->handler.pcap_handler;

	cb(((pcap_t *)user)->handler.pcap_user, &pcap_h, data);
}


static int pfq_read_linux(pcap_t *p, int max_packets, pcap_handler callback, u_char *user)
{
	p->handler.pcap_handler = callback;
	p->handler.pcap_user 	= user;

	return pfq_dispatch(p->handler.q, pfq_callback, p->md.timeout * 1000, (void *)p, max_packets);
}


static int pfq_setdirection_linux(pcap_t *p, pcap_direction_t d)
{
	snprintf(p->errbuf, sizeof(p->errbuf), "Setting direction is not supported with PFQ enabled");
	return (-1);
}


static int pfq_stats_linux(pcap_t *p, struct pcap_stat *stat)
{
	struct pfq_stats pstats;

	if(pfq_get_stats(p->handler.q, &pstats) < 0)
	{
        	return -1;
	}
	
	stat->ps_recv   = (u_int) pstats.recv;	
	stat->ps_drop   = (u_int) pstats.drop;	
	stat->ps_ifdrop = (u_int) pstats.drop + pstats.lost;	

	return 0;
}

