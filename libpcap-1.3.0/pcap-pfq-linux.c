
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap-int.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <pcap.h>

#include <linux/filter.h>
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


static int pfq_activate_linux(pcap_t *handle)
{
	const char *device;
	int queue  = Q_ANY_QUEUE;
	int caplen = handle->snapshot; 
	int slots  = 131072;
	int offset = 0;
	int status = 0;

	char *opt;

	handle->linktype = DLT_EN10MB;
	handle->offset = 0;

	if (opt = getenv("PFQ_OFFSET"))
	{
		offset = handle->offset = atoi(opt);
	}
	if (opt = getenv("PFQ_SLOTS"))
	{
		slots = atoi(opt);
	}
	if (opt = getenv("PFQ_CAPLEN"))
	{
		caplen = atoi(opt);
	}

	device = handle->opt.source;

	handle->read_op 		= pfq_read_linux;
	handle->inject_op 		= pfq_inject_linux;
	handle->setfilter_op 		= pfq_setfilter_linux; 
	handle->setdirection_op 	= pfq_setdirection_linux;
	handle->getnonblock_op 		= pcap_getnonblock_fd;
	handle->setnonblock_op 		= pcap_setnonblock_fd;
	handle->stats_op 		= pfq_stats_linux;
	handle->cleanup_op 		= pfq_cleanup_linux;
	handle->set_datalink_op 	= NULL;	/* can't change data link type */

	/*
	 * The "any" device is a special device which causes us not
	 * to bind to a particular device and thus to look at all
	 * devices.
	 */

	if (strcmp(device, "any") == 0) { 
		if (handle->opt.promisc) {
			handle->opt.promisc = 0;
			/* Just a warning. */
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "Promiscuous mode not supported on the \"any\" device");
			status = PCAP_WARNING_PROMISC_NOTSUP;
		}
	}

	handle->md.device = strdup(device);
	if (handle->md.device == NULL) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "strdup: %s",
			 pcap_strerror(errno) );
		return PCAP_ERROR;
	}
	
	/*
	 * If we're in promiscuous mode, then we probably want 
	 * to see when the interface drops packets too, so get an
	 * initial count from /proc/net/dev
	 */

	// if (handle->opt.promisc)
	//	handle->md.proc_dropped = linux_if_drops(handle->md.device);

	if (opt = getenv("PFQ_GROUP"))
	{
		handle->handler.q = pfq_open_nogroup(caplen, offset, slots);
		if (handle->handler.q == NULL)
		{	
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->handler.q));
			goto fail;
		}

		int gid = atoi(opt);                      

                fprintf(stderr, "[PFQ] capture group %d\n", gid);

		if (pfq_join_group(handle->handler.q, gid, Q_CLASS_DEFAULT, Q_GROUP_SHARED) < 0)
		{
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->handler.q));
			goto fail;
		}

		if (opt = getenv("PFQ_STEERFUN"))
		{
                	fprintf(stderr, "[PFQ] steering function: %s\n", opt);
			if (pfq_steering_function(handle->handler.q, gid, opt) < 0)
			{
				snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->handler.q));
				goto fail;
			}
		}
		
		/* bind to device */

		if (pfq_bind_group(handle->handler.q, gid, device, queue) == -1) 
		{	
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->handler.q));
			goto fail;
		}
	}
	else
	{
		handle->handler.q = pfq_open_group(Q_CLASS_DEFAULT, Q_GROUP_SHARED, caplen, offset, slots);
		if (handle->handler.q == NULL)
		{	
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->handler.q));
			goto fail;
		}
		
		/* bind to device */

		if (pfq_bind(handle->handler.q, device, queue) == -1) 
		{	
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->handler.q));
			goto fail;
		}
	}


	/* enable timestamping */

	if (pfq_set_timestamp(handle->handler.q, 1) == -1) 
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->handler.q));
		goto fail;
	}

	/* enable socket */

	if (pfq_enable(handle->handler.q) == -1)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->handler.q));
		goto fail;
	}

	handle->selectable_fd = pfq_get_fd(handle->handler.q);

	status = 1;
	return status;

fail:
	pfq_cleanup_linux(handle);
	status = -1;
	return status;
}


static int pfq_inject_linux(pcap_t *handle, const void * buf, size_t size)
{
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "inject not supported");
	return PCAP_ERROR;
}


void pfq_cleanup_linux(pcap_t *handle)
{
	if(handle->handler.q)
		pfq_close(handle->handler.q);

	pcap_cleanup_live_common(handle);
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


static int pfq_read_linux(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	handle->handler.pcap_handler = callback;
	handle->handler.pcap_user 	= user;

	if (handle->break_loop) 
	{
        	handle->break_loop = 0;
        	return PCAP_ERROR_BREAK;
	}
	return pfq_dispatch(handle->handler.q, pfq_callback, handle->md.timeout * 1000, (void *)handle, max_packets);
}


static int pfq_setdirection_linux(pcap_t *handle, pcap_direction_t d)
{
	snprintf(handle->errbuf, sizeof(handle->errbuf), "Setting direction is not supported with PFQ enabled");
	return PCAP_ERROR;
}


static int pfq_stats_linux(pcap_t *handle, struct pcap_stat *stat)
{
	struct pfq_stats pstats;

	if(pfq_get_stats(handle->handler.q, &pstats) < 0)
	{
        	return -1;
	}
	
	stat->ps_recv   = (u_int) pstats.recv;	
	stat->ps_drop   = (u_int) pstats.drop;	
	stat->ps_ifdrop = (u_int) pstats.drop + pstats.lost;	

	return 0;
}

