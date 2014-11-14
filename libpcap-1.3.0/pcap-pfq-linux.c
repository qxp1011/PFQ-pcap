
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap-int.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <pcap.h>
#include "pcap/sll.h"
#include "pcap/vlan.h"

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


static int
set_kernel_filter(pcap_t *handle, struct sock_fprog *fcode)
{
	int gid = 0;
	char *opt;

	if (opt = getenv("PFQ_GROUP"))
		gid = atoi(opt);

	return pfq_group_fprog(handle->q_data.q, gid, fcode);
}


static int
reset_kernel_filter(pcap_t *handle)
{
	int gid = 0;
	char *opt;

	if (opt = getenv("PFQ_GROUP"))
		gid = atoi(opt);

	return pfq_group_fprog_reset(handle->q_data.q, gid);
}


static int
fix_offset(struct bpf_insn *p)
{
	/*
	 * What's the offset?
	 */
	if (p->k >= SLL_HDR_LEN) {
		/*
		 * It's within the link-layer payload; that starts at an
		 * offset of 0, as far as the kernel packet filter is
		 * concerned, so subtract the length of the link-layer
		 * header.
		 */
		p->k -= SLL_HDR_LEN;
	} else if (p->k == 0) {
		/*
		 * It's the packet type field; map it to the special magic
		 * kernel offset for that field.
		 */
		p->k = SKF_AD_OFF + SKF_AD_PKTTYPE;
	} else if (p->k == 14) {
		/*
		 * It's the protocol field; map it to the special magic
		 * kernel offset for that field.
		 */
		p->k = SKF_AD_OFF + SKF_AD_PROTOCOL;
	} else if ((bpf_int32)(p->k) > 0) {
		/*
		 * It's within the header, but it's not one of those
		 * fields; we can't do that in the kernel, so punt
		 * to userland.
		 */
		return -1;
	}
	return 0;
}


static int
fix_program(pcap_t *handle, struct sock_fprog *fcode, int is_mmapped)
{
	size_t prog_size;
	register int i;
	register struct bpf_insn *p;
	struct bpf_insn *f;
	int len;

	/*
	 * Make a copy of the filter, and modify that copy if
	 * necessary.
	 */
	prog_size = sizeof(*handle->fcode.bf_insns) * handle->fcode.bf_len;
	len = handle->fcode.bf_len;
	f = (struct bpf_insn *)malloc(prog_size);
	if (f == NULL) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "malloc: %s", pcap_strerror(errno));
		return -1;
	}
	memcpy(f, handle->fcode.bf_insns, prog_size);
	fcode->len = len;
	fcode->filter = (struct sock_filter *) f;

	for (i = 0; i < len; ++i) {
		p = &f[i];
		/*
		 * What type of instruction is this?
		 */
		switch (BPF_CLASS(p->code)) {

		case BPF_RET:
			/*
			 * It's a return instruction; are we capturing
			 * in memory-mapped mode?
			 */
			if (!is_mmapped) {
				/*
				 * No; is the snapshot length a constant,
				 * rather than the contents of the
				 * accumulator?
				 */
				if (BPF_MODE(p->code) == BPF_K) {
					/*
					 * Yes - if the value to be returned,
					 * i.e. the snapshot length, is
					 * anything other than 0, make it
					 * 65535, so that the packet is
					 * truncated by "recvfrom()",
					 * not by the filter.
					 *
					 * XXX - there's nothing we can
					 * easily do if it's getting the
					 * value from the accumulator; we'd
					 * have to insert code to force
					 * non-zero values to be 65535.
					 */
					if (p->k != 0)
						p->k = 65535;
				}
			}
			break;

		case BPF_LD:
		case BPF_LDX:
			/*
			 * It's a load instruction; is it loading
			 * from the packet?
			 */
			switch (BPF_MODE(p->code)) {

			case BPF_ABS:
			case BPF_IND:
			case BPF_MSH:
				/*
				 * Yes; are we in cooked mode?
				 */
				if (handle->md.cooked) {
					/*
					 * Yes, so we need to fix this
					 * instruction.
					 */
					if (fix_offset(p) < 0) {
						/*
						 * We failed to do so.
						 * Return 0, so our caller
						 * knows to punt to userland.
						 */
						return 0;
					}
				}
				break;
			}
			break;
		}
	}
	return 1;	/* we succeeded */
}


static int pfq_setfilter_linux(pcap_t *handle, struct bpf_program *filter)
{
	struct sock_fprog	fcode;
	int			can_filter_in_kernel;
	int			err = 0;

	if (!handle)
		return -1;
	if (!filter) {
	        strncpy(handle->errbuf, "[PFQ] setfilter: No filter specified",
			PCAP_ERRBUF_SIZE);
		return -1;
	}

	/* Make our private copy of the filter */

	if (install_bpf_program(handle, filter) < 0)
		/* install_bpf_program() filled in errbuf */
		return -1;

	/*
	 * Run user level packet filter by default. Will be overriden if
	 * installing a kernel filter succeeds.
	 */
	handle->md.use_bpf = 0;

	switch (fix_program(handle, &fcode, 1)) {

	case -1:
	default:
		/*
		 * Fatal error; just quit.
		 * (The "default" case shouldn't happen; we
		 * return -1 for that reason.)
		 */
		return -1;

	case 0:
		/*
		 * The program performed checks that we can't make
		 * work in the kernel.
		 */
		can_filter_in_kernel = 0;
		break;

	case 1:
		/*
		 * We have a filter that'll work in the kernel.
		 */
		can_filter_in_kernel = 1;
		break;
	}

	if (can_filter_in_kernel)
	{
		if ((err = set_kernel_filter(handle, &fcode)) == 0)
		{
			/* Installation succeded - using kernel filter. */
			handle->md.use_bpf = 1;
		}
		else if (err == -1)	/* Non-fatal error */
		{
			/*
			 * Print a warning if we weren't able to install
			 * the filter for a reason other than "this kernel
			 * isn't configured to support socket filters.
			 */
			if (errno != ENOPROTOOPT && errno != EOPNOTSUPP) {
				fprintf(stderr,
				    "[PFQ] Kernel filter failed: %s\n",
					pcap_strerror(errno));
			}
		}
	}
	else
	{
		printf("[PFQ] could not set BPF filter in kernel!\n");
	}

	/*
	 * If we're not using the kernel filter, get rid of any kernel
	 * filter that might've been there before, e.g. because the
	 * previous filter could work in the kernel, or because some other
	 * code attached a filter to the socket by some means other than
	 * calling "pcap_setfilter()".  Otherwise, the kernel filter may
	 * filter out packets that would pass the new userland filter.
	 */
	if (!handle->md.use_bpf)
		reset_kernel_filter(handle);

	/*
	 * Free up the copy of the filter that was made by "fix_program()".
	 */
	if (fcode.filter != NULL)
		free(fcode.filter);

	if (err == -2)
		/* Fatal error */
		return -1;

	return 0;
}


typedef int (*pfq_token_handler_t)(const char *);

int pfq_for_each_token(const char *ds, const char *sep, pfq_token_handler_t handler)
{
        char * mutable = strdup(ds);
        char *str, *token, *saveptr;
        int i, ret = 0;

        for (i = 1, str = mutable; ; i++, str = NULL)
        {
                token = strtok_r(str, sep, &saveptr);
                if (token == NULL)
                        break;
                if (handler(token) <0) {
		        ret = PCAP_ERROR;
			break;
		}
        }

        free(mutable);
	return ret;
}


static int pfq_activate_linux(pcap_t *handle)
{
	const char *device = NULL;
	int queue  = Q_ANY_QUEUE;
	int caplen = handle->snapshot;
	int slots  = 131072;
	int slots_tx = 4096;
	int status = 0;

        const int max_caplen = 1514;

	char *opt;

	handle->linktype = DLT_EN10MB;

	if (opt = getenv("PFQ_RX_SLOTS"))
		slots = atoi(opt);

	if (opt = getenv("PFQ_TX_SLOTS"))
		slots_tx = atoi(opt);

	if (opt = getenv("PFQ_CAPLEN"))
		caplen = atoi(opt);

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

	handle->q_data.cleanup 		= 0;

	handle->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (handle->fd == -1) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "socket: %s", pcap_strerror(errno));
		if (errno == EPERM || errno == EACCES) {
			/*
			 * You don't have permission to open the
			 * socket.
			 */
			return PCAP_ERROR_PERM_DENIED;
		} else {
			/*
			 * Other error.
			 */
			return PCAP_ERROR;
		}
	}

	/*
	 * The "any" device is a special device which causes us not
	 * to bind to a particular device and thus to look at all
	 * devices of a given group.
	 */

	/* handle promisc */

	if (handle->opt.promisc)
	{
        	/* put all devic(es) in promisc mode */
                int n = 0;

		int set_promisc(const char *dev)
		{
			struct ifreq ifr;

			memset(&ifr, 0, sizeof(ifr));
			strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
			if (ioctl(handle->fd, SIOCGIFFLAGS, &ifr) == -1) {
				snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
						"SIOCGIFFLAGS: %s", pcap_strerror(errno));
				return PCAP_ERROR;
			}
			if ((ifr.ifr_flags & IFF_PROMISC) == 0) {

				/*
				 * Promiscuous mode isn't currently on,
				 * so turn it on, and remember that
				 * we should turn it off when the
				 * pcap_t is closed.
				 */

				/*
				 * If we haven't already done so, arrange
				 * to have "pcap_close_all()" called when
				 * we exit.
				 */
				if (!pcap_do_addexit(handle)) {
					/*
					 * "atexit()" failed; don't put
					 * the interface in promiscuous
					 * mode, just give up.
					 */
					return PCAP_ERROR;
				}

				ifr.ifr_flags |= IFF_PROMISC;
				if (ioctl(handle->fd, SIOCSIFFLAGS, &ifr) == -1) {
					snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
							"SIOCSIFFLAGS: %s",
							pcap_strerror(errno));
					return PCAP_ERROR;
				}

				handle->q_data.cleanup |= (1 << n);
				handle->md.must_do_on_close |= MUST_CLEAR_PROMISC;
			}

			n++;
			return 0;
		}

		if (strcmp(device, "any") != 0) {
			if (pfq_for_each_token(device, ":", set_promisc) < 0)
			{
				return PCAP_ERROR;
			}
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

        if (caplen > max_caplen)
        {
                fprintf(stderr, "[PFQ] capture length too large (%d) -> %d forced!\n", caplen, max_caplen);
                caplen = max_caplen;
        }

	if (opt = getenv("PFQ_GROUP"))
	{
		int gid = atoi(opt);

		int bind_group(const char *dev)
		{
                	fprintf(stderr, "[PFQ] binding group %d on dev %s...\n", gid, dev);
			if (pfq_bind_group(handle->q_data.q, gid, dev, queue) == -1)
			{
				snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->q_data.q));
				return PCAP_ERROR;
			}
			return 0;
		}

		handle->q_data.q = pfq_open_nogroup(caplen, slots);
		if (handle->q_data.q == NULL)
		{
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->q_data.q));
			goto fail;
		}

                fprintf(stderr, "[PFQ] group %d\n", gid);

		if (pfq_join_group(handle->q_data.q, gid, Q_CLASS_DEFAULT, Q_POLICY_GROUP_SHARED) < 0)
		{
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->q_data.q));
			goto fail;
		}

		if (opt = getenv("PFQ_FUNCTION"))
		{
                	fprintf(stderr, "[PFQ] function: %s\n", opt);

			if (pfq_set_group_computation_from_string(handle->q_data.q, gid, opt) < 0)
			{
				snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->q_data.q));
				goto fail;
			}
		}

		/* bind to device(es) */


		if (strcmp(device, "any") != 0) {
			if (pfq_for_each_token(device, ":", bind_group) < 0)
				goto fail;
		}
	}
	else
	{
		int bind_socket(const char *dev)
		{
                	fprintf(stderr, "[PFQ] binding dev %s...\n", dev);
			if (pfq_bind(handle->q_data.q, dev, queue) == -1)
			{
				snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->q_data.q));
				return PCAP_ERROR;
			}
			return 0;
		}

		handle->q_data.q = pfq_open_group(Q_CLASS_DEFAULT, Q_POLICY_GROUP_SHARED, caplen, slots, caplen, slots_tx);
		if (handle->q_data.q == NULL)
		{
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->q_data.q));
			goto fail;
		}

		/* bind to device(es) */

		if (strcmp(device, "any") != 0) {
			if (pfq_for_each_token(device, ":", bind_socket) < 0)
				goto fail;
		}
	}

	/* set vlan filters */

	if (opt = getenv("PFQ_VLAN_ID"))
        {
                int gid = pfq_group_id(handle->q_data.q);

                if (gid == -1) {
                	fprintf(stderr, "[PFQ] group %d error!\n", gid);
                	return PCAP_ERROR;
                }


                if (pfq_vlan_filters_enable(handle->q_data.q, gid, 1) < 0)
                {
                	fprintf(stderr, "[PFQ] group %d enabling vlan filters error!\n", gid);
                	return PCAP_ERROR;
                }

		int set_vlan_filter(const char *vid_)
		{
		        int vid = atoi(vid_);

                	fprintf(stderr, "[PFQ] group %d setting vlan filer id=%d\n", gid, vid);
			if (pfq_vlan_set_filter(handle->q_data.q, gid, vid)  == -1)
			{
				snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->q_data.q));
				return PCAP_ERROR;
			}
			return 0;
		}

		if (pfq_for_each_token(opt, ",", set_vlan_filter) < 0)
                {
                        goto fail;
                }
        }

	/* enable timestamping */

	if (pfq_timestamp_enable(handle->q_data.q, 1) == -1)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->q_data.q));
		goto fail;
	}

	/* enable socket */

	if (pfq_enable(handle->q_data.q) == -1)
	{
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "%s", pfq_error(handle->q_data.q));
		goto fail;
	}

	/* handle->selectable_fd = pfq_get_fd(handle->q_data.q); */

	handle->selectable_fd = -1;
	return 0;

fail:
	pfq_cleanup_linux(handle);
	return PCAP_ERROR;
}


static int pfq_inject_linux(pcap_t *handle, const void * buf, size_t size)
{
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "inject not supported");
	return PCAP_ERROR;
}


void pfq_cleanup_linux(pcap_t *handle)
{
	int n = 0;
	int clear_promisc(const char *dev)
	{
		struct ifreq ifr;

		if (!(handle->q_data.cleanup & (1 << n++)))
			return 0;

		fprintf(stderr, "[PFQ] clear promisc on %s...\n", dev);

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, dev,
				sizeof(ifr.ifr_name));
		if (ioctl(handle->fd, SIOCGIFFLAGS, &ifr) == -1) {
			fprintf(stderr,
					"Can't restore interface %s flags (SIOCGIFFLAGS failed: %s).\n"
					"Please adjust manually.\n"
					"Hint: This can't happen with Linux >= 2.2.0.\n",
					dev, strerror(errno));
		} else {
			if (ifr.ifr_flags & IFF_PROMISC) {
				/*
				 * Promiscuous mode is currently on;
				 * turn it off.
				 */
				ifr.ifr_flags &= ~IFF_PROMISC;
				if (ioctl(handle->fd, SIOCSIFFLAGS,
							&ifr) == -1) {
					fprintf(stderr,
							"Can't restore interface %s flags (SIOCSIFFLAGS failed: %s).\n"
							"Please adjust manually.\n"
							"Hint: This can't happen with Linux >= 2.2.0.\n",
							dev,
							strerror(errno));
				}
			}
		}

		return 0;
	}

	if (handle->md.must_do_on_close & MUST_CLEAR_PROMISC) {

		if (strcmp(handle->md.device, "any") != 0) {
			pfq_for_each_token(handle->md.device, ":", clear_promisc);
		}
	}

	if(handle->q_data.q) {
		fprintf(stderr, "[PFQ] close socket...\n");
		pfq_close(handle->q_data.q);
		handle->q_data.q = NULL;
	}

	close(handle->fd);

	if (handle->md.device != NULL) {
		free(handle->md.device);
		handle->md.device = NULL;
	}

	pcap_cleanup_live_common(handle);
}


static int
pfq_read_linux(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
	int n = max_packets;
	struct pfq_net_queue nq;
        int start = handle->md.packets_read;

	pfq_iterator_t it, it_end;

        if (handle->q_data.current == handle->q_data.end)
	{
        	if (pfq_read(handle->q_data.q, &nq, handle->md.timeout > 0 ? handle->md.timeout * 1000 : 50000) < 0)
		{
			snprintf(handle->errbuf, sizeof(handle->errbuf), "PFQ read error");
			return PCAP_ERROR;
		}
		handle->q_data.current = pfq_net_queue_begin(&nq);
		handle->q_data.end     = pfq_net_queue_end(&nq);
	}

	it = handle->q_data.current;
	it_end = handle->q_data.end;

	for(; (max_packets <= 0 || n > 0) && (it != it_end); it = pfq_net_queue_next(&nq, it))
	{
		struct pcap_pkthdr pcap_h;
		struct pfq_pkt_hdr *h;
                uint16_t vlan_tci;
		const char *pkt;

		while (!pfq_iterator_ready(&nq, it))
			pfq_yield();

		h = (struct pfq_pkt_hdr *)pfq_iterator_header(it);

		pcap_h.ts.tv_sec  = h->tstamp.tv.sec;
		pcap_h.ts.tv_usec = h->tstamp.tv.nsec / 1000;
		pcap_h.caplen     = h->caplen;
		pcap_h.len        = h->len;

		pkt = pfq_iterator_data(it);

		if ((vlan_tci = h->un.vlan_tci) != 0)
		{
			struct vlan_tag *tag;

			pkt -= VLAN_TAG_LEN;

			memmove((char *)pkt, pkt + VLAN_TAG_LEN, 2 * ETH_ALEN);

			tag = (struct vlan_tag *)(pkt + 2 * ETH_ALEN);
			tag->vlan_tpid = htons(ETH_P_8021Q);
			tag->vlan_tci  = htons(vlan_tci);

			pcap_h.len += VLAN_TAG_LEN;
		}

		callback(user, &pcap_h, pkt);

		handle->md.packets_read++;
		n--;
	}

	if (handle->break_loop)
	{
		handle->break_loop = 0;
		return PCAP_ERROR_BREAK;
	}

	handle->q_data.current = it;
	return handle->md.packets_read-start;
}


static int pfq_setdirection_linux(pcap_t *handle, pcap_direction_t d)
{
	snprintf(handle->errbuf, sizeof(handle->errbuf), "Setting direction is not supported with PFQ enabled");
	return PCAP_ERROR;
}


static int pfq_stats_linux(pcap_t *handle, struct pcap_stat *stat)
{
	struct pfq_stats qstats;

	if(pfq_get_stats(handle->q_data.q, &qstats) < 0)
	{
        	return -1;
	}

	stat->ps_recv   = handle->md.packets_read;
	stat->ps_drop   = 0;
	stat->ps_ifdrop = (u_int) qstats.drop + (u_int) qstats.lost;

	return 0;
}

