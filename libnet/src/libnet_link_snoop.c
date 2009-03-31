/*
 *  $Id: libnet_link_snoop.c,v 1.5 2004/01/03 20:31:02 mike Exp $
 *
 *  libnet
 *  libnet_snoop.c - snoop routines
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <sys/param.h>
#include <sys/file.h>

#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif
#include "../include/libnet.h"

#include <net/raw.h>
#include <net/if.h>

#include <netinet/ip_var.h>
#include <netinet/if_ether.h>
#include <netinet/udp_var.h>
#include <netinet/tcpip.h>

#include "../include/gnuc.h"
#include "../include/bpf.h"
#ifdef HAVE_OS_PROTO_H
#include "../include/os-proto.h"
#endif


struct libnet_link_int *
libnet_open_link_interface(int8_t *device, int8_t *ebuf)
{
    int fd;
    struct sockaddr_raw sr;
    u_int v;
    struct libnet_link_int *l;

    l = (struct libnet_link_int *)malloc(sizeof(*l));
    if (l == NULL)
    {
        sprintf(ebuf, "malloc: %s", strerror(errno));
        return (NULL);
    }
    memset(l, 0, sizeof(*l));
    l->fd = socket(PF_RAW, SOCK_RAW, RAWPROTO_DRAIN);
    if (l->fd < 0)
    {
        sprintf(ebuf, "drain socket: %s", strerror(errno));
        goto bad;
    }

    memset(&sr, 0, sizeof(sr));
    sr.sr_family = AF_RAW;
  	strncpy(sr.sr_ifname, device, sizeof(sr.sr_ifname) - 1);
    sr.sr_name[sizeof(sr.sr_name) - 1] = '\0';

    if (bind(l->fd, (struct sockaddr *)&sr, sizeof(sr)))
    {
        sprintf(ebuf, "drain bind: %s", strerror(errno));
        goto bad;
    }

    /*
     * XXX hack - map device name to link layer type
     */
    if (strncmp("et", device, 2) == 0      ||    /* Challenge 10 Mbit */
	    strncmp("ec", device, 2) == 0  ||    /* Indigo/Indy 10 Mbit, O2 10/100 */
            strncmp("ef", device, 2) == 0 ||    /* O200/2000 10/100 Mbit */
            strncmp("gfe", device, 3) == 0 ||   /* GIO 100 Mbit */
            strncmp("fxp", device, 3) == 0 ||   /* Challenge VME Enet */
            strncmp("ep", device, 2) == 0 ||    /* Challenge 8x10 Mbit EPLEX */
            strncmp("vfe", device, 3) == 0 ||   /* Challenge VME 100Mbit */
            strncmp("fa", device, 2) == 0 ||
            strncmp("qaa", device, 3) == 0)
    {
        l->linktype = DLT_EN10MB;
    }
    else if (strncmp("ipg", device, 3) == 0 ||
            strncmp("rns", device, 3) == 0 ||	/* O2/200/2000 FDDI */
            strncmp("xpi", device, 3) == 0)
        {
            l->linktype = DLT_FDDI;
	}
    else if (strncmp("ppp", device, 3) == 0) {
		l->linktype = DLT_RAW;
	} else if (strncmp("lo", device, 2) == 0) {
		l->linktype = DLT_NULL;
	} else {
		sprintf(ebuf, "drain: unknown physical layer type");
		goto bad;
	}

	return (l);
 bad:
	close(fd);
	free(l);
	return (NULL);
}


int
libnet_close_link_interface(struct libnet_link_int *l)
{
    if (close(l->fd) == 0)
    {
        free(l);
        return (1);
    }
    else
    {
        free(l);
        return (-1);
    }
}


int
libnet_write_link_layer(struct libnet_link_int *l, const int8_t *device,
            u_int8_t *buf, int len)
{
    int c;
    struct ifreq ifr;
    struct ether_header *eh = (struct ether_header *)buf;
  
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  
    if (ioctl(l->fd, SIOCGIFADDR, &ifr) == -1)
    {
        perror("ioctl SIOCGIFADDR");
        return (-1);
    }
  
    memcpy(eh->ether_shost, ifr.ifr_addr.sa_data, sizeof(eh->ether_shost));
  
    if (write(l->fd, buf, len) == -1)
    {
        /* err */
        return (-1);
    }

    return (len);
}
