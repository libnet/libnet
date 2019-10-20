/*
 *  $Id: libnet_link_pf.c,v 1.3 2004/01/03 20:31:02 mike Exp $
 *
 *  libnet
 *  libnet_pf.c - pf routines
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * packet filter subroutines for tcpdump
 *	Extraction/creation by Jeffrey Mogul, DECWRL
 */

#include "common.h"

#include "../include/gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "../include/os-proto.h"
#endif

struct libnet_link_int *
libnet_open_link_interface(int8_t *device, int8_t *ebuf)
{
    register struct libnet_link_int *l;
    int16_t enmode;
    int backlog = -1;   /* request the most */
    struct enfilter Filter;
    struct endevp devparams;

    l = (struct libnet_link_int *)malloc(sizeof(*l));
    if (l == NULL)
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "libnet_open_link_int: %s", strerror(errno));
        return (0);
    }
    memset(l, 0, sizeof(*l));
    l->fd = pfopen(device, O_RDWR);
    if (l->fd < 0)
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "pf open: %s: %s\nyour system may not be properly configured; see \"man packetfilter(4)\"",
            device, strerror(errno));
        goto bad;
    }

    enmode = ENTSTAMP|ENBATCH|ENNONEXCL;
    if (ioctl(l->fd, EIOCMBIS, (caddr_t)&enmode) < 0)
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "EIOCMBIS: %s", strerror(errno));
        goto bad;
    }
#ifdef	ENCOPYALL
    /* Try to set COPYALL mode so that we see packets to ourself */
    enmode = ENCOPYALL;
    ioctl(l->fd, EIOCMBIS, (caddr_t)&enmode);   /* OK if this fails */
#endif
	/* set the backlog */
    if (ioctl(l->fd, EIOCSETW, (caddr_t)&backlog) < 0)
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "EIOCSETW: %s", strerror(errno));
        goto bad;
    }
    /*
     *  discover interface type
     */
    if (ioctl(l->fd, EIOCDEVP, (caddr_t)&devparams) < 0)
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "EIOCDEVP: %s", strerror(errno));
        goto bad;
    }

    /* HACK: to compile prior to Ultrix 4.2 */
#ifndef	ENDT_FDDI
#define	ENDT_FDDI   4
#endif
    switch (devparams.end_dev_type)
    {
        case ENDT_10MB:
            l->linktype = DLT_EN10MB;
            break;
        case ENDT_FDDI:
            l->linktype = DLT_FDDI;
            break;
        default:
            /*
             * XXX
             * Currently, the Ultrix packet filter supports only
             * Ethernet and FDDI.  Eventually, support for SLIP and PPP
             * (and possibly others: T1?) should be added.
             */
            l->linktype = DLT_EN10MB;
            break;
	}
    /*
     *  acceptag all packets
     */
    bzero((int8_t *)&Filter, sizeof(Filter));
    Filter.enf_Priority = 37;	/* anything > 2 */
    Filter.enf_FilterLen = 0;	/* means "always true" */
    if (ioctl(l->fd, EIOCSETF, (caddr_t)&Filter) < 0)
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "EIOCSETF: %s", strerror(errno));
        goto bad;
    }

    return (l);
bad:
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
            const uint8_t *buf, int len)
{
    int c;

    c = write(l->fd, buf, len);
    if (c != len)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
            "libnet_write_link: %d bytes written (%s)", c,
            strerror(errno));
    }
    return (c);
}

/**
 * Local Variables:
 *  indent-tabs-mode: nil
 *  c-file-style: "stroustrup"
 * End:
 */
