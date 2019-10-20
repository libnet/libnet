/*
 *  $Id: libnet_link_snit.c,v 1.6 2004/01/03 20:31:02 mike Exp $
 *
 *  libnet
 *  libnet_snit.c - snit routines
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
 * Modifications made to accommodate the new SunOS4.0 NIT facility by
 * Micky Liu, micky@cunixc.cc.columbia.edu, Columbia University in May, 1989.
 * This module now handles the STREAMS based NIT.
 */

#include "common.h"

#include "../include/gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "../include/os-proto.h"
#endif

struct libnet_link_int *
libnet_open_link_interface(int8_t *device, int8_t *ebuf)
{
    struct strioctl si;	    /* struct for ioctl() */
    struct ifreq ifr;       /* interface request struct */
    static int8_t dev[] = "/dev/nit";
    register struct libnet_link_int *l;

    l = (struct libnet_link_int *)malloc(sizeof(*l));
    if (l == NULL)
    {
        strcpy(ebuf, strerror(errno));
        return (NULL);
    }

    memset(l, 0, sizeof(*l));

    l->fd  = open(dev, O_RDWR);
    if (l->fd < 0)
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "%s: %s", dev, strerror(errno));
        goto bad;
    }

    /*
     *  arrange to get discrete messages from the STREAM and use NIT_BUF
     */
    if (ioctl(l->fd, I_SRDOPT, (int8_t *)RMSGD) < 0)
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "I_SRDOPT: %s", strerror(errno));
        goto bad;
    }
    if (ioctl(l->fd, I_PUSH, "nbuf") < 0)
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "push nbuf: %s", strerror(errno));
        goto bad;
    }
    /*
     *  request the interface
     */
    strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) -1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
    si.ic_cmd = NIOCBIND;
    si.ic_len = sizeof(ifr);
    si.ic_dp = (int8_t *)&ifr;
    if (ioctl(l->fd, I_STR, (int8_t *)&si) < 0)
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "NIOCBIND: %s: %s", ifr.ifr_name, strerror(errno));
        goto bad;
    }

    ioctl(l->fd, I_FLUSH, (int8_t *)FLUSHR);
    /*
     * NIT supports only ethernets.
     */
    l->linktype = DLT_EN10MB;

    return (l);
bad:
    if (l->fd >= 0)
    {
        close(l->fd);
    }
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
    struct sockaddr sa;

    memset(&sa, 0, sizeof(sa));
    strncpy(sa.sa_data, device, sizeof(sa.sa_data));

    c = sendto(l->fd, buf, len, 0, &sa, sizeof(sa));
    if (c != len)
    {
        /* err */
        return (-1);
    }
    return (c);
}

/**
 * Local Variables:
 *  indent-tabs-mode: nil
 *  c-file-style: "stroustrup"
 * End:
 */
