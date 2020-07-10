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
 */

#include "common.h"

#include <sys/param.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include <net/raw.h>
#include <net/if.h>
#include <net/bpf.h>

#include <netinet/ip_var.h>
#include <netinet/if_ether.h>
#include <netinet/udp_var.h>

#include "../include/gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "../include/os-proto.h"
#endif


/**
 *
 */
int
libnet_open_link(libnet_t *l)
{
    int fd;
    struct sockaddr_raw sr;
    uint v;

    if (l == NULL)
    {
        return -1;
    }

    l->fd = socket(PF_RAW, SOCK_RAW, RAWPROTO_DRAIN);

    if (l->fd < 0)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                 "drain socket: %s", strerror(errno));
        goto bad;
    }

    memset(&sr, 0, sizeof(sr));
    sr.sr_family = AF_RAW;
    strncpy(sr.sr_ifname, l->device, sizeof(sr.sr_ifname) - 1);
    sr.sr_ifname[sizeof(sr.sr_ifname) - 1] = '\0';

    if (bind(l->fd, (struct sockaddr *)&sr, sizeof(sr)))
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                 "drain bind: %s", strerror(errno));
        goto bad;
    }

    /*
     * XXX hack - map device name to link layer type
     */
    if (strncmp("et", l->device, 2) == 0      ||   /* Challenge 10 Mbit */
            strncmp("ec", l->device, 2) == 0  ||   /* Indigo/Indy 10 Mbit, O2 10/100 */
            strncmp("ef", l->device, 2) == 0  ||   /* O200/2000 10/100 Mbit */
            strncmp("gfe", l->device, 3) == 0 ||   /* GIO 100 Mbit */
            strncmp("fxp", l->device, 3) == 0 ||   /* Challenge VME Enet */
            strncmp("ep", l->device, 2) == 0  ||   /* Challenge 8x10 Mbit EPLEX */
            strncmp("vfe", l->device, 3) == 0 ||   /* Challenge VME 100Mbit */
            strncmp("fa", l->device, 2) == 0  ||
            strncmp("qaa", l->device, 3) == 0)
    {
        l->link_type = DLT_EN10MB;
    }
    else if (strncmp("ipg", l->device, 3) == 0 ||
            strncmp("rns", l->device, 3) == 0 ||        /* O2/200/2000 FDDI */
            strncmp("xpi", l->device, 3) == 0)
    {
        l->link_type = DLT_FDDI;
    }
    else if (strncmp("ppp", l->device, 3) == 0)
    {
        l->link_type = DLT_RAW;
    }
    else if (strncmp("lo", l->device, 2) == 0)
    {
        l->link_type = DLT_NULL;
    }
    else
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                 "drain: unknown physical layer type");
        goto bad;
    }

    return 1;
bad:
    close(fd);
    free(l);
    return -1;
}


int
libnet_close_link(libnet_t *l)
{
    if (close(l->fd) == 0)
    {
        return (1);
    }
    else
    {
        return (-1);
    }
}


int
libnet_write_link(libnet_t *l, const uint8_t *buf, uint32_t len)
{
    int c;
    struct ifreq ifr;
    struct ether_header *eh = (struct ether_header *)buf;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, l->device, sizeof(ifr.ifr_name));

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

struct libnet_ether_addr *
libnet_get_hwaddr(libnet_t *l)
{
    struct ifreq ifdat;
    int s = -1;

    if (-1 == (s = socket(PF_RAW, SOCK_RAW, RAWPROTO_SNOOP)))
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "socket(): %s", strerror(errno));
        goto errout;
    }

    memset(&ifdat, 0, sizeof(struct ifreq));
    strncpy(ifdat.ifr_name, l->device, IFNAMSIZ);
    if (ioctl(s, SIOCGIFADDR, &ifdat) < 0)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "SIOCGIFADDR: %s", strerror(errno));
        goto errout;
    }
    close(s);

    return memcpy(l->link_addr.ether_addr_octet, &ifdat.ifr_addr.sa_data,
                  ETHER_ADDR_LEN);

 errout:
    if (s > 0)
    {
        close(s);
    }
    if (ea)
    {
        free(ea);
        ea = 0;
    }

    return NULL;
}

/**
 * Local Variables:
 *  indent-tabs-mode: nil
 *  c-file-style: "stroustrup"
 * End:
 */
