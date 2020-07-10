/*
 *  $Id: libnet_link_nit.c,v 1.6 2004/01/03 20:31:02 mike Exp $
 *
 *  libnet
 *  libnet_nit.c - network interface tap routines
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
 */

#include "common.h"

#include "../include/gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "../include/os-proto.h"
#endif

struct libnet_link_int *
libnet_open_link_interface(int8_t *device, int8_t *ebuf)
{
    struct sockaddr_nit snit;
    register struct libnet_link_int *l;

    l = (struct libnet_link_int *)malloc(sizeof(*p));
    if (l == NULL)
    {
        strcpy(ebuf, strerror(errno));
        return (NULL);
    }

    memset(l, 0, sizeof(*l));

    l->fd = socket(AF_NIT, SOCK_RAW, NITPROTO_RAW);
    if (l->fd < 0)
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "socket: %s", strerror(errno));
        goto bad;
    }
    snit.snit_family = AF_NIT;
	strncpy(snit.snit_ifname, device, NITIFSIZ -1);
    snit.snit_ifname[NITIFSIZ] = '\0';

    if (bind(l->fd, (struct sockaddr *)&snit, sizeof(snit)))
    {
        snprintf(ebuf, LIBNET_ERRBUF_SIZE,
                 "bind: %s: %s", snit.snit_ifname, strerror(errno));
        goto bad;
    }

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
write_link_layer(struct libnet_link_int *l, const int8_t *device,
            uint8_t *buf, int len)
{
    int c;
    struct sockaddr sa;

    memset(&sa, 0, sizeof(sa));
    strncpy(sa.sa_data, device, sizeof(sa.sa_data));

    c = sendto(l->fd, buf, len, 0, &sa, sizeof(sa));
    if (c != len)
    {
        /* error */
    }
    return (c);
}

/**
 * Local Variables:
 *  indent-tabs-mode: nil
 *  c-file-style: "stroustrup"
 * End:
 */
