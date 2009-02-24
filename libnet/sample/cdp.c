/*
 *  $Id: cdp.c,v 1.2 2004/01/03 20:31:01 mike Exp $
 *
 *  libnet 1.1
 *  Build an CDP packet
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif
#include "./libnet_test.h"

int
main(int argc, char *argv[])
{
    int c, len;
    libnet_t *l;
    libnet_ptag_t t;
    char *value;
    u_char values[100];
    u_short tmp;
    u_long tmp2;
    char *device = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];

    printf("libnet 1.1 packet shaping: CDP[link]\n"); 
    /*
     *  Initialize the library.  Root priviledges are required.
     */
    l = libnet_init(
            LIBNET_LINK,                            /* injection type */
            device,                                 /* network interface */
            errbuf);                                /* errbuf */

    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    value   = "switch";
    len     = strlen(value);

    t = libnet_build_cdp(
            1,                                      /* version */
            30,                                     /* time to live */
            0,                                      /* checksum */
            LIBNET_CDP_DEVID,                       /* type */
            len,                                    /* length */
            (u_char*)value,                         /* value */
            NULL,                                   /* payload */
            0,                                      /* payload size */
            l,                                      /* libnet handle */
            0);                                     /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build CDP header: %s\n", libnet_geterror(l));
        goto bad;
    }

    memset(values, 0, sizeof(values));
    tmp = htons(LIBNET_CDP_PORTID);
    memcpy(values, &tmp, 2);
    tmp = htons(0x0014);
    memcpy(values + 2, &tmp, 2);
    memcpy(values + 4, (u_char *)"FastEthernet0/20", 16);
    t = libnet_build_data(
            values,
            20,
            l,
            0);
    if (t == -1)
    {
        fprintf(stderr, "Can't build CDP data: %s\n", libnet_geterror(l));
        goto bad;
    }
    memset(values, 0, sizeof(values));
    tmp = htons(LIBNET_CDP_CAPABIL);
    memcpy(values, &tmp, 2);
    tmp = htons(0x0008);
    memcpy(values + 2, &tmp, 2);
    tmp2 = htonl((LIBNET_CDP_CAP_L2S | LIBNET_CDP_CAP_L2B));
    memcpy(values + 4, &tmp2, 4);
    t = libnet_build_data(
            values,
            8,
            l,
            0);
    if (t == -1)
    {
        fprintf(stderr, "Can't build CDP data: %s\n", libnet_geterror(l));
        goto bad;
    }
    memset(values, 0, sizeof(values));
    tmp = htons(LIBNET_CDP_VERSION);
    memcpy(values, &tmp, 2);
    tmp = htons(0x001f);
    memcpy(values + 2, &tmp, 2);
    memcpy(values + 4, (u_char *)"ABCDEFGHIJKLMNOPQRSTUVWXYZ", 26);
    t = libnet_build_data(
            values,
            31,
            l,
            0);
    if (t == -1)
    {
        fprintf(stderr, "Can't build CDP data: %s\n", libnet_geterror(l));
        goto bad;
    }
    memset(values, 0, sizeof(values));
    tmp = htons(LIBNET_CDP_PLATFORM);
    memcpy(values, &tmp, 2);
    tmp = htons(0x0015);
    memcpy(values + 2, &tmp, 2);
    memcpy(values + 4, (u_char *)"cisco WS-C2924-XL", 17);
    t = libnet_build_data(
            values,
            21,
            l,
            0);
    if (t == -1)
    {
        fprintf(stderr, "Can't build CDP data: %s\n", libnet_geterror(l));
        goto bad;
    }

    t = libnet_build_ethernet(
            enet_dst,                               /* ethernet destination */
            enet_src,                               /* ethernet source */
            0x2000,                                 /* protocol type */
            NULL,                                   /* payload */
            0,                                      /* payload size */
            l,                                      /* libnet handle */
            0);                                     /* libnet id */
    if (t == -1)
    {
        fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
        goto bad;
    }

    /*
     *  Write it to the wire.
     */
    c = libnet_write(l);

    if (c == -1)
    {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
        goto bad;
    }
    else
    {
        fprintf(stderr, "Wrote %d byte CDP packet; check the wire.\n", c);
    }
    libnet_destroy(l);
    return (EXIT_SUCCESS);
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);
}

/* EOF */
