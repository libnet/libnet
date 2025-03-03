/*
 *  $Id: libnet_link_bpf.c,v 1.6 2004/01/28 19:45:00 mike Exp $
 *
 *  libnet
 *  libnet_link_bpf.c - low-level bpf routines
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Copyright (c) 1993, 1994, 1995, 1996, 1998
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

#include <sys/param.h>  /* optionally get BSD define */
#if !defined(__OpenBSD__) && !defined(__FreeBSD__)
#include <sys/timeb.h>
#endif
#include <sys/file.h>
#include <sys/ioctl.h>

#include <sys/types.h>
#include <sys/time.h>
#include <net/bpf.h>

#include <sys/sysctl.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include "../include/gnuc.h"

#ifdef HAVE_OS_PROTO_H
#include "../include/os-proto.h"
#endif

int
libnet_bpf_open(char *err_buf)
{
    int i, fd;
    char device[] = "/dev/bpf000";

    /*
     *  Go through all the minors and find one that isn't in use.
     */
    for (i = 0; i < 1000; i++)
    {
        snprintf(device, sizeof(device), "/dev/bpf%d", i);

        fd = open(device, O_RDWR);
        if (fd == -1 && errno == EBUSY)
        {
            /*
             *  Device is busy.
             */
            continue;
        }
        else
        {
            /*
             *  Either we've got a valid file descriptor, or errno is not
             *  EBUSY meaning we've probably run out of devices.
             */
            break;
        }
    }

    if (fd == -1)
    {
        snprintf(err_buf, LIBNET_ERRBUF_SIZE, "%s(): open(): (%s): %s",
                __func__, device, strerror(errno));
    }
    return (fd);
}


int
libnet_open_link(libnet_t *l)
{
    struct ifreq ifr;
    struct bpf_version bv;
    uint v;

#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT) && !(__APPLE__)
    uint spoof_eth_src = 1;
#endif

    if (l == NULL)
    { 
        return (-1);
    } 

    if (l->device == NULL)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): NULL device", 
                __func__);
        goto bad;
    }

    l->fd = libnet_bpf_open((char*)l->err_buf);
    if (l->fd == -1)
    {
        goto bad;
    }

    /*
     *  Get bpf version.
     */
    if (ioctl(l->fd, BIOCVERSION, (caddr_t)&bv) < 0)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): BIOCVERSION: %s",
                __func__, strerror(errno));
        goto bad;
    }

    if (bv.bv_major != BPF_MAJOR_VERSION || bv.bv_minor < BPF_MINOR_VERSION)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "%s(): kernel bpf filter out of date", __func__);
        goto bad;
    }

    /*
     *  Attach network interface to bpf device.
     */
	strncpy(ifr.ifr_name, l->device, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(l->fd, BIOCSETIF, (caddr_t)&ifr) == -1)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): BIOCSETIF: (%s): %s",
                __func__, l->device, strerror(errno));
        goto bad;
    }

    /*
     *  Get the data link-layer type.
     */
    if (ioctl(l->fd, BIOCGDLT, (caddr_t)&v) == -1)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): BIOCGDLT: %s",
                __func__, strerror(errno));
        goto bad;
    }

    /*
     *  NetBSD and FreeBSD BPF have an ioctl for enabling/disabling
     *  automatic filling of the link level source address.
     */
#if defined(BIOCGHDRCMPLT) && defined(BIOCSHDRCMPLT) && !(__APPLE__)
    if (ioctl(l->fd, BIOCSHDRCMPLT, &spoof_eth_src) == -1)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): BIOCSHDRCMPLT: %s",
                __func__, strerror(errno));
        goto bad;
    }
#endif

    /*
     *  Assign link type and offset.
     */
    switch (v)
    {
        case DLT_SLIP:
            l->link_offset = 0x10;
            break;
        case DLT_RAW:
            l->link_offset = 0x0;
            break;
        case DLT_PPP:
            l->link_offset = 0x04;
            break;
        case DLT_EN10MB:
        default:
            l->link_offset = 0xe;     /* default to ethernet */
            break;
    }
#if _BSDI_VERSION - 0 >= 199510
    switch (v)
    {
        case DLT_SLIP:
            v = DLT_SLIP_BSDOS;
            l->link_offset = 0x10;
            break;
        case DLT_PPP:
            v = DLT_PPP_BSDOS;
            l->link_offset = 0x04;
            break;
    }
#endif
    l->link_type = v;

    return (1);

bad:
    if (l->fd > 0)
    {
        close(l->fd);      /* this can fail ok */
    }
    return (-1);
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
libnet_write_link(libnet_t *l, const uint8_t *packet, uint32_t size)
{
    if (l == NULL)
    { 
        return (-1);
    } 

    const int c = write(l->fd, packet, size);
    if (c != size)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "%s(): %d bytes written (%s)", __func__, c, strerror(errno));
    }
    return (c);
}


struct libnet_ether_addr *
libnet_get_hwaddr(libnet_t *l)
{
    int mib[6];
    size_t len;
    int8_t *next;
    struct if_msghdr *ifm;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    mib[5] = 0;

    if (l == NULL)
    { 
        return (NULL);
    } 

    if (l->device == NULL)
    {           
        if (libnet_select_device(l) == -1)
        {
            /* err msg set in libnet_select_device */ 
            return (NULL);
        }
    }

    if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): sysctl(): %s",
                __func__, strerror(errno));
        return (NULL);
    }

    int8_t * const buf = (int8_t *)malloc(len);
    if (buf == NULL)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): malloc(): %s",
                __func__, strerror(errno));
        return (NULL);
    }
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): sysctl(): %s",
                __func__, strerror(errno));
        free(buf);
        return (NULL);
    }
    int8_t * const end = buf + len;

    for (next = buf ; next < end ; next += ifm->ifm_msglen)
    {
        ifm = (struct if_msghdr *)next;

        if (ifm->ifm_version != RTM_VERSION)
            continue;

        if (ifm->ifm_type == RTM_IFINFO)
        {
            struct sockaddr_dl * const sdl = (struct sockaddr_dl *)(ifm + 1);
            if (sdl->sdl_type != IFT_ETHER
#ifdef IFT_FASTETHER
                && sdl->sdl_type != IFT_FASTETHER
#endif
#ifdef IFT_FASTETHERFX
                && sdl->sdl_type != IFT_FASTETHERFX
#endif
#ifdef IFT_GIGABITETHERNET
                && sdl->sdl_type != IFT_GIGABITETHERNET
#endif

                && sdl->sdl_type != IFT_L2VLAN)
                continue;
            if (sdl->sdl_nlen == strlen(l->device)
                && strncmp(&sdl->sdl_data[0], l->device, sdl->sdl_nlen) == 0)
            {
                memcpy(l->link_addr.ether_addr_octet, LLADDR(sdl), ETHER_ADDR_LEN);
                break;
            }
        }
    }
    free(buf);
    if (next == end)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                 "%s(): interface %s of known type not found.",
                 __func__, l->device);
        return NULL;
    }

    return (&l->link_addr);
}

/**
 * Local Variables:
 *  indent-tabs-mode: nil
 *  c-file-style: "stroustrup"
 * End:
 */
