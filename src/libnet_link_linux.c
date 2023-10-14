/*
 *  $Id: libnet_link_linux.c,v 1.5 2004/01/03 20:31:02 mike Exp $
 *
 *  libnet 1.1
 *  libnet_link_linux.c - linux packet socket and pack socket routines
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


#include <sys/time.h>

#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

#ifndef SOL_PACKET
#define SOL_PACKET 263
#endif  /* SOL_PACKET */
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */

#include "../include/libnet.h"

/* These should not vary across linux systems, and are only defined in
 * <pcap-bpf.h>, included from <pcap.h>, but since we have no other dependency
 * on libpcap right now, define locally. I'm not sure if this is a good idea,
 * but we'll try.
 */
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_FDDI	10	/* FDDI */
#define DLT_RAW		12	/* raw IP */

#include "../include/gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "../include/os-proto.h"
#endif


int
libnet_open_link(libnet_t *l)
{
    struct ifreq ifr;
    const int n = 1;

    if (l == NULL)
    { 
        return (-1);
    } 

    l->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (l->fd == -1)
    {
        if (errno == EPERM) {
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                     "%s(): UID/EUID 0 or capability CAP_NET_RAW required",
                     __func__);

        } else {
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                     "socket: %s", strerror(errno));
        }
        goto bad;
    }

    memset(&ifr, 0, sizeof (ifr));
    strncpy(ifr.ifr_name, l->device, sizeof (ifr.ifr_name) -1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(l->fd, SIOCGIFHWADDR, &ifr) < 0 )
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "SIOCGIFHWADDR: %s", strerror(errno));
        goto bad;
    }

    switch (ifr.ifr_hwaddr.sa_family)
    {
        case ARPHRD_ETHER:
        case ARPHRD_METRICOM:
#ifdef ARPHRD_LOOPBACK
        case ARPHRD_LOOPBACK:   
#endif
            l->link_type = DLT_EN10MB;
            l->link_offset = 0xe;
            break;
        case ARPHRD_SLIP:
        case ARPHRD_CSLIP:
        case ARPHRD_SLIP6:
        case ARPHRD_CSLIP6:
        case ARPHRD_PPP:
        case ARPHRD_NONE:
            l->link_type = DLT_RAW;
            break;
        case ARPHRD_FDDI:
            l->link_type   = DLT_FDDI;
            l->link_offset = 0x15;
            break;
        /* Token Ring */
        case ARPHRD_IEEE802:
        case ARPHRD_IEEE802_TR:
        case ARPHRD_PRONET:
            l->link_type   = DLT_PRONET;
            l->link_offset = 0x16;
            break;

        default:
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "unknown physical layer type 0x%x",
                ifr.ifr_hwaddr.sa_family);
        goto bad;
    }
#ifdef SO_BROADCAST
/*
 * man 7 socket
 *
 * Set or get the broadcast flag. When  enabled,  datagram  sockets
 * receive packets sent to a broadcast address and they are allowed
 * to send packets to a broadcast  address.   This  option  has  no
 * effect on stream-oriented sockets.
 */
    if (setsockopt(l->fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n)) == -1)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
		 "%s: set SO_BROADCAST failed: %s",
		 __func__, strerror(errno));
        goto bad;
    }
#endif  /*  SO_BROADCAST  */

    return (1);

bad:
    if (l->fd >= 0)
    {
        close(l->fd);
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


static int
get_iface_index(int fd, const char *device)
{
    struct ifreq ifr;
 
    /* memset(&ifr, 0, sizeof(ifr)); */
    strncpy (ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';
 
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
    {
        return (-1);
    }
 
    return ifr.ifr_ifindex;
}


int
libnet_write_link(libnet_t *l, const uint8_t *packet, uint32_t size)
{
    struct sockaddr_ll sa;

    if (l == NULL)
    { 
        return (-1);
    }

    memset(&sa, 0, sizeof (sa));
    sa.sll_family    = AF_PACKET;
    sa.sll_ifindex   = get_iface_index(l->fd, l->device);
    if (sa.sll_ifindex == -1)
    {
        return (-1);
    }
    sa.sll_protocol  = htons(ETH_P_ALL);

    const ssize_t c = sendto(l->fd, packet, size, 0,
            (struct sockaddr *)&sa, sizeof (sa));
    if (c != (ssize_t)size)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "libnet_write_link(): only %zd bytes written (%s)", c,
                strerror(errno));
    }
    return (c);
}


struct libnet_ether_addr *
libnet_get_hwaddr(libnet_t *l)
{
    struct ifreq ifr;

    if (l == NULL)
    { 
        return (NULL);
    } 

    if (l->device == NULL)
    {           
        if (libnet_select_device(l) == -1)
        {   
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                    "libnet_get_hwaddr: can't figure out a device to use");
            return (NULL);
        }
    }

    /*
     *  Create dummy socket to perform an ioctl upon.
     */
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "socket: %s", strerror(errno));
        goto bad;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, l->device, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        close(fd);
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "ioctl: %s", strerror(errno));
        goto bad;
    }
    close(fd);

    return memcpy(l->link_addr.ether_addr_octet, &ifr.ifr_hwaddr.sa_data,
                  ETHER_ADDR_LEN);

bad:
    return (NULL);
}

/**
 * Local Variables:
 *  indent-tabs-mode: nil
 *  c-file-style: "stroustrup"
 * End:
 */
