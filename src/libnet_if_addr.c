/*
 *  $Id: libnet_if_addr.c,v 1.23 2004/04/13 17:32:28 mike Exp $
 *
 *  libnet
 *  libnet_if_addr.c - interface selection code
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

#include "common.h"

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

struct ifaddrlist
{
#if (HAVE_SOLARIS || HAVE_HPUX11)
    uint addr;
#else
    uint32_t addr;
#endif
    char *device;
};

struct libnet_ifaddr_list
{
    uint32_t addr;
    char *device;
};

#define MAX_IPADDR 512
static size_t ip_addr_num = MAX_IPADDR;

#if !(__WIN32__)

/*
 * By testing if we can retrieve the FLAGS of an iface
 * we can know if it exists or not and if it is up.
 */
int 
libnet_check_iface(libnet_t *l)
{
    struct ifreq ifr;
    int res;

    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s() socket: %s", __func__, strerror(errno));
        return (-1);
    }

    strncpy(ifr.ifr_name, l->device, sizeof(ifr.ifr_name) -1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
    
    res = ioctl(fd, SIOCGIFFLAGS, (int8_t *)&ifr);
    if (res < 0)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s() ioctl: %s", __func__, strerror(errno));
    }
    else
    {
        if ((ifr.ifr_flags & IFF_UP) == 0)
        {
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): %s is down", __func__, l->device);
	    res = -1;
        }
    }
    close(fd);

    return (res);
}

#endif

#if defined(__OpenBSD__) ||  defined(__linux__)
#include <sys/types.h>
    #ifdef __OpenBSD__
    #include <sys/socket.h>
    #endif
#include <ifaddrs.h>

int
libnet_ifaddrlist(struct libnet_ifaddr_list **ipaddrp, const char *dev, char *errbuf)
{
    struct libnet_ifaddr_list *ifaddrlist = NULL;
    struct ifaddrs *ifap, *ifa;
    size_t nipaddr = 0;

    if (getifaddrs(&ifap) != 0)
    {
        snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): getifaddrs: %s", __func__, strerror(errno));
        return 0;
    }

    ifaddrlist = calloc(ip_addr_num, sizeof(struct libnet_ifaddr_list));
    if (!ifaddrlist)
    {
        snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): OOM when allocating initial ifaddrlist", __func__);
        return (-1);
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next)
    {
        struct libnet_ifaddr_list *al = &ifaddrlist[nipaddr];

        if (dev == NULL && (ifa->ifa_flags & IFF_LOOPBACK))
            continue;

        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        al->device = strdup(ifa->ifa_name);
        if (al->device == NULL)
        {
            snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): OOM", __func__);
            continue;
        }
        al->addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
        nipaddr++;

        if (nipaddr == ip_addr_num) {
            struct libnet_ifaddr_list *tmp;

            /* grow by a factor of 1.5, close enough to golden ratio */
            ip_addr_num += ip_addr_num >> 2;
            tmp = realloc(ifaddrlist, ip_addr_num * sizeof(struct libnet_ifaddr_list));
            if (!tmp)
            {
                snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): OOM reallocating ifaddrlist", __func__);
                break;
            }

            ifaddrlist = tmp;
        }
    }

    freeifaddrs(ifap);
    *ipaddrp = ifaddrlist;
    return ((int)nipaddr);
}


#else
#if !(__WIN32__)


#ifdef HAVE_LINUX_PROCFS /* Unclear (2022) which OSs end up here ... speculative code */
#define PROC_DEV_FILE "/proc/net/dev"

#ifndef BUFSIZE
#define BUFSIZE 2048
#endif

int
libnet_ifaddrlist(struct libnet_ifaddr_list **ipaddrp, const char *dev, char *errbuf)
{
    struct libnet_ifaddr_list *ifaddrlist = NULL;
    struct ifreq ibuf[MAX_IPADDR];
    size_t nipaddr = 0;
    struct ifconf ifc;
    char buf[BUFSIZE];

    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
	snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): socket error: %s", __func__, strerror(errno));
	return (-1);
    }

    FILE * const fp = fopen(PROC_DEV_FILE, "r");
    if (!fp)
    {
	snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): failed opening %s: %s",  __func__, PROC_DEV_FILE, strerror(errno));
	goto bad;
    }

    memset(&ifc, 0, sizeof(ifc));
    ifc.ifc_len = sizeof(ibuf);
    ifc.ifc_buf = (caddr_t)ibuf;

    if (ioctl(fd, SIOCGIFCONF, &ifc) < 0)
    {
	snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): ioctl(SIOCGIFCONF) error: %s", __func__, strerror(errno));
	goto bad;
    }

    ifaddrlist = calloc(ip_addr_num, sizeof(struct libnet_ifaddr_list));
    if (!ifaddrlist)
    {
        snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): OOM when allocating initial ifaddrlist", __func__);
	goto bad;
    }

    while (fgets(buf, sizeof(buf), fp))
    {
        struct libnet_ifaddr_list *al = &ifaddrlist[nipaddr];
        struct ifreq ifr;
        char *nm;

        nm = strchr(buf, ':');
	if (!nm)
            continue;

        *nm = '\0';
        for (nm = buf; *nm == ' '; nm++)
	    ;
	
        strncpy(ifr.ifr_name, nm, sizeof(ifr.ifr_name) - 1);
        ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = 0;
        if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
            continue;
        if ((ifr.ifr_flags & IFF_UP) == 0)
            continue;
        if (dev == NULL && LIBNET_ISLOOPBACK(&ifr))
            continue;

        if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
        {
            if (errno != EADDRNOTAVAIL)
            {
                snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): SIOCGIFADDR: dev=%s: %s", __func__, ifr.ifr_name, strerror(errno));
                goto bad;
	    }

            /* device has no IP address => set to 0 */
            al->addr = 0;
        }
        else
        {
            al->addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
        }

        al->device = strdup(ifr.ifr_name);
        if (al->device == NULL)
        {
            snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): strdup not enough memory", __func__);
            goto bad;
        }

        nipaddr++;
        if (nipaddr == ip_addr_num) {
            struct libnet_ifaddr_list *tmp;

            /* grow by a factor of 1.5, close enough to golden ratio */
            ip_addr_num += ip_addr_num >> 2;
            tmp = realloc(ifaddrlist, ip_addr_num * sizeof(struct libnet_ifaddr_list));
            if (!tmp) {
                snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): OOM reallocating ifaddrlist", __func__);
                break;
            }

            ifaddrlist = tmp;
        }
    }
	
    if (ferror(fp))
    {
        snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): ferror: %s", __func__, strerror(errno));
	goto bad;
    }
    fclose(fp);

    close(fd);
    *ipaddrp = ifaddrlist;

    return ((int)nipaddr);
bad:
    if (ifaddrlist)
        free(ifaddrlist);
    if (fp)
	fclose(fp);
    close(fd);
    return (-1);
}

#else  /* !HAVE_LINUX_PROCFS && !__WIN32__ */

#ifdef HAVE_SOCKADDR_SA_LEN
#define NEXTIFR(i) ((struct ifreq *)((u_char *)&i->ifr_addr + i->ifr_addr.sa_len))
#else
#define NEXTIFR(i) (i + 1)
#endif

int
libnet_ifaddrlist(struct libnet_ifaddr_list **ipaddrp, const char *dev, char *errbuf)
{
    struct libnet_ifaddr_list *ifaddrlist = NULL;
    struct ifreq *ifr, *pifr, nifr;
    struct ifreq ibuf[MAX_IPADDR];
    size_t nipaddr = 0;
    struct ifconf ifc;

    const int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
	snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): socket error: %s", __func__, strerror(errno));
	return (-1);
    }

    memset(&ifc, 0, sizeof(ifc));
    ifc.ifc_len = sizeof(ibuf);
    ifc.ifc_buf = (caddr_t)ibuf;

    if (ioctl(fd, SIOCGIFCONF, &ifc) < 0)
    {
	snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): ioctl(SIOCGIFCONF) error: %s", __func__, strerror(errno));
	goto bad;
    }

    pifr = NULL;
    struct ifreq * const lifr = (struct ifreq *)&ifc.ifc_buf[ifc.ifc_len];

    ifaddrlist = calloc(ip_addr_num, sizeof(struct libnet_ifaddr_list));
    if (!ifaddrlist)
    {
        snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): OOM when allocating initial ifaddrlist", __func__);
	goto bad;
    }

    for (ifr = ifc.ifc_req; ifr < lifr; ifr = NEXTIFR(ifr))
    {
        struct libnet_ifaddr_list *al = &ifaddrlist[nipaddr];
        char *ptr;

	/* XXX LINUX SOLARIS ifalias */
        ptr = strchr(ifr->ifr_name, ':');
	if (ptr)
            *ptr = '\0';

	if (pifr && strcmp(ifr->ifr_name, pifr->ifr_name) == 0)
            continue;

	strncpy(nifr.ifr_name, ifr->ifr_name, sizeof(nifr.ifr_name) - 1);
	nifr.ifr_name[sizeof(nifr.ifr_name) - 1] = '\0';
        if (ioctl(fd, SIOCGIFFLAGS, &nifr) < 0)
        {
            pifr = ifr;
            continue;
	}
        if ((nifr.ifr_flags & IFF_UP) == 0)
	{
            pifr = ifr;
            continue;	
	}

        if (dev == NULL && LIBNET_ISLOOPBACK(&nifr))
	{
            pifr = ifr;
            continue;
	}
	
        if (ioctl(fd, SIOCGIFADDR, &nifr) < 0)
        {
            if (errno != EADDRNOTAVAIL)
            {
                snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): SIOCGIFADDR: dev=%s: %s", __func__, nifr.ifr_name, strerror(errno));
                goto bad;
	    }

            /* device has no IP address => set to 0 */
            al->addr = 0;
        }
        else
        {
            al->addr = ((struct sockaddr_in *)&nifr.ifr_addr)->sin_addr.s_addr;
        }
        
        al->device = strdup(nifr.ifr_name);
        if (al->device == NULL)
        {
            snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): strdup not enough memory", __func__);
            goto bad;
        }

        nipaddr++;
        if (nipaddr == ip_addr_num) {
            struct libnet_ifaddr_list *tmp;

            /* grow by a factor of 1.5, close enough to golden ratio */
            ip_addr_num += ip_addr_num >> 2;
            tmp = realloc(ifaddrlist, ip_addr_num * sizeof(struct libnet_ifaddr_list));
            if (!tmp) {
                snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): OOM reallocating ifaddrlist", __func__);
                break;
            }

            ifaddrlist = tmp;
        }

        pifr = ifr;
    }
	
    close(fd);
    *ipaddrp = ifaddrlist;

    return ((int)nipaddr);
bad:
    if (ifaddrlist)
        free(ifaddrlist);
    close(fd);
    return (-1);
}

#endif  /* HAVE_LINUX_PROCFS */

#else
/* WIN32 support *
 * TODO move win32 support into win32 specific source file */

/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS    12
static int8_t *iptos(uint32_t in)
{
    static int8_t output[IPTOSBUFFERS][ 3 * 4 + 3 + 1];
    static int16_t which;

    uint8_t * const p = (uint8_t *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    snprintf(output[which], IPTOSBUFFERS, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

    return output[which];
}

int
libnet_ifaddrlist(struct libnet_ifaddr_list **ipaddrp, char *unused, char *errbuf)
{
    struct libnet_ifaddr_list *ifaddrlist = NULL;
    int8_t err[PCAP_ERRBUF_SIZE];
    pcap_if_t *devlist = NULL;
    pcap_if_t *dev = NULL;
    size_t nipaddr = 0;

    (void)unused;

    /* Retrieve the interfaces list */
    if (pcap_findalldevs(&devlist, err) == -1)
    {
        snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): error in pcap_findalldevs: %s", __func__, err);
        return (-1);
    }

    ifaddrlist = calloc(ip_addr_num, sizeof(struct libnet_ifaddr_list));
    if (!ifaddrlist)
    {
        snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): OOM when allocating initial ifaddrlist", __func__);
        return (0);
    }

    for (dev = devlist; dev; dev = dev->next)
    {
        struct pcap_addr *pcapaddr;

        for (pcapaddr = dev->addresses; pcapaddr; pcapaddr = pcapaddr->next)
        {
            struct libnet_ifaddr_list *al = &ifaddrlist[nipaddr];
            struct sockaddr *addr = pcapaddr->addr;

#if 0
            printf("if name '%s' description '%s' loop? %d\n", dev->name, dev->description, dev->flags);
            {
                char p[NI_MAXHOST] = "";
                int sz = sizeof(struct sockaddr_storage);
                int r;
                r = getnameinfo(addr, sz, p, sizeof(p), NULL,0, NI_NUMERICHOST);
                printf("  addr %s\n", r ? gai_strerror(r) : p);
            }
#endif

            if (dev->flags & PCAP_IF_LOOPBACK)
                continue;

            /* this code ignores IPv6 addresses, a limitation of the libnet_ifaddr_list struct */

            if (addr->sa_family != AF_INET)
                continue;

            al->device = strdup(dev->name);
            al->addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
            ++nipaddr;

            if (nipaddr == ip_addr_num)
            {
                struct libnet_ifaddr_list *tmp;

                /* grow by a factor of 1.5, close enough to golden ratio */
                ip_addr_num += ip_addr_num >> 2;
                tmp = realloc(ifaddrlist, ip_addr_num * sizeof(struct libnet_ifaddr_list));
                if (!tmp)
                {
                    snprintf(errbuf, LIBNET_ERRBUF_SIZE, "%s(): OOM reallocating ifaddrlist", __func__);
                    break;
                }

                ifaddrlist = tmp;
            }
        }
    }

    pcap_freealldevs(devlist);

    *ipaddrp = ifaddrlist;

    return ((int)nipaddr);
}
#endif /* __WIN32__ */

#endif /* __OpenBSD__ */

int
libnet_select_device(libnet_t *l)
{
    struct libnet_ifaddr_list *address_list = NULL, *al;
    int rc = -1;
    int i;

    if (l == NULL)
    { 
        return (-1);
    }

    if (l->device && !isdigit(l->device[0]))
    {
#if !(__WIN32__)
	if (libnet_check_iface(l) < 0)
	{
            /* err msg set in libnet_check_iface() */
	    return (-1);
	}
#endif
	return (1);
    }

    /*
     *  Number of interfaces.
     */
    const int c = libnet_ifaddrlist(&address_list, l->device, l->err_buf);
    if (c < 0)
    {
        goto end;
    }
    else if (c == 0)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): no network interface found", __func__);
        goto end;
    }

    al = address_list;
    if (l->device)
    {
        const uint32_t addr = libnet_name2addr4(l, l->device, LIBNET_DONT_RESOLVE);

        for (i = c; i; --i, ++al)
        {
            if (!strcmp(l->device, al->device) ||  al->addr == addr)
            {
                /* free the "user supplied device" - see libnet_init() */
                free(l->device);
                l->device =  strdup(address_list->device);
                goto good;
            }
        }

        if (i <= 0)
        {
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): can't find interface for IP %s", __func__, l->device);
	    goto end;
        }
    }
    else
    {
        l->device = strdup(address_list->device);
    }

good:
    rc = 1;
end:
    if (address_list) {
        for (i = 0; i < c; i++)
        {
            free(address_list[i].device);
            address_list[i].device = NULL;
        }
        free(address_list);
    }

    return rc;
}

/**
 * Local Variables:
 *  indent-tabs-mode: nil
 *  c-file-style: "stroustrup"
 * End:
 */
