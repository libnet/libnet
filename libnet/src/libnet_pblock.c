/*
 *  $Id: libnet_pblock.c,v 1.14 2004/11/09 07:05:07 mike Exp $
 *
 *  libnet
 *  libnet_pblock.c - Memory protocol block routines.
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
#if (!(_WIN32) || (__CYGWIN__)) 
#include "../include/libnet.h"
#else
#include "../include/win32/libnet.h"
#endif

libnet_pblock_t *
libnet_pblock_probe(libnet_t *l, libnet_ptag_t ptag, u_int32_t n, u_int8_t type)
{
    int offset;
    libnet_pblock_t *p;

    if (ptag == LIBNET_PTAG_INITIALIZER)
    {
        /*
         *  Create a new pblock and enough buffer space for the packet.
         */
        p = libnet_pblock_new(l, n);
        if (p == NULL)
        {
            /* err msg set in libnet_pblock_new() */
            return (NULL);
        }
    }
    else
    {
        /*
         *  Update this pblock, don't create a new one.  Note that if the
         *  new packet size is larger than the old one we will do a malloc.
         */
        p = libnet_pblock_find(l, ptag);

        if (p == NULL)
        {
            /* err msg set in libnet_pblock_find() */
            return (NULL);
        }
        if (p->type != type)
        {
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
            "%s(): ptag refers to different type than expected (0x%x != 0x%x)",
               __func__, p->type, type);
            return (NULL); 
        }
        /*
         *  If size is greater than the original block of memory, we need 
         *  to malloc more memory.  Should we use realloc?
         */
        if (n > p->b_len)
        {
            offset = n - p->b_len;  /* how many bytes larger new pblock is */
            free(p->buf);
            p->buf = malloc(n);
            if (p->buf == NULL)
            {
                snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                        "%s(): can't resize pblock buffer: %s\n", __func__,
                        strerror(errno));
                return (NULL);
            }
            memset(p->buf, 0, n);
            p->h_len += offset; /* new length for checksums */
            p->b_len = n;       /* new buf len */
            l->total_size += offset;
        }
        else
        {
            offset = p->b_len - n;
            p->h_len -= offset; /* new length for checksums */
            p->b_len = n;       /* new buf len */
            l->total_size -= offset;
        }
        p->copied = 0;      /* reset copied counter */
    }
    return (p);
}

libnet_pblock_t *
libnet_pblock_new(libnet_t *l, u_int32_t size)
{
    libnet_pblock_t *p;
    /*
     *  Should we do error checking the size of the pblock here, or
     *  should we rely on the underlying operating system to complain when
     *  the user tries to write some ridiculously huge packet?
     */

    /* make the head node if it doesn't exist */
    if (l->protocol_blocks == NULL)
    {
        p = l->protocol_blocks = malloc(sizeof (libnet_pblock_t));
        if (p == NULL)
        {
            goto bad;
        }
        memset(p, 0, sizeof (libnet_pblock_t));
    }
    else
    {
        p = l->pblock_end;
        p->next = malloc(sizeof (libnet_pblock_t));

        if (p->next == NULL)
        {
            goto bad;
        }
        memset(p->next, 0, sizeof (libnet_pblock_t));
        p->next->prev = p;
        p = p->next;
    }

    p->buf = malloc(size);
    if (p->buf == NULL)
    {
        free(p);
        p = NULL;
        goto bad;
    }
    memset(p->buf, 0, size);
    p->b_len      = size;
    l->total_size += size;
    l->n_pblocks++;
    return (p);

    bad:
    snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): malloc(): %s\n", __func__, 
            strerror(errno));
    return (NULL);
}

int
libnet_pblock_swap(libnet_t *l, libnet_ptag_t ptag1, libnet_ptag_t ptag2)
{
    libnet_pblock_t *p1, *p2;

    p1 = libnet_pblock_find(l, ptag1);
    p2 = libnet_pblock_find(l, ptag2);
    if (p1 == NULL || p2 == NULL)
    {
        /* error set elsewhere */
        return (-1);
    }

    p2->prev = p1->prev;
    p1->next = p2->next;
    p2->next = p1;
    p1->prev = p2;

    if (p1->next)
    {
        p1->next->prev = p1;
    }

    if (p2->prev)
    {
        p2->prev->next = p2;
    }
    else
    {
        /* first node on the list */
        l->protocol_blocks = p2;
    }

    if (l->pblock_end == p2)
    {
        l->pblock_end = p1;
    }
    return (1);
}

int
libnet_pblock_insert_before(libnet_t *l, libnet_ptag_t ptag1,
        libnet_ptag_t ptag2)
{
    libnet_pblock_t *p1, *p2;

    p1 = libnet_pblock_find(l, ptag1);
    p2 = libnet_pblock_find(l, ptag2);
    if (p1 == NULL || p2 == NULL)
    {
        /* error set elsewhere */
        return (-1);
    }

    p2->prev = p1->prev;
    p2->next = p1;
    p1->prev = p2;

    if (p2->prev)  
    {
        p2->prev->next = p2;
    }
    else
    {
        /* first node on the list */
        l->protocol_blocks = p2;
    }
    
    return (1);
}

libnet_pblock_t *
libnet_pblock_find(libnet_t *l, libnet_ptag_t ptag)
{
    libnet_pblock_t *p;

    for (p = l->protocol_blocks; p; p = p->next)
    {
        if (p->ptag == ptag)
        {
            return (p); 
        }
    }
    snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
            "%s(): couldn't find protocol block\n", __func__);
    return (NULL);
}

int
libnet_pblock_append(libnet_t *l, libnet_pblock_t *p, u_int8_t *buf,
            u_int32_t len)
{
    if (p->copied + len > p->b_len)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "%s(): memcpy would overflow buffer\n", __func__);
        return (-1);
    }
    memcpy(p->buf + p->copied, buf, len);
    p->copied += len;
    return (1);
}

void
libnet_pblock_setflags(libnet_pblock_t *p, u_int8_t flags)
{
    p->flags = flags;
}

libnet_ptag_t
libnet_pblock_update(libnet_t *l, libnet_pblock_t *p, u_int32_t h,
u_int8_t type)
{
    p->type  =  type;
    p->ptag  =  ++(l->ptag_state);
    p->h_len = h;
    l->pblock_end = p;              /* point end of pblock list here */

    return (p->ptag);
}

int
libnet_pblock_coalesce(libnet_t *l, u_int8_t **packet, u_int32_t *size)
{
    libnet_pblock_t *p, *q;
    u_int32_t c, n;

    /*
     *  Determine the offset required to keep memory aligned (strict
     *  architectures like solaris enforce this, but's a good practice
     *  either way).  This is only required on the link layer with the
     *  14 byte ethernet offset (others are similarly unkind).
     */
    if (l->injection_type == LIBNET_LINK || 
        l->injection_type == LIBNET_LINK_ADV)
    {
        /* 8 byte alignment should work */
        l->aligner = 8 - (l->link_offset % 8);
    }
    else
    {
        l->aligner = 0;
    }

    *packet = malloc(l->aligner + l->total_size);
    if (*packet == NULL)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): malloc(): %s\n",
                __func__, strerror(errno));
        return (-1);
    }

    memset(*packet, 0, l->aligner + l->total_size);

    if (l->injection_type == LIBNET_RAW4 && 
        l->pblock_end->type == LIBNET_PBLOCK_IPV4_H)
    {
        libnet_pblock_setflags(l->pblock_end, LIBNET_PBLOCK_DO_CHECKSUM); 
    }
    
    /* additional sanity checks to perform if we're not in advanced mode */
    if (!(l->injection_type & LIBNET_ADV_MASK))
    {
    	switch (l->injection_type)
    	{
            case LIBNET_LINK:
                if ((l->pblock_end->type != LIBNET_PBLOCK_TOKEN_RING_H) &&
                    (l->pblock_end->type != LIBNET_PBLOCK_FDDI_H)       &&
                    (l->pblock_end->type != LIBNET_PBLOCK_ETH_H)        &&
                    (l->pblock_end->type != LIBNET_PBLOCK_802_1Q_H)     &&
                    (l->pblock_end->type != LIBNET_PBLOCK_ISL_H)        &&
                    (l->pblock_end->type != LIBNET_PBLOCK_802_3_H))
                {
                    snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, 
                    "%s(): packet assembly cannot find a layer 2 header\n",
                    __func__);
                    goto err;
                }
                break;
            case LIBNET_RAW4:
                if ((l->pblock_end->type != LIBNET_PBLOCK_IPV4_H))
                {
                    snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, 
                    "%s(): packet assembly cannot find an IPv4 header\n",
                     __func__);
                    goto err;
                }
                break;
            case LIBNET_RAW6:
                if ((l->pblock_end->type != LIBNET_PBLOCK_IPV6_H))
                {
                    snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, 
                    "%s(): packet assembly cannot find an IPv6 header\n",
                     __func__);
                    goto err;
                }
                break;
            default:
                /* we should not end up here ever */
                snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, 
                "%s(): suddenly the dungeon collapses -- you die\n",
                 __func__);
                goto err;
            break;
        }
    }

    q = NULL; 
    for (n = l->aligner + l->total_size, p = l->protocol_blocks; p || q; )
    {
        if (q)
        {
            p = p->next;
        }
        if (p)
        {
            n -= p->b_len;
            /* copy over the packet chunk */
            memcpy(*packet + n, p->buf, p->b_len);
        }
        if (q)
        {
            if (p == NULL || ((p->flags) & LIBNET_PBLOCK_DO_CHECKSUM))
            {
                if ((q->flags) & LIBNET_PBLOCK_DO_CHECKSUM)
                {
                    int offset = (l->total_size + l->aligner) - q->ip_offset;
                    c = libnet_do_checksum(l, *packet + offset,
                            libnet_pblock_p2p(q->type), q->h_len);
                    if (c == -1)
                    {
                        /* err msg set in libnet_do_checksum() */
                        goto err;
                    }
                }
                q = p;
            }
        }
        else
        {
            q = p;
        }
    }
    *size = l->aligner + l->total_size;

    /*
     *  Set the packet pointer to the true beginning of the packet and set
     *  the size for transmission.
     */
    if ((l->injection_type == LIBNET_LINK ||
        l->injection_type == LIBNET_LINK_ADV) && l->aligner)
    {
        *packet += l->aligner;
        *size -= l->aligner;
    }
    return (1);

err:
    free(*packet);
    return (-1);
}

void
libnet_pblock_delete(libnet_t *l, libnet_pblock_t *p)
{
    if (p)
    {
        l->total_size -= p->b_len;
        l->n_pblocks--;
        if (p->prev) 
        {
            p->prev->next = p->next;
        }
        else
        {
            l->protocol_blocks = p->next;
        }

        if (p->next)
        {
            p->next->prev = p->prev;
        }
        else
        {
            l->pblock_end = p->prev;
        }

        if (p->buf)
        {
          free(p->buf);
        }

        free(p);
        p = NULL;
    }
}

int
libnet_pblock_p2p(u_int8_t type)
{
    /* for checksum; return the protocol number given a pblock type*/
    switch (type)
    {
        case LIBNET_PBLOCK_CDP_H:
            return (LIBNET_PROTO_CDP);
        case LIBNET_PBLOCK_ICMPV4_H:
        case LIBNET_PBLOCK_ICMPV4_ECHO_H:
        case LIBNET_PBLOCK_ICMPV4_MASK_H:
        case LIBNET_PBLOCK_ICMPV4_UNREACH_H:
        case LIBNET_PBLOCK_ICMPV4_TIMXCEED_H:
        case LIBNET_PBLOCK_ICMPV4_REDIRECT_H:
        case LIBNET_PBLOCK_ICMPV4_TS_H:
            return (IPPROTO_ICMP);
        case LIBNET_PBLOCK_IGMP_H:
            return (IPPROTO_IGMP);
        case LIBNET_PBLOCK_IPV4_H:
            return (IPPROTO_IP);
        case LIBNET_ISL_H:
            return (LIBNET_PROTO_ISL);
        case LIBNET_PBLOCK_OSPF_H:
            return (IPPROTO_OSPF);
        case LIBNET_PBLOCK_LS_RTR_H:
            return (IPPROTO_OSPF_LSA);
        case LIBNET_PBLOCK_TCP_H:
            return (IPPROTO_TCP);
        case LIBNET_PBLOCK_UDP_H:
            return (IPPROTO_UDP);
        case LIBNET_PBLOCK_VRRP_H:
            return (IPPROTO_VRRP);
        case LIBNET_PBLOCK_GRE_H:
            return (IPPROTO_GRE);
        default:
            return (-1);
    }
}

void
libnet_pblock_record_ip_offset(libnet_t *l, u_int32_t offset)
{
    libnet_pblock_t *p = l->pblock_end;

    do
    {
        p->ip_offset = offset;
        p = p->prev;
    } while (p && p->type != LIBNET_PBLOCK_IPV4_H);
}


/* EOF */
