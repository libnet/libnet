/*
 *  $Id: libnet_checksum.c,v 1.14 2004/11/09 07:05:07 mike Exp $
 *
 *  libnet
 *  libnet_checksum.c - checksum routines
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

/* FIXME - unit test these - 0 is debian's version, else is -RC1's */
int
libnet_in_cksum(uint16_t *addr, int len)
{
    int sum;
#if 0
    uint16_t last_byte;

    sum = 0;
    last_byte = 0;
#else
    union
    {
        uint16_t s;
        uint8_t b[2];
    }pad;

    sum = 0;
#endif

    while (len > 1)
    {
        sum += *addr++;
        len -= 2;
    }
#if 0
    if (len == 1)
    {
        *(uint8_t *)&last_byte = *(uint8_t *)addr;
        sum += last_byte;
#else
    if (len == 1)
    {
        pad.b[0] = *(uint8_t *)addr;
        pad.b[1] = 0;
        sum += pad.s;
#endif
    }

    return (sum);
}

int
libnet_toggle_checksum(libnet_t *l, libnet_ptag_t ptag, int mode)
{
    libnet_pblock_t *p;

    p = libnet_pblock_find(l, ptag);
    if (p == NULL)
    {
        /* err msg set in libnet_pblock_find() */
        return (-1);
    }
    if (mode == LIBNET_ON)
    {
        if ((p->flags) & LIBNET_PBLOCK_DO_CHECKSUM)
        {
            return (1);
        }
        else
        {
            (p->flags) |= LIBNET_PBLOCK_DO_CHECKSUM;
            return (1);
        }
    }
    else
    {
        if ((p->flags) & LIBNET_PBLOCK_DO_CHECKSUM)
        {
            (p->flags) &= ~LIBNET_PBLOCK_DO_CHECKSUM;
            return (1);
        }
        else
        {
            return (1);
        }
    }
}

/* len is the pblock->h_len */
int
libnet_do_checksum(libnet_t *l, uint8_t *buf, int protocol, int len)
{
    /* will need to update this for ipv6 at some point */
    struct libnet_ipv4_hdr *iph_p;
    struct libnet_ipv6_hdr *ip6h_p;
    int is_ipv6;
    int ip_hl;
    int sum;

    is_ipv6 = 0;    /* default to not using IPv6 */
    sum     = 0;
    iph_p   = NULL;
    ip6h_p  = NULL;

    if (len == 0)
    {
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
            "%s(): header length can't be zero\n", __func__);
        return (-1);
    }

    /*
     *  Figure out which IP version we're dealing with.  We'll assume v4
     *  and overlay a header structure to yank out the version.
     */
    iph_p = (struct libnet_ipv4_hdr *)buf;
    if (iph_p && iph_p->ip_v == 6)
    {
        ip6h_p = (struct libnet_ipv6_hdr *)buf;
        is_ipv6 = 1;
        ip_hl   = 40;
    }
    else
    {
        is_ipv6 = 0;
        ip_hl = iph_p->ip_hl << 2;
    }

    /*
     *  Dug Song came up with this very cool checksuming implementation
     *  eliminating the need for explicit psuedoheader use.  Check it out.
     */
    switch (protocol)
    {
        /*
         *  Style note: normally I don't advocate declaring variables inside
         *  blocks of control, but it makes good sense here. -- MDS
         */
        case IPPROTO_TCP:
        {
            struct libnet_tcp_hdr *tcph_p =
                (struct libnet_tcp_hdr *)(buf + ip_hl);

#if (STUPID_SOLARIS_CHECKSUM_BUG)
            tcph_p->th_sum = tcph_p->th_off << 2;
            return (1);
#endif /* STUPID_SOLARIS_CHECKSUM_BUG */
#if (HAVE_HPUX11)   
            if (l->injection_type != LIBNET_LINK)
            {
                /*
                 *  Similiar to the Solaris Checksum bug - but need to add
                 *  the size of the TCP payload (only for raw sockets).
                 */
                tcph_p->th_sum = (tcph_p->th_off << 2) +
                        (len - (tcph_p->th_off << 2));
                return (1); 
            }
#endif
            tcph_p->th_sum = 0;
            if (is_ipv6)
            {
                sum = libnet_in_cksum((uint16_t *)&ip6h_p->ip_src, 32);
            }
            else
            {
                sum = libnet_in_cksum((uint16_t *)&iph_p->ip_src, 8);
            }
            sum += ntohs(IPPROTO_TCP + len);
            sum += libnet_in_cksum((uint16_t *)tcph_p, len);
            tcph_p->th_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_UDP:
        {
            struct libnet_udp_hdr *udph_p =
                (struct libnet_udp_hdr *)(buf + ip_hl);
            udph_p->uh_sum = 0;
            if (is_ipv6)
            {
                sum = libnet_in_cksum((uint16_t *)&ip6h_p->ip_src, 32);
            }
            else
            {
                sum = libnet_in_cksum((uint16_t *)&iph_p->ip_src, 8);
            }
            sum += ntohs(IPPROTO_UDP + len);
            sum += libnet_in_cksum((uint16_t *)udph_p, len);
            udph_p->uh_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_ICMP:
        {
            struct libnet_icmpv4_hdr *icmph_p =
                (struct libnet_icmpv4_hdr *)(buf + ip_hl);

            icmph_p->icmp_sum = 0;
            if (is_ipv6)
            {
                sum = libnet_in_cksum((uint16_t *)&ip6h_p->ip_src, 32);
                sum += ntohs(IPPROTO_ICMP6 + len);
            }
            sum += libnet_in_cksum((uint16_t *)icmph_p, len);
            icmph_p->icmp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_IGMP:
        {
            struct libnet_igmp_hdr *igmph_p =
                (struct libnet_igmp_hdr *)(buf + ip_hl);

            igmph_p->igmp_sum = 0;
            sum = libnet_in_cksum((uint16_t *)igmph_p, len);
            igmph_p->igmp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
	case IPPROTO_GRE:
	{
            /* checksum is always at the same place in GRE header
             * in the multiple RFC version of the protocol ... ouf !!!
             */
	    struct libnet_gre_hdr *greh_p = 
		(struct libnet_gre_hdr *)(buf + ip_hl);
	    uint16_t fv = ntohs(greh_p->flags_ver);
	    if (!(fv & (GRE_CSUM|GRE_ROUTING | GRE_VERSION_0)) ||
                !(fv & (GRE_CSUM|GRE_VERSION_1)))
	    {
		snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "%s(): can't compute GRE checksum (wrong flags_ver bits: 0x%x )\n",  __func__, fv);
		return (-1);
	    }
	    sum = libnet_in_cksum((uint16_t *)greh_p, len);
	    greh_p->gre_sum = LIBNET_CKSUM_CARRY(sum);
	    break;
	}
        case IPPROTO_OSPF:
        {
            struct libnet_ospf_hdr *oh_p =
                (struct libnet_ospf_hdr *)(buf + ip_hl);

            oh_p->ospf_sum = 0;
            sum += libnet_in_cksum((uint16_t *)oh_p, len);
            oh_p->ospf_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_OSPF_LSA:
        {
            struct libnet_ospf_hdr *oh_p =
                (struct libnet_ospf_hdr *)(buf + ip_hl);
            struct libnet_lsa_hdr *lsa_p =
                (struct libnet_lsa_hdr *)(buf + 
                ip_hl + oh_p->ospf_len);

            lsa_p->lsa_sum = 0;
            sum += libnet_in_cksum((uint16_t *)lsa_p, len);
            lsa_p->lsa_sum = LIBNET_CKSUM_CARRY(sum);
            break;
#if 0
            /*
             *  Reworked fletcher checksum taken from RFC 1008.
             */
            int c0, c1;
            struct libnet_lsa_hdr *lsa_p = (struct libnet_lsa_hdr *)buf;
            uint8_t *p, *p1, *p2, *p3;

            c0 = 0;
            c1 = 0;

            lsa_p->lsa_cksum = 0;

            p = buf;
            p1 = buf;
            p3 = buf + len;             /* beginning and end of buf */

            while (p1 < p3)
            {
                p2 = p1 + LIBNET_MODX;
                if (p2 > p3)
                {
                    p2 = p3;
                }
  
                for (p = p1; p < p2; p++)
                {
                    c0 += (*p);
                    c1 += c0;
                }

                c0 %= 255;
                c1 %= 255;      /* modular 255 */
 
                p1 = p2;
            }

#if AWR_PLEASE_REWORK_THIS
            lsa_p->lsa_cksum[0] = (((len - 17) * c0 - c1) % 255);
            if (lsa_p->lsa_cksum[0] <= 0)
            {
                lsa_p->lsa_cksum[0] += 255;
            }

            lsa_p->lsa_cksum[1] = (510 - c0 - lsa_p->lsa_cksum[0]);
            if (lsa_p->lsa_cksum[1] > 255)
            {
                lsa_p->lsa_cksum[1] -= 255;
            }
#endif
            break;
#endif
        }
        case IPPROTO_IP:
        {
            iph_p->ip_sum = 0;
            sum = libnet_in_cksum((uint16_t *)iph_p, ip_hl);
            iph_p->ip_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case IPPROTO_VRRP:
        {
            struct libnet_vrrp_hdr *vrrph_p =
                (struct libnet_vrrp_hdr *)(buf + ip_hl);

            vrrph_p->vrrp_sum = 0;
            sum = libnet_in_cksum((uint16_t *)vrrph_p, len);
            vrrph_p->vrrp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case LIBNET_PROTO_CDP:
        {   /* XXX - Broken: how can we easily get the entire packet size? */
            struct libnet_cdp_hdr *cdph_p =
                (struct libnet_cdp_hdr *)buf;

            cdph_p->cdp_sum = 0;
            sum = libnet_in_cksum((uint16_t *)cdph_p, len);
            cdph_p->cdp_sum = LIBNET_CKSUM_CARRY(sum);
            break;
        }
        case LIBNET_PROTO_ISL:
        {
#if 0
            struct libnet_isl_hdr *islh_p =
                (struct libnet_isl_hdr *)buf;
#endif
            /*
             *  Need to compute 4 byte CRC for the ethernet frame and for
             *  the ISL frame itself.  Use the libnet_crc function.
             */
        }
        default:
        {
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                "%s(): unsuported protocol %d\n", __func__, protocol);
            return (-1);
        }
    }
    return (1);
}


uint16_t
libnet_ip_check(uint16_t *addr, int len)
{
    int sum;

    sum = libnet_in_cksum(addr, len);
    return (LIBNET_CKSUM_CARRY(sum));
}

/* EOF */
