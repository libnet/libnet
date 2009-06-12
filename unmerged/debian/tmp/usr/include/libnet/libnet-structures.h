/*
 *  $Id: libnet-structures.h,v 1.19 2004/11/09 07:05:07 mike Exp $
 *
 *  libnet-structures.h - Network routine library structures header file
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

#ifndef __LIBNET_STRUCTURES_H
#define __LIBNET_STRUCTURES_H

#if ((__WIN32__) && !(__CYGWIN__))
#include "Packet32.h"
#endif

/* port list chain structure */
typedef struct libnet_port_list_chain libnet_plist_t;
struct libnet_port_list_chain
{
    u_int16_t node;                     /* node number */
    u_int16_t bport;                    /* beggining port */
    u_int16_t eport;                    /* terminating port */
    u_int8_t  id;                       /* global array offset */
    libnet_plist_t *next;               /* next node in the list */
};


/* libnet statistics structure */
struct libnet_stats
{
#if (!defined(__WIN32__) || (__CYGWIN__))
    u_int64_t packets_sent;             /* packets sent */
    u_int64_t packet_errors;            /* packets errors */
    u_int64_t bytes_written;            /* bytes written */
#else
    __int64 packets_sent;               /* packets sent */
    __int64 packet_errors;              /* packets errors */
    __int64 bytes_written;              /* bytes written */
#endif
};


/*
 *  Libnet ptags are how we identify specific protocol blocks inside the
 *  list.
 */
typedef int32_t libnet_ptag_t;
#define LIBNET_PTAG_INITIALIZER         0


/*
 *  Libnet generic protocol block memory object.  Sort of a poor man's mbuf.
 */
struct libnet_protocol_block
{
    u_int8_t *buf;                      /* protocol buffer */
    u_int32_t b_len;                    /* length of buf */
    u_int16_t h_len;                    /* header length (for checksumming) */
       /* Unused for IPV4_H block types.
        * For protocols that sit on top of IP, it should be the the amount of
        * buf that is the header, and will be included in the checksum.
        */
    u_int32_t ip_offset;                /* offset from end of pkt to beginning of IP header for csums */
       /* Unused for IPV4_H block types.
        * For protocols that sit on top of IP (UDP, ICMP, ...), they often
        * include some information from the IP header (in the form of a "pseudo
        * header") in their own checksum calculation. To build that
        * pseudo-header, thet need to find the real header.
        */
    u_int32_t copied;                   /* bytes copied - the amount of data copied into buf */
       /* Used and updated by libnet_pblock_append(). */
    u_int8_t type;                      /* type of pblock */
/* this needs to be updated every time a new packet builder is added */
#define LIBNET_PBLOCK_ARP_H             0x01    /* ARP header */
#define LIBNET_PBLOCK_DHCPV4_H          0x02    /* DHCP v4 header */
#define LIBNET_PBLOCK_DNSV4_H           0x03    /* DNS v4 header */
#define LIBNET_PBLOCK_ETH_H             0x04    /* Ethernet header */
#define LIBNET_PBLOCK_ICMPV4_H          0x05    /* ICMP v4 base header */
#define LIBNET_PBLOCK_ICMPV4_ECHO_H     0x06    /* ICMP v4 echo header */
#define LIBNET_PBLOCK_ICMPV4_MASK_H     0x07    /* ICMP v4 mask header */
#define LIBNET_PBLOCK_ICMPV4_UNREACH_H  0x08    /* ICMP v4 unreach header */
#define LIBNET_PBLOCK_ICMPV4_TIMXCEED_H 0x09    /* ICMP v4 exceed header */
#define LIBNET_PBLOCK_ICMPV4_REDIRECT_H 0x0a    /* ICMP v4 redirect header */
#define LIBNET_PBLOCK_ICMPV4_TS_H       0x0b    /* ICMP v4 timestamp header */
#define LIBNET_PBLOCK_IGMP_H            0x0c    /* IGMP header */
#define LIBNET_PBLOCK_IPV4_H            0x0d    /* IP v4 header */
#define LIBNET_PBLOCK_IPO_H             0x0e    /* IP v4 options */
#define LIBNET_PBLOCK_IPDATA            0x0f    /* IP data */
#define LIBNET_PBLOCK_OSPF_H            0x10    /* OSPF base header */
#define LIBNET_PBLOCK_OSPF_HELLO_H      0x11    /* OSPF hello header */
#define LIBNET_PBLOCK_OSPF_DBD_H        0x12    /* OSPF dbd header */
#define LIBNET_PBLOCK_OSPF_LSR_H        0x13    /* OSPF lsr header */
#define LIBNET_PBLOCK_OSPF_LSU_H        0x14    /* OSPF lsu header */
#define LIBNET_PBLOCK_OSPF_LSA_H        0x15    /* OSPF lsa header */
#define LIBNET_PBLOCK_OSPF_AUTH_H       0x16    /* OSPF auth header */
#define LIBNET_PBLOCK_OSPF_CKSUM        0x17    /* OSPF checksum header */
#define LIBNET_PBLOCK_LS_RTR_H          0x18    /* linkstate rtr header */
#define LIBNET_PBLOCK_LS_NET_H          0x19    /* linkstate net header */
#define LIBNET_PBLOCK_LS_SUM_H          0x1a    /* linkstate as sum header */
#define LIBNET_PBLOCK_LS_AS_EXT_H       0x1b    /* linkstate as ext header */
#define LIBNET_PBLOCK_NTP_H             0x1c    /* NTP header */
#define LIBNET_PBLOCK_RIP_H             0x1d    /* RIP header */
#define LIBNET_PBLOCK_TCP_H             0x1e    /* TCP header */
#define LIBNET_PBLOCK_TCPO_H            0x1f    /* TCP options */
#define LIBNET_PBLOCK_TCPDATA           0x20    /* TCP data */
#define LIBNET_PBLOCK_UDP_H             0x21    /* UDP header */
#define LIBNET_PBLOCK_VRRP_H            0x22    /* VRRP header */
#define LIBNET_PBLOCK_DATA_H            0x23    /* generic data */
#define LIBNET_PBLOCK_CDP_H             0x24    /* CDP header */
#define LIBNET_PBLOCK_IPSEC_ESP_HDR_H   0x25    /* IPSEC ESP header */
#define LIBNET_PBLOCK_IPSEC_ESP_FTR_H   0x26    /* IPSEC ESP footer */
#define LIBNET_PBLOCK_IPSEC_AH_H        0x27    /* IPSEC AH header */
#define LIBNET_PBLOCK_802_1Q_H          0x28    /* 802.1q header */
#define LIBNET_PBLOCK_802_2_H           0x29    /* 802.2 header */
#define LIBNET_PBLOCK_802_2SNAP_H       0x2a    /* 802.2 SNAP header */
#define LIBNET_PBLOCK_802_3_H           0x2b    /* 802.3 header */
#define LIBNET_PBLOCK_STP_CONF_H        0x2c    /* STP configuration header */
#define LIBNET_PBLOCK_STP_TCN_H         0x2d    /* STP TCN header */
#define LIBNET_PBLOCK_ISL_H             0x2e    /* ISL header */
#define LIBNET_PBLOCK_IPV6_H            0x2f    /* IP v6 header */
#define LIBNET_PBLOCK_802_1X_H          0x30    /* 802.1x header */
#define LIBNET_PBLOCK_RPC_CALL_H        0x31    /* RPC Call header */
#define LIBNET_PBLOCK_MPLS_H            0x32    /* MPLS header */
#define LIBNET_PBLOCK_FDDI_H            0x33    /* FDDI header */
#define LIBNET_PBLOCK_TOKEN_RING_H      0x34    /* TOKEN RING header */
#define LIBNET_PBLOCK_BGP4_HEADER_H     0x35    /* BGP4 header */
#define LIBNET_PBLOCK_BGP4_OPEN_H       0x36    /* BGP4 open header */
#define LIBNET_PBLOCK_BGP4_UPDATE_H     0x37    /* BGP4 update header */
#define LIBNET_PBLOCK_BGP4_NOTIFICATION_H 0x38  /* BGP4 notification header */
#define LIBNET_PBLOCK_GRE_H             0x39    /* GRE header */
#define LIBNET_PBLOCK_GRE_SRE_H         0x3a    /* GRE SRE header */
#define LIBNET_PBLOCK_IPV6_FRAG_H       0x3b    /* IPv6 frag header */
#define LIBNET_PBLOCK_IPV6_ROUTING_H    0x3c    /* IPv6 routing header */
#define LIBNET_PBLOCK_IPV6_DESTOPTS_H   0x3d    /* IPv6 dest opts header */
#define LIBNET_PBLOCK_IPV6_HBHOPTS_H    0x3e    /* IPv6 hop/hop opts header */
#define LIBNET_PBLOCK_SEBEK_H           0x3f    /* Sebek header */
#define LIBNET_PBLOCK_HSRP_H            0x40    /* HSRP header */
    u_int8_t flags;                             /* control flags */
#define LIBNET_PBLOCK_DO_CHECKSUM       0x01    /* needs a checksum */
    libnet_ptag_t ptag;                 /* protocol block tag */
    struct libnet_protocol_block *next; /* next pblock */
    struct libnet_protocol_block *prev; /* prev pblock */
};
typedef struct libnet_protocol_block libnet_pblock_t;


/*
 *  Libnet context
 *  Opaque structure.  Nothing in here should ever been touched first hand by
 *  the applications programmer.
 */
struct libnet_context
{
#if ((__WIN32__) && !(__CYGWIN__)) 
    SOCKET fd;
    LPADAPTER  lpAdapter;
#else
    int fd;                             /* file descriptor of packet device */
#endif
    int injection_type;                 /* raw (ipv4 or ipv6) or link */
#define LIBNET_LINK     0x00            /* link-layer interface */
#define LIBNET_RAW4     0x01            /* raw socket interface (ipv4) */
#define LIBNET_RAW6     0x02            /* raw socket interface (ipv6) */
/* the following should actually set a flag in the flags variable above */
#define LIBNET_LINK_ADV 0x08            /* advanced mode link-layer */
#define LIBNET_RAW4_ADV 0x09            /* advanced mode raw socket (ipv4) */
#define LIBNET_RAW6_ADV 0x0a            /* advanced mode raw socket (ipv6) */
#define LIBNET_ADV_MASK 0x08            /* mask to determine adv mode */

    libnet_pblock_t *protocol_blocks;   /* protocol headers / data */
    libnet_pblock_t *pblock_end;        /* last node in list */
    u_int32_t n_pblocks;                /* number of pblocks */

    int link_type;                      /* link-layer type */
    int link_offset;                    /* link-layer header size */
    int aligner;                        /* used to align packets */
    char *device;                       /* device name */

    struct libnet_stats stats;          /* statistics */
    libnet_ptag_t ptag_state;           /* state holder for pblock tag */
    char label[LIBNET_LABEL_SIZE];      /* textual label for cq interface */

    char err_buf[LIBNET_ERRBUF_SIZE];   /* error buffer */
    u_int32_t total_size;               /* total size */
};
typedef struct libnet_context libnet_t;

/*
 *  Libnet context queue structure
 *  Opaque structure.  Nothing in here should ever been touched first hand by
 *  the applications programmer.
 */
typedef struct _libnet_context_queue libnet_cq_t;
struct _libnet_context_queue
{
    libnet_t *context;                  /* pointer to libnet context */
    libnet_cq_t *next;                  /* next node in the list */
    libnet_cq_t *prev;                  /* previous node in the list */
};

struct _libnet_context_queue_descriptor
{
    u_int32_t node;                     /* number of nodes in the list */
    u_int32_t cq_lock;                  /* lock status */
    libnet_cq_t *current;               /* current context */
};
typedef struct _libnet_context_queue_descriptor libnet_cqd_t;

#endif  /* __LIBNET_STRUCTURES_H */

/* EOF */
