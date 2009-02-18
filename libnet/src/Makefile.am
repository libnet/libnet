# $Id: Makefile.am,v 1.5 2004/03/11 18:50:20 mike Exp $
#
# Libnet automake information file
# Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
# All rights reserved.
#
# Process this file with automake to produce a Makefile.in script.

include $(top_srcdir)/Makefile.am.common

lib_LIBRARIES = libnet.a

libnet_a_SOURCES = libnet_asn1.c \
			libnet_build_802.1q.c \
			libnet_build_802.1x.c \
			libnet_build_802.2.c \
			libnet_build_802.3.c \
			libnet_build_arp.c \
			libnet_build_bgp.c \
			libnet_build_cdp.c \
			libnet_build_data.c \
			libnet_build_dhcp.c \
			libnet_build_dns.c \
			libnet_build_ethernet.c \
			libnet_build_fddi.c \
			libnet_build_gre.c \
			libnet_build_icmp.c \
			libnet_build_igmp.c \
			libnet_build_ip.c \
			libnet_build_ipsec.c \
			libnet_build_isl.c \
			libnet_build_mpls.c \
			libnet_build_ntp.c \
			libnet_build_ospf.c \
			libnet_build_rip.c \
			libnet_build_rpc.c \
			libnet_build_sebek.c \
			libnet_build_snmp.c \
			libnet_build_stp.c \
			libnet_build_tcp.c \
			libnet_build_token_ring.c \
			libnet_build_udp.c \
			libnet_build_vrrp.c \
			libnet_advanced.c \
			libnet_checksum.c \
			libnet_cq.c \
			libnet_crc.c \
			libnet_error.c \
			libnet_if_addr.c \
			libnet_init.c \
			libnet_internal.c \
			libnet_pblock.c \
			libnet_port_list.c \
			libnet_prand.c \
			libnet_raw.c \
			libnet_resolve.c \
			libnet_version.c \
			libnet_write.c

EXTRA_libnet_a_SOURCES = libnet_link_bpf.c \
			libnet_link_dlpi.c \
			libnet_link_linux.c \
			libnet_link_nit.c \
 			libnet_link_none.c \
			libnet_link_pf.c \
			libnet_link_snit.c \
			libnet_link_snoop.c \
			libnet_link_win32.c

libnet_a_LIBADD = @LIBOBJS@

