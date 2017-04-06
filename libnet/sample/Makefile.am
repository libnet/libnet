#
# Libnet automake information file
# Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
# All rights reserved.
#
# Process this file with automake to produce a Makefile.in script.

samples = arp \
          bgp4_hdr \
          bgp4_open \
          bgp4_update \
          bgp4_notification \
          cdp \
          dhcp_discover \
          dns \
          dot1x \
          fddi_tcp1 \
          fddi_tcp2 \
          get_addr \
          gre \
          hsrp \
          icmp_echo_cq \
          icmp_redirect \
          icmp_timeexceed \
          icmp_timestamp \
          icmp6_echoreq \
          icmp_unreach \
          icmp6_unreach \
          ieee \
          ip_link \
          ip_raw \
          isl \
          mpls \
          ntp \
          ospf_hello \
          ospf_lsa \
          ping_of_death \
          rpc_tcp \
          rpc_udp \
          synflood \
          synflood6 \
          sebek \
          smurf \
          stp \
          synflood6_frag \
          tcp1 \
          tcp2 \
          tftp \
          udp1 \
          udp2 \
          test_ipv4 \
          test_ipv6_icmpv4 \
          test_ipv4_options \
          tring_tcp1 \
          tring_tcp2

noinst_PROGRAMS = $(samples)

arp_SOURCES               = arp.c
bgp4_hdr_SOURCES          = bgp4_hdr.c
bgp4_open_SOURCES         = bgp4_open.c
bgp4_update_SOURCES       = bgp4_update.c
bgp4_notification_SOURCES = bgp4_notification.c
cdp_SOURCES               = cdp.c
dot1x_SOURCES             = dot1x.c
dhcp_discover_SOURCES     = dhcp_discover.c
dns_SOURCES               = dns.c
fddi_tcp1_SOURCES         = fddi_tcp1.c
fddi_tcp2_SOURCES         = fddi_tcp2.c
get_addr_SOURCES          = get_addr.c
gre_SOURCES               = gre.c
hsrp_SOURCES              = hsrp.c
icmp_echo_cq_SOURCES      = icmp_echo_cq.c
icmp_redirect_SOURCES     = icmp_redirect.c
icmp_timestamp_SOURCES    = icmp_timestamp.c
icmp_timeexceed_SOURCES   = icmp_timeexceed.c
icmp_unreach_SOURCES      = icmp_unreach.c
icmp6_echoreq_SOURCES     = icmp6_echoreq.c
icmp6_unreach_SOURCES     = icmp6_unreach.c
ieee_SOURCES              = ieee.c
ip_raw_SOURCES            = ip_raw.c
ip_link_SOURCES           = ip_link.c
isl_SOURCES               = isl.c
mpls_SOURCES              = mpls.c
ntp_SOURCES               = ntp.c
ospf_hello_SOURCES        = ospf_hello.c
ospf_lsa_SOURCES          = ospf_lsa.c
ping_of_death_SOURCES     = ping_of_death.c
rpc_tcp_SOURCES           = rpc_tcp.c
rpc_udp_SOURCES           = rpc_udp.c
sebek_SOURCES             = sebek.c
smurf_SOURCES             = smurf.c
stp_SOURCES               = stp.c
synflood_SOURCES          = synflood.c
synflood6_SOURCES         = synflood6.c
synflood6_frag_SOURCES    = synflood6_frag.c
tcp1_SOURCES              = tcp1.c
tcp2_SOURCES              = tcp2.c
test_ipv4_SOURCES         = test_ipv4.c
test_ipv4_options_SOURCES = test_ipv4_options.c
test_ipv6_icmpv4_SOURCES  = test_ipv6_icmpv4.c
tftp_SOURCES              = tftp.c
tring_tcp1_SOURCES        = tring_tcp1.c
tring_tcp2_SOURCES        = tring_tcp2.c
udp1_SOURCES              = udp1.c
udp2_SOURCES              = udp2.c

LDADD      = $(top_builddir)/src/libnet.la

EXTRA_DIST = libnet_test.h \
             arp-new.c \
             win32/getopt.c \
             win32/arp/arp.vcproj \
             win32/cdp/cdp.vcproj \
             win32/dhcp_discover/dhcp_discover.vcproj \
             win32/dns/dns.vcproj \
             win32/get_addr/get_addr.vcproj \
             win32/icmp_echo_cq/icmp_echo_cq.vcproj \
             win32/tcp1/tcp1.vcproj \
             win32/udp1/dns.vcproj \
             win32/udp1/udp1.vcproj
             