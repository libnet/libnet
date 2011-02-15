/*
Copyright (C) 2011 Wurldtech Security Technologies All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED.IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.
*/

/* Code common to the lua netfilter bindings. */

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <linux/netfilter.h>
#include <linux/types.h>

static const char* nfemsg(int eno)
{
    switch(errno) {
        case EAGAIN: return "timeout";
    }
    return strerror(eno);
}
static int push_error(lua_State* L)
{
    lua_pushnil(L);
    lua_pushstring(L, nfemsg(errno));
    lua_pushinteger(L, errno);

    return 3;
}

static int nfsetblocking(lua_State* L, int fd)
{
    int set = lua_toboolean(L, 2);
    long flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0) {
        return push_error(L);
    }
    /* to SET blocking, we CLEAR O_NONBLOCK */
    if(set) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;

    }
    if(fcntl(fd, F_SETFL, flags) < 0) {
        return push_error(L);
    }

    lua_settop(L, 1);

    return 1;
}

#ifdef WANT_NF_LUA_PF
/*-
-- DOCUMENTATION
  unspec    -- PF_UNSPEC, Unspecified.
  local     -- PF_LOCAL, Local to host (pipes and file-domain).
  unix      -- PF_UNIX, POSIX name for PF_LOCAL.
  file      -- PF_FILE, Another non-standard name for PF_LOCAL.
  inet      -- PF_INET, IP protocol family.
  ax25      -- PF_AX25, Amateur Radio AX.25.
  ipx       -- PF_IPX, Novell Internet Protocol.
  appletalk -- PF_APPLETALK, Appletalk DDP.
  netrom    -- PF_NETROM, Amateur radio NetROM.
  bridge    -- PF_BRIDGE, Multiprotocol bridge.
  atmpvc    -- PF_ATMPVC, ATM PVCs.
  x25       -- PF_X25, Reserved for X.25 project.
  inet6     -- PF_INET6, IP version 6.
  rose      -- PF_ROSE, Amateur Radio X.25 PLP.
  decnet    -- PF_DECnet, Reserved for DECnet project.
  netbeui   -- PF_NETBEUI, Reserved for 802.2LLC project.
  security  -- PF_SECURITY, Security callback pseudo AF.
  key       -- PF_KEY, PF_KEY key management API.
  netlink   -- PF_NETLINK
  route     -- PF_ROUTE, Alias to emulate 4.4BSD.
  packet    -- PF_PACKET, Packet family.
  ash       -- PF_ASH, Ash.
  econet    -- PF_ECONET, Acorn Econet.
  atmsvc    -- PF_ATMSVC, ATM SVCs.
  rds       -- PF_RDS, RDS sockets.
  sna       -- PF_SNA, Linux SNA Project
  irda      -- PF_IRDA, IRDA sockets.
  pppox     -- PF_PPPOX, PPPoX sockets.
  wanpipe   -- PF_WANPIPE, Wanpipe API sockets.
  llc       -- PF_LLC, Linux LLC.
  can       -- PF_CAN, Controller Area Network.
  tipc      -- PF_TIPC, TIPC sockets.
  bluetooth -- PF_BLUETOOTH, Bluetooth sockets.
  iucv      -- PF_IUCV, IUCV sockets.
  rxrpc     -- PF_RXRPC, RxRPC sockets.
  isdn      -- PF_ISDN, mISDN sockets.
  phonet    -- PF_PHONET, Phonet sockets.
  ieee802154-- PF_IEEE802154, IEEE 802.15.4 sockets.
*/
static const char* PF_opts[] = {
  "unspec",
  "local",
  "unix",
  "file",
  "inet",
  "ax25",
  "ipx",
  "appletalk",
  "netrom",
  "bridge",
  "atmpvc",
  "x25",
  "inet6",
  "rose",
  "decnet",
  "netbeui",
  "security",
  "key",
  "netlink",
  "route",
  "packet",
  "ash",
  "econet",
  "atmsvc",
  "rds",
  "sna",
  "irda",
  "pppox",
  "wanpipe",
  "llc",
  "can",
  "tipc",
  "bluetooth",
  "iucv",
  "rxrpc",
  "isdn",
  "phonet",
  "ieee802154",
  NULL
};

static int PF_vals[] = {
  PF_UNSPEC,
  PF_LOCAL,
  PF_UNIX,
  PF_FILE,
  PF_INET,
  PF_AX25,
  PF_IPX,
  PF_APPLETALK,
  PF_NETROM,
  PF_BRIDGE,
  PF_ATMPVC,
  PF_X25,
  PF_INET6,
  PF_ROSE,
  PF_DECnet,
  PF_NETBEUI,
  PF_SECURITY,
  PF_KEY,
  PF_NETLINK,
  PF_ROUTE,
  PF_PACKET,
  PF_ASH,
  PF_ECONET,
  PF_ATMSVC,
  PF_RDS,
  PF_SNA,
  PF_IRDA,
  PF_PPPOX,
  PF_WANPIPE,
  PF_LLC,
  PF_CAN,
  PF_TIPC,
  PF_BLUETOOTH,
  PF_IUCV,
  PF_RXRPC,
  PF_ISDN,
  PF_PHONET,
  PF_IEEE802154,
};

static int check_PF(lua_State* L, int argn)
{
  int opt = luaL_checkoption(L, argn, NULL /* default? */, PF_opts);
  int val = PF_vals[opt];
  return val;
}
#ifdef WANT_NF_LUA_PF_PUSH
static int PF_vals_size = 38;
static void push_PF(lua_State* L, int val)
{
    int i;
    for(i = 0; i < PF_vals_size; i++) {
        if(val == PF_vals[i]) {
            lua_pushstring(L, PF_opts[i]);
            return;
        }
    }
    lua_pushnumber(L, val);
    return;
}
#endif
#endif

#ifdef WANT_NF_LUA_IPPROTO
/*-
-- DOCUMENTATION
  ip        -- IPPROTO_IP, Dummy protocol for TCP.
  hopopts   -- IPPROTO_HOPOPTS, IPv6 Hop-by-Hop options.
  icmp      -- IPPROTO_ICMP, Internet Control Message Protocol.
  igmp      -- IPPROTO_IGMP, Internet Group Management Protocol.
  ipip      -- IPPROTO_IPIP, IPIP tunnels (older KA9Q tunnels use 94).
  tcp       -- IPPROTO_TCP, Transmission Control Protocol.
  egp       -- IPPROTO_EGP, Exterior Gateway Protocol.
  pup       -- IPPROTO_PUP, PUP protocol.
  udp       -- IPPROTO_UDP, User Datagram Protocol.
  idp       -- IPPROTO_IDP, XNS IDP protocol.
  tp        -- IPPROTO_TP, SO Transport Protocol Class 4.
  dccp      -- IPPROTO_DCCP, Datagram Congestion Control Protocol.
  ipv6      -- IPPROTO_IPV6, IPv6 header.
  routing   -- IPPROTO_ROUTING, IPv6 routing header.
  fragment  -- IPPROTO_FRAGMENT, IPv6 fragmentation header.
  rsvp      -- IPPROTO_RSVP, Reservation Protocol.
  gre       -- IPPROTO_GRE, General Routing Encapsulation.
  esp       -- IPPROTO_ESP, encapsulating security payload.
  ah        -- IPPROTO_AH, authentication header.
  icmpv6    -- IPPROTO_ICMPV6, ICMPv6.
  none      -- IPPROTO_NONE, IPv6 no next header.
  dstopts   -- IPPROTO_DSTOPTS, IPv6 destination options.
  mtp       -- IPPROTO_MTP, Multicast Transport Protocol.
  encap     -- IPPROTO_ENCAP, Encapsulation Header.
  pim       -- IPPROTO_PIM, Protocol Independent Multicast.
  comp      -- IPPROTO_COMP, Compression Header Protocol.
  sctp      -- IPPROTO_SCTP, Stream Control Transmission Protocol.
  udplite   -- IPPROTO_UDPLITE, UDP-Lite protocol.
  raw       -- IPPROTO_RAW, Raw IP packets.
*/
static const char* IPPROTO_opts[] = {
  "ip",
  "hopopts",
  "icmp",
  "igmp",
  "ipip",
  "tcp",
  "egp",
  "pup",
  "udp",
  "idp",
  "tp",
  "dccp",
  "ipv6",
  "routing",
  "fragment",
  "rsvp",
  "gre",
  "esp",
  "ah",
  "icmpv6",
  "none",
  "dstopts",
  "mtp",
  "encap",
  "pim",
  "comp",
  "sctp",
  "udplite",
  "raw",
  NULL
};

static int IPPROTO_vals[] = {
  IPPROTO_IP,
  IPPROTO_HOPOPTS,
  IPPROTO_ICMP,
  IPPROTO_IGMP,
  IPPROTO_IPIP,
  IPPROTO_TCP,
  IPPROTO_EGP,
  IPPROTO_PUP,
  IPPROTO_UDP,
  IPPROTO_IDP,
  IPPROTO_TP,
  IPPROTO_DCCP,
  IPPROTO_IPV6,
  IPPROTO_ROUTING,
  IPPROTO_FRAGMENT,
  IPPROTO_RSVP,
  IPPROTO_GRE,
  IPPROTO_ESP,
  IPPROTO_AH,
  IPPROTO_ICMPV6,
  IPPROTO_NONE,
  IPPROTO_DSTOPTS,
  IPPROTO_MTP,
  IPPROTO_ENCAP,
  IPPROTO_PIM,
  IPPROTO_COMP,
  IPPROTO_SCTP,
  IPPROTO_UDPLITE,
  IPPROTO_RAW,
};

static int IPPROTO_vals_size = 29;
static int check_IPPROTO(lua_State* L, int argn)
{
  int opt = luaL_checkoption(L, argn, NULL /* default? */, IPPROTO_opts);
  int val = IPPROTO_vals[opt];
  return val;
}

static void push_IPPROTO(lua_State* L, int val)
{
    int i;
    for(i = 0; i < IPPROTO_vals_size; i++) {
        if(val == IPPROTO_vals[i]) {
            lua_pushstring(L, IPPROTO_opts[i]);
            return;
        }
    }
    lua_pushnumber(L, val);
    return;
}
#endif

