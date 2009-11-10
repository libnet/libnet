/*
Copyright (c) 2009 Wurldtech Security Technologies All rights reserved.

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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* TODO - remove dependence on dnet */
#include <dnet.h>
#include <libnet.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#undef NET_DUMP

/*
Get field from arg table, errors if argt is not a table, returns
0 if field not found, otherwise pushes field value and returns
index.
*/
static int v_arg(lua_State* L, int argt, const char* field)
{
    luaL_checktype(L, argt, LUA_TTABLE);

    lua_getfield(L, argt, field);

    if(lua_isnil(L, -1)) {
        lua_pop(L, 1);
        return 0;
    }
    return lua_gettop(L);
}

static const char* v_arg_lstring(lua_State* L, int argt, const char* field, size_t* size, const char* def)
{
    if(!v_arg(L, argt, field))
    {
        if(def) {
            lua_pushstring(L, def);
            return lua_tolstring(L, -1, size);
        } else {
            const char* msg = lua_pushfstring(L, "%s is missing", field);
            luaL_argerror(L, argt, msg);
        }
    }

    if(!lua_tostring(L, -1)) {
        const char* msg = lua_pushfstring(L, "%s is not a string", field);
        luaL_argerror(L, argt, msg);
    }

    return lua_tolstring(L, -1, size);
}

static const char* v_arg_string(lua_State* L, int argt, const char* field)
{
    return v_arg_lstring(L, argt, field, NULL, NULL);
}

static int v_arg_integer_get_(lua_State* L, int argt, const char* field)
{
    if(lua_type(L, -1) != LUA_TNUMBER) {
        const char* msg = lua_pushfstring(L, "%s is not an integer", field);
        luaL_argerror(L, argt, msg);
    }

    return lua_tointeger(L, -1);
}

static int v_arg_integer(lua_State* L, int argt, const char* field)
{
    if(!v_arg(L, argt, field))
    {
        const char* msg = lua_pushfstring(L, "%s is missing", field);
        luaL_argerror(L, argt, msg);
    }

    return v_arg_integer_get_(L, argt, field);
}

static int v_arg_integer_opt(lua_State* L, int argt, const char* field, int def)
{
    if(!v_arg(L, argt, field))
    {
        lua_pushinteger(L, def);
        return lua_tointeger(L, -1);
    }

    return v_arg_integer_get_(L, argt, field);
}

static void v_obj_metatable(lua_State* L, const char* regid, const struct luaL_reg methods[])
{
    /* metatable = { ... methods ... } */
    luaL_newmetatable(L, regid);
    luaL_register(L, NULL, methods);
    /* metatable["__index"] = metatable */
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_pop(L, 1);
}




#define L_NET_REGID "wt.net"


static int net_error(lua_State* L, libnet_t* l)
{
    return luaL_error(L, "%s", libnet_geterror(l));
}

static int check_error(lua_State* L, libnet_t* l, int r)
{
    if(r < 0) {
        return net_error(L, l);
    }
    return r;
}

static uint32_t check_ip_pton(lua_State* L, const char* p, const char* name)
{
    uint32_t n = 0;
    if(ip_pton(p, &n) < 0) {
        return luaL_error(L, "ip_pton failed on %s '%s'", name, p);
    }
    return n;
}

static eth_addr_t check_eth_pton(lua_State* L, const char* p, const char* name)
{
    eth_addr_t n;
    if(eth_pton(p, &n) < 0) {
        luaL_error(L, "eth_pton failed on %s '%s'", name, p);
    }
    return n;
}

static int lnet_arg_ptag(lua_State* L, int targ)
{
    return v_arg_integer_opt(L, targ, "ptag", LIBNET_PTAG_INITIALIZER);
}

static libnet_t* checkudata(lua_State* L)
{
    libnet_t** ud = luaL_checkudata(L, 1, L_NET_REGID);

    luaL_argcheck(L, *ud, 1, "net has been destroyed");

    return *ud;
}

/*-
- net:destroy()

Manually destroy a net object, freeing it's resources (this will happen
on garbage collection if not done explicitly).
*/
static int lnet_destroy (lua_State *L)
{
    libnet_t** ud = luaL_checkudata(L, 1, L_NET_REGID);

    if(*ud)
        libnet_destroy(*ud);

    *ud = NULL;

    return 0;
}

/*-
- net:dump()

Write summary of protocol blocks to stdout.
*/
static const char* type_string(u_int8_t type)
{
    return libnet_diag_dump_pblock_type(type);
/*
    switch(type) {
        case LIBNET_PBLOCK_ETH_H:  return "eth";
        case LIBNET_PBLOCK_IPV4_H: return "ip4";
        case LIBNET_PBLOCK_IPO_H:  return "ipo";
        case LIBNET_PBLOCK_IPDATA: return "ipd";
    }
    return "?";
*/
}
static int lnet_dump(lua_State* L)
{
    libnet_t* ud = checkudata(L);
    libnet_pblock_t* p = ud->protocol_blocks;
    int strings = 0;

    while(p) {
        /* h_len is header length for checksumming? "chksum length"? */
        char str[1024];
        sprintf(str, "tag %d flags %d type %s/%#x buf %p b_len %2u h_len %2u ip_offset %2u, copied %u\n",
                p->ptag, p->flags, type_string(p->type), p->type,
                p->buf, p->b_len, p->h_len, p->ip_offset, p->copied);
        lua_pushstring(L, str);
        p = p->next;
        strings++;
    }
    lua_pushfstring(L, "link_offset %d aligner %d total_size %d nblocks %d\n",
            ud->link_offset, ud->aligner, ud->total_size, ud->n_pblocks);
    strings++;

    lua_concat(L, strings);

    return 1;
}

/*-
- net = net:clear()

Clear the current packet and all it's protocol blocks.

Return self.
*/
static int lnet_clear(lua_State* L)
{
    libnet_t* ud = checkudata(L);
    libnet_clear_packet(ud);
    /* TODO - these bugs are fixed in libnet head */
    ud->n_pblocks = 0;
    ud->ptag_state = 0;
    return 1;
}

static libnet_pblock_t* checkpblock(lua_State* L, libnet_t* ud, int narg)
{
    int ptag = luaL_checkint(L, narg);
    libnet_pblock_t* pblock = libnet_pblock_find(ud, ptag);
    luaL_argcheck(L, pblock, narg, "ptag cannot be found");
    return pblock;
}

static int pushtagornil(lua_State* L, libnet_pblock_t* pblock)
{
    if(pblock)
        lua_pushinteger(L, pblock->ptag);
    else
        lua_pushnil(L);
    return 1;
}

/*-
- net:tag_below(ptag)

tag below ptag, or bottom tag if ptag is nil
*/
static int lnet_tag_below(lua_State* L)
{
    libnet_t* ud = checkudata(L);
    libnet_pblock_t* pblock = NULL;
    
    if(lua_isnoneornil(L, 2)) {
        return pushtagornil(L, ud->pblock_end);
    }

    pblock = checkpblock(L, ud, 2);

    return pushtagornil(L, pblock->next);
}

/*-
- net:tag_above(ptag)

tag above ptag, or top tag if ptag is nil
*/
static int lnet_tag_above(lua_State* L)
{
    libnet_t* ud = checkudata(L);
    libnet_pblock_t* pblock = NULL;

    if(lua_isnoneornil(L, 2)) {
        return pushtagornil(L, ud->protocol_blocks);
    }

    pblock = checkpblock(L, ud, 2);

    return pushtagornil(L, pblock->prev);
}


/*- net:tag_type(ptag)

returns type of ptag, a string
*/

static int lnet_tag_type(lua_State* L)
{
    libnet_t* ud = checkudata(L);
    libnet_pblock_t* pblock = checkpblock(L, ud, 2);
    lua_pushstring(L, libnet_diag_dump_pblock_type(pblock->type));
    return 1;
}

/*-
- str = net:block([ptag])

Coalesce the protocol blocks into a single chunk, and return.

If a ptag is provided, just return data of that pblock (no checksums
will be calculated).
*/
static int lnet_block(lua_State* L)
{
    libnet_t* ud = checkudata(L);

    u_int32_t len;
    u_int8_t *packet = NULL;
    u_int8_t *block;

    int r = libnet_pblock_coalesce(ud, &packet, &len);

    check_error(L, ud, r);

    block = packet;

    if(!lua_isnoneornil(L, 2)) {
        libnet_pblock_t* end = checkpblock(L, ud, 2);
        libnet_pblock_t* p = ud->pblock_end;
        while(p != end) {
            block += p->b_len;
            p = p->prev;
        }
        assert(p == end);
        len = p->b_len;
    }

    lua_pushlstring(L, (char*) block, len);

    libnet_adv_free_packet(ud, packet);

    return 1;
}

/*-
- net:fd()

Get the fileno of the underlying file descriptor.
*/
static int lnet_getfd(lua_State* L)
{ 
    libnet_t* ud = checkudata(L);
    lua_pushinteger(L, libnet_getfd(ud));
    return 1;
}

/*-
- net:device()

Get the device name, maybe be nil.
*/
static int lnet_getdevice(lua_State* L)
{ 
    libnet_t* ud = checkudata(L);
    const char* device = libnet_getdevice(ud);
    if(device)
      lua_pushstring(L, device);
    else
      lua_pushnil(L);

    return 1;
}

/*-
- net:pbuf(ptag)
*/
static int lnet_pbuf(lua_State* L)
{
    libnet_t* ud = checkudata(L);
    int ptag = luaL_checkint(L, 2); /* checkpblock */
    const char* pbuf = (const char*)libnet_getpbuf(ud, ptag);
    size_t pbufsz = libnet_getpbuf_size(ud, ptag);

    if(!pbuf)
      return net_error(L, ud);

    lua_pushlstring(L, pbuf, pbufsz);

    return 1;
}

/*-
- net:write()

Write the packet (which must previously have been built up inside the context).
*/
static int lnet_write(lua_State *L)
{
    libnet_t* ud = checkudata(L);

#ifdef NET_DUMP
    lnet_dump(L);
#endif

    int r = libnet_write(ud);
    check_error(L, ud, r);
    lua_pushinteger(L, r);
    return 1;
}

static const uint8_t*
checklbuffer(lua_State* L, int argt, const char* field, uint32_t* size)
{
    size_t payloadsz = 0;
    const char* payload = v_arg_lstring(L, argt, field, &payloadsz, "");

    if(payloadsz == 0) {
        payload = NULL;
    }

    *size = payloadsz;

    return (const uint8_t*) payload;
}

static const uint8_t*
checkpayload(lua_State* L, int argt, uint32_t* size)
{
  return checklbuffer(L, argt, "payload", size);
}

/*-
- ptag = net:data{payload=STR, ptag=int}

Build generic data packet inside net context.

ptag is optional, defaults to creating a new protocol block
*/
static int lnet_data (lua_State *L)
{
    libnet_t* ud = checkudata(L);
    uint32_t payloadsz = 0;
    const uint8_t* payload = checkpayload(L, 2, &payloadsz);
    int ptag = lnet_arg_ptag(L, 2);

    ptag = libnet_build_data(payload, payloadsz, ud, ptag);
    check_error(L, ud, ptag);
    lua_pushinteger(L, ptag);
    return 1;
}

/*-
- ptag = net:udp{src=NUM, dst=NUM, len=NUM, payload=STR, ptag=int}

Build UDP packet inside net context.

ptag is optional, defaults to creating a new protocol block
*/
static int lnet_udp (lua_State *L)
{
    libnet_t* ud = checkudata(L);
    int src = v_arg_integer(L, 2, "src");
    int dst = v_arg_integer(L, 2, "dst");
    uint32_t payloadsz = 0;
    const uint8_t* payload = checkpayload(L, 2, &payloadsz);
    int len = v_arg_integer_opt(L, 2, "len", LIBNET_UDP_H + payloadsz);
    int cksum = 0;
    int ptag = lnet_arg_ptag(L, 2);

    ptag = libnet_build_udp(src, dst, len, cksum, payload, payloadsz, ud, ptag);
    check_error(L, ud, ptag);
    lua_pushinteger(L, ptag);
    return 1;
}

/*-
- ptag = n:ipv4{len=int, protocol=int, src=ipaddr, dst=ipaddr, payload=str, ptag=int, options=ip_options}

ptag is optional, defaults to creating a new protocol block
options is optional
*/
static int lnet_ipv4 (lua_State *L)
{
    libnet_t* ud = checkudata(L);
    int len = v_arg_integer(L, 2, "len"); /* FIXME - should be optional! */
    int tos = 0;
    int id = 0;
    int offset = 0;
    int ttl = 64;
    int protocol = v_arg_integer(L, 2, "protocol");
    int cksum = 0; /* 0 is a flag requesting libnet to fill in correct cksum */
    const char* src = v_arg_string(L, 2, "src");
    const char* dst = v_arg_string(L, 2, "dst");
    uint32_t payloadsz = 0;
    const uint8_t* payload = checkpayload(L, 2, &payloadsz);
    int ptag = lnet_arg_ptag(L, 2);
    int options_ptag = 0;
    uint32_t optionsz = 0;
    const uint8_t* options = checklbuffer(L, 2, "options", &optionsz);
    uint32_t src_n;
    uint32_t dst_n;

#ifdef NET_DUMP
    printf("net ipv4 src %s dst %s len %d payloadsz %lu ptag %d optionsz %lu\n", src, dst, len, payloadsz, ptag, optionsz);
#endif

    src_n = check_ip_pton(L, src, "src");
    dst_n = check_ip_pton(L, dst, "dst");

    if(ptag) {
        /* Modifying exist IPv4 packet, so find the preceeding options block (we
         * _always_ push an options block, perhaps empty, to make this easy).
         */
        libnet_pblock_t* p = libnet_pblock_find(ud, ptag);

        if(!p)
            return check_error(L, ud, -1);

        options_ptag = p->prev->ptag;
    }

#ifdef NET_DUMP
    printf("  options_ptag %d optionsz %lu\n", options_ptag, optionsz);
#endif

    options_ptag = libnet_build_ipv4_options(options, optionsz, ud, options_ptag);

    check_error(L, ud, options_ptag);

    ptag = libnet_build_ipv4(len, tos, id, offset, ttl, protocol, cksum, src_n,
            dst_n, payload, payloadsz, ud, ptag);
    check_error(L, ud, ptag);
    lua_pushinteger(L, ptag);
    return 1;
}

/*-
- ptag = n:eth{src=ethmac, dst=ethmac, type=int, payload=str, ptag=int}

type is optional, defaults to IP
ptag is optional, defaults to creating a new protocol block
*/
static int lnet_eth (lua_State *L)
{
    libnet_t* ud = checkudata(L);
    const char* src = v_arg_string(L, 2, "src");
    const char* dst = v_arg_string(L, 2, "dst");
    int type = v_arg_integer_opt(L, 2, "type", ETHERTYPE_IP);
    uint32_t payloadsz = 0;
    const uint8_t* payload = checkpayload(L, 2, &payloadsz);
    int ptag = lnet_arg_ptag(L, 2);

    if(payloadsz == 0) {
        payload = NULL;
    }

#ifdef NET_DUMP
    printf("net eth src %s dst %s type %d payloadsz %lu ptag %d\n", src, dst, type, payloadsz, ptag);
#endif

    {
      eth_addr_t src_n = check_eth_pton(L, src, "src");
      eth_addr_t dst_n = check_eth_pton(L, dst, "dst");
      ptag = libnet_build_ethernet(dst_n.data, src_n.data, type, payload, payloadsz, ud, ptag);
    }
    check_error(L, ud, ptag);
    lua_pushinteger(L, ptag);
    return 1;
}

static int lnet_link (lua_State *L)
{
    libnet_t* ud = checkudata(L);
    uint32_t payloadsz = 0;
    const uint8_t* payload = checkpayload(L, 2, &payloadsz);
    int size = libnet_write_link(ud, payload, payloadsz);
    lua_pushinteger(L, size);
    return 1;
}

/*-
- network = net.pton(presentation)

presentation is something like "df:33:44:12:45:54", or "1.2.3.4", or a host name

return is the binary, network byte-ordered address (you have to know what kind it was!)
*/
static int lnet_pton(lua_State *L)
{
    const char* src = luaL_checkstring(L, 1);
    struct addr dst;

    if(addr_pton(src, &dst) < 0) {
        return luaL_error(L, "pton failed on '%s'", src);
    }

    {
      int size = dst.addr_bits;
      void* addr = &dst.__addr_u;

      lua_pushlstring(L, addr, size/8);
    }

    return 1;
}

/*-
- chksum = net.chksum(string, ...)

Checksum the series of strings passed in.
*/
static int lnet_chksum(lua_State *L)
{
    int interm = 0;
    u_int16_t chks = 0;

    int i;
    int top = lua_gettop(L);
    for (i = 1; i <= top; i++) {
        size_t length = 0;
        const char* src = luaL_checklstring(L, i, &length);
        interm += libnet_in_cksum((uint16_t*)src, length);
    }

    chks = LIBNET_CKSUM_CARRY(interm);

    lua_pushlstring(L, (char *)&chks, 2);
    return 1;
}

/*-
- remaining = net.nanosleep(seconds)

Seconds can be decimal (resolution is nanoseconds, theoretically).
Return is number of seconds not slept, or nil and an error message on failure.

remaining = assert(net.nanosleep(seconds))

*/
static int lnet_nanosleep(lua_State *L)
{
    double n = luaL_checknumber(L, 1);
    struct timespec req = { 0 };
    struct timespec rem = { 0 };

    luaL_argcheck(L, n > 0, 1, "seconds must be greater than zero");

    req.tv_sec = (time_t) n;
    req.tv_nsec = 1000000000 * (n-req.tv_sec);

    if(nanosleep(&req, &rem) < 0) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    } else {
        lua_pushnumber(L, (double) rem.tv_sec + rem.tv_nsec / 1000000000.0);
        return 1;
    }
}

/*-
    t = net.gettimeofday()

Returns the current time since the epoch as a decimal number, with up to 
microsecond precision.  On error, returns nil and an error message.
*/
static int lnet_gettimeofday(lua_State *L)
{
    struct timeval tv;
    if(gettimeofday(&tv, NULL) < 0) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    } else {
        lua_pushnumber(L, (double) tv.tv_sec + tv.tv_usec / 1000000.0);
        return 1;
    }
}

/*-
- net.new(injection, device)

injection is one of "link", "raw", ...
device is "eth0", ...
*/
static int lnet_init(lua_State *L)
{
    static const char* injection_opt[] = {
        "link", "link_adv", "raw4", "raw4_adv", "raw6", "raw6_adv", NULL
    };
    static int injection_val[] = {
        LIBNET_LINK, LIBNET_LINK_ADV, LIBNET_RAW4, LIBNET_RAW4_ADV, LIBNET_RAW6, LIBNET_RAW6_ADV
    };
    char errbuf[LIBNET_ERRBUF_SIZE];
    int type = injection_val[luaL_checkoption(L, 1, "link", injection_opt)];
    /* FIXME provide a default injection type */
    const char *device = luaL_checkstring(L, 2);

    libnet_t** ud = lua_newuserdata(L, sizeof(*ud));
    *ud = NULL;

    luaL_getmetatable(L, L_NET_REGID);
    lua_setmetatable(L, -2);

    *ud = libnet_init(type, device, errbuf);

    if (!*ud) {
        return luaL_error(L, "%s", errbuf);
    }

    return 1;
}

/* TODO - merge these into libnet */
/* FIXME - below code has NO error checking and will segv on bad input */
static int libnet_decode_udp(const uint8_t* pkt, size_t pkt_s, libnet_t *l)
{
    const struct libnet_udp_hdr* udp_hdr = (const struct libnet_udp_hdr*) pkt;
    const uint8_t* payload = pkt + LIBNET_UDP_H;
    size_t payload_s = pkt + pkt_s - payload;
    int ptag = libnet_build_data(payload, payload_s, l, 0);
    int utag;

    if(ptag < 0) {
        return ptag;
    }

    assert(payload_s == 1);
    assert(l->ptag_end->b_len == 1);

    utag = libnet_build_udp(
            ntohs(udp_hdr->uh_sport),
            ntohs(udp_hdr->uh_dport),
            ntohs(udp_hdr->uh_ulen),
            0, /* recalculate checksum */
            NULL, 0,
            l, 0);

    return ptag;
}

static int libnet_decode_ipv4(const uint8_t* pkt, size_t pkt_s, libnet_t *l)
{
    const struct libnet_ipv4_hdr* ip_hdr = (const struct libnet_ipv4_hdr*) pkt;
    const uint8_t* payload = pkt + ip_hdr->ip_hl * 4;
    size_t payload_s = pkt + pkt_s - payload;
    int ptag = 0; /* payload tag */
    int otag = 0; /* options tag */
    int itag = 0; /* ip tag */

    /* This could be table-based */
    switch(ip_hdr->ip_p) {
        case IPPROTO_UDP:
            ptag = libnet_decode_udp(payload, payload_s, l);
            break;
#if 0
        case IPPROTO_TCP:
            ptag = libnet_decode_tcp(payload, payload_s, l, 0);
            break;
#endif
        default:
            ptag = libnet_build_data((void*)payload, payload_s, l, 0);
            break;
    }

    if(ptag < 0) return ptag;

    if(ip_hdr->ip_hl > 5) {
        payload = pkt + LIBNET_TCP_H;
        payload_s = ip_hdr->ip_hl * 4 - LIBNET_TCP_H;
        otag = libnet_build_ipv4_options((void*)payload, payload_s, l, 0);
        if(otag < 0) {
            /* FIXME - remove blocks from ptag until end */
            return otag;
        }
    }

    itag = libnet_build_ipv4(
            ntohs(ip_hdr->ip_len),
            ip_hdr->ip_tos,
            ntohs(ip_hdr->ip_id),
            ntohs(ip_hdr->ip_off),
            ip_hdr->ip_ttl,
            ip_hdr->ip_p,
            0, /* checksum, 0 to recalculate */
            ip_hdr->ip_src.s_addr,
            ip_hdr->ip_dst.s_addr,
            NULL, 0, /* payload already pushed */
            l, 0
            );

    return itag;
}

static int lnet_decode_ipv4(lua_State* L)
{
    libnet_t* ud = checkudata(L);
    size_t pkt_s = 0;
    const char* pkt = luaL_checklstring(L, 2, &pkt_s);
    int ptag = 0;

    ptag = libnet_decode_ipv4((void*)pkt, pkt_s, ud);

    lua_pushinteger(L, ptag);

    return 1;
}

static const luaL_reg net_methods[] =
{
  {"__gc", lnet_destroy},
  {"destroy", lnet_destroy},
  {"clear", lnet_clear},
  {"write", lnet_write},
  {"data", lnet_data},
  {"udp", lnet_udp},
  {"ipv4", lnet_ipv4},
  {"eth", lnet_eth},
  {"write_link", lnet_link},
  {"block", lnet_block},
  {"dump", lnet_dump},
  {"fd", lnet_getfd},
  {"pbuf", lnet_pbuf},
  {"device", lnet_getdevice},
  {"tag_below", lnet_tag_below},
  {"tag_above", lnet_tag_above},
  {"tag_type", lnet_tag_type},
  {"decode_ipv4", lnet_decode_ipv4},
  {NULL, NULL}
};

static const luaL_reg net[] =
{
  {"init", lnet_init},
  {"pton", lnet_pton},
  {"checksum", lnet_chksum},
  {"nanosleep", lnet_nanosleep},
  {"gettimeofday", lnet_gettimeofday},
  {NULL, NULL}
};

LUALIB_API int luaopen_net (lua_State *L)
{
  v_obj_metatable(L, L_NET_REGID, net_methods);

  luaL_register(L, "net", net);

  return 1;
}

