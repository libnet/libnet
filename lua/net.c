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

#include <dnet.h>
#include <libnet.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

/*#define NET_DUMP*/

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
    // metatable = { ... methods ... }
    luaL_newmetatable(L, regid);
    luaL_register(L, NULL, methods);
    // metatable["__index"] = metatable
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
    switch(type) {
        case LIBNET_PBLOCK_ETH_H:  return "eth";
        case LIBNET_PBLOCK_IPV4_H: return "ip4";
        case LIBNET_PBLOCK_IPO_H:  return "ipo";
        case LIBNET_PBLOCK_IPDATA: return "ipd";
    }
    return "?";
}
static int lnet_dump(lua_State* L)
{
    libnet_t** ud = luaL_checkudata(L, 1, L_NET_REGID);
    luaL_argcheck(L, *ud, 1, "net has been destroyed");

    libnet_pblock_t* p = (*ud)->protocol_blocks;
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
            (*ud)->link_offset, (*ud)->aligner, (*ud)->total_size, (*ud)->n_pblocks);
    strings++;

    lua_concat(L, strings);

    return 1;
}

/*-
- str = net:block()

Coalesce the protocol blocks into a single chunk, and return.
*/
static int lnet_block(lua_State* L)
{
    libnet_t** ud = luaL_checkudata(L, 1, L_NET_REGID);
    luaL_argcheck(L, *ud, 1, "net has been destroyed");

    u_int32_t len;
    u_int8_t *packet = NULL;

    int r = libnet_pblock_coalesce(*ud, &packet, &len);

    check_error(L, *ud, r);

    lua_pushlstring(L, (char*) packet, len);

    return 1;
}

/*-
- net:write()

Write the packet (which must previously have been built up inside the context).
*/
static int lnet_write(lua_State *L)
{
    libnet_t** ud = luaL_checkudata(L, 1, L_NET_REGID);
    luaL_argcheck(L, *ud, 1, "net has been destroyed");

#ifdef NET_DUMP
    lnet_dump(L);
#endif

    int r = libnet_write(*ud);

    check_error(L, *ud, r);

    lua_pushinteger(L, r);

    return 1;
}

/*-
- ptag = net:udp{src=NUM, dst=NUM, len=NUM, payload=STR, ptag=int}

Build UDP packet inside net context.

ptag is optional, defaults to creating a new protocol block
*/
static int lnet_udp (lua_State *L)
{
    libnet_t** ud = luaL_checkudata(L, 1, L_NET_REGID);
    luaL_argcheck(L, *ud, 1, "net has been destroyed");

    int src = v_arg_integer(L, 2, "src");
    int dst = v_arg_integer(L, 2, "dst");

    size_t payloadsz = 0;
    const char* payload = v_arg_lstring(L, 2, "payload", &payloadsz, "");
    int len = v_arg_integer_opt(L, 2, "len", LIBNET_UDP_H + payloadsz);
    int cksum = 0;
    int ptag = lnet_arg_ptag(L, 2);

    if(payloadsz == 0) {
        payload = NULL;
    }

    ptag = libnet_build_udp(src, dst, len, cksum, (uint8_t*)payload, payloadsz, *ud, ptag);
    check_error(L, *ud, ptag);
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
    libnet_t** ud = luaL_checkudata(L, 1, L_NET_REGID);
    luaL_argcheck(L, *ud, 1, "net has been destroyed");

    int len = v_arg_integer(L, 2, "len"); // FIXME - should be optional!
    int tos = 0;
    int id = 0;
    int offset = 0;
    int ttl = 64;
    int protocol = v_arg_integer(L, 2, "protocol");
    int cksum = 0; // 0 is a flag requesting libnet to fill in correct cksum
    const char* src = v_arg_string(L, 2, "src");
    const char* dst = v_arg_string(L, 2, "dst");
    size_t payloadsz = 0;
    const char* payload = v_arg_lstring(L, 2, "payload", &payloadsz, "");
    int ptag = lnet_arg_ptag(L, 2);
    int options_ptag = 0;
    size_t optionsz = 0;
    const char* options = v_arg_lstring(L, 2, "options", &optionsz, "");

    if(payloadsz == 0) {
        payload = NULL;
    }

#ifdef NET_DUMP
    printf("net ipv4 src %s dst %s len %d payloadsz %lu ptag %d optionsz %lu\n", src, dst, len, payloadsz, ptag, optionsz);
#endif

    uint32_t src_n = check_ip_pton(L, src, "src");
    uint32_t dst_n = check_ip_pton(L, dst, "dst");

    if(ptag) {
        /* Modifying exist IPv4 packet, so find the preceeding options block (we
         * _always_ push an options block, perhaps empty, to make this easy).
         */
        libnet_pblock_t* p = libnet_pblock_find(*ud, ptag);

        if(!p)
            return check_error(L, *ud, -1);

        options_ptag = p->prev->ptag;
    }

#ifdef NET_DUMP
    printf("  options_ptag %d optionsz %lu\n", options_ptag, optionsz);
#endif

    options_ptag = libnet_build_ipv4_options((uint8_t*) options,
            optionsz, *ud, options_ptag);

    check_error(L, *ud, options_ptag);

    ptag = libnet_build_ipv4(len, tos, id, offset, ttl, protocol, cksum, src_n,
            dst_n, (uint8_t*) payload, payloadsz, *ud, ptag);
    check_error(L, *ud, ptag);
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
    libnet_t** ud = luaL_checkudata(L, 1, L_NET_REGID);
    luaL_argcheck(L, *ud, 1, "net has been destroyed");

    const char* src = v_arg_string(L, 2, "src");
    const char* dst = v_arg_string(L, 2, "dst");
    int type = v_arg_integer_opt(L, 2, "type", ETHERTYPE_IP);
    size_t payloadsz = 0;
    const char* payload = v_arg_lstring(L, 2, "payload", &payloadsz, "");
    int ptag = lnet_arg_ptag(L, 2);

    if(payloadsz == 0) {
        payload = NULL;
    }

#ifdef NET_DUMP
    printf("net eth src %s dst %s type %d payloadsz %lu ptag %d\n", src, dst, type, payloadsz, ptag);
#endif

    eth_addr_t src_n = check_eth_pton(L, src, "src");
    eth_addr_t dst_n = check_eth_pton(L, dst, "dst");
    ptag = libnet_build_ethernet(dst_n.data, src_n.data, type, (uint8_t*)payload, payloadsz, *ud, ptag);
    check_error(L, *ud, ptag);
    lua_pushinteger(L, ptag);
    return 1;
}

static int lnet_link (lua_State *L)
{
    libnet_t** ud = luaL_checkudata(L, 1, L_NET_REGID);
    luaL_argcheck(L, *ud, 1, "net has been destroyed");
    size_t payloadsz = 0;
    const char* payload = luaL_checklstring(L, 2, &payloadsz);

    int size = libnet_write_link(*ud, (uint8_t*)payload, payloadsz);
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

    int size = dst.addr_bits;
    void* addr = &dst.__addr_u;

    lua_pushlstring(L, addr, size/8);

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
        interm += libnet_in_cksum((u_int16_t*)src, length);
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

    luaL_argcheck(L, n > 0, 1, "seconds must be greater than zero");

    struct timespec req = { 0 };
    req.tv_sec = (time_t) n;
    req.tv_nsec = 1000000000 * (n-req.tv_sec);

    struct timespec rem = { 0 };

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
    int type = injection_val[luaL_checkoption(L, 1, NULL, injection_opt)];
    const char *device = luaL_checkstring(L, 2);

    libnet_t** ud = lua_newuserdata(L, sizeof(*ud));
    *ud = NULL;

    luaL_getmetatable(L, L_NET_REGID);
    lua_setmetatable(L, -2);

    *ud = libnet_init(type, (char*)device, errbuf);

    if (!*ud) {
        return luaL_error(L, "%s", errbuf);
    }

    return 1;
}

static const luaL_reg net_methods[] =
{
  {"__gc", lnet_destroy},
  {"destroy", lnet_destroy},
  {"write", lnet_write},
  {"udp", lnet_udp},
  {"ipv4", lnet_ipv4},
  {"eth", lnet_eth},
  {"write_link", lnet_link},
  {"block", lnet_block},
  {"dump", lnet_dump},
  {NULL, NULL}
};

static const luaL_reg net[] =
{
  {"init", lnet_init},
  {"pton", lnet_pton},
  {"checksum", lnet_chksum},
  {"nanosleep", lnet_nanosleep},
  {NULL, NULL}
};

LUALIB_API int luaopen_net (lua_State *L)
{
  v_obj_metatable(L, L_NET_REGID, net_methods);

  luaL_register(L, "net", net);

  return 1;
}

