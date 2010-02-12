/*
Copyright (C) 2010 Wurldtech Security Technologies All rights reserved.

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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static double tv2secs(struct timeval* tv)
{
    double secs = tv->tv_sec;
    secs += (double)tv->tv_usec / 1000000.0;
    return secs;
}

static struct timeval* secs2tv(double secs, struct timeval* tv)
{
    tv->tv_sec  = (time_t) secs;
    tv->tv_usec = (suseconds_t) ((secs - tv->tv_sec) * 1000000);
    return tv;
}

static struct timeval* opttimeval(lua_State* L, int argi, struct timeval* tv)
{
    if(lua_isnoneornil(L, argi)) {
#ifndef NDEBUG
        int e =
#endif
            gettimeofday(tv, NULL);
#ifndef NDEBUG
        assert(e == 0); /* can only fail due to argument errors */
#endif
    } else {
        double secs = luaL_checknumber(L, argi);
        secs2tv(secs, tv);
    }
    return tv;
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

#include <pcap.h>

/* Wrap pcap_dumper_t */

#define L_PCAP_DUMPER_REGID "wt.pcap_dumper"

static pcap_dumper_t* checkdumper(lua_State* L)
{
    pcap_dumper_t** dumper = luaL_checkudata(L, 1, L_PCAP_DUMPER_REGID);

    luaL_argcheck(L, *dumper, 1, "pcap dumper has been destroyed");

    return *dumper;
}

/*-
- dumper:destroy()

Manually destroy a dumper object, freeing it's resources (this will happen on
garbage collection if not done explicitly).
*/
static int lpcap_dump_destroy (lua_State *L)
{
    pcap_dumper_t** dumper = luaL_checkudata(L, 1, L_PCAP_DUMPER_REGID);

    if(*dumper)
        pcap_dump_close(*dumper);

    *dumper = NULL;

    return 0;
}

/*-
  dumper = dumper:dump(pkt, [timestamp, [wirelen]])

pkt to dump
timestamp of packet, defaults to 0, meaning the current time
wire length of packet, defaults to pkt's length

Returns self on sucess.
Returns nil and an error msg on failure.

Note that arguments are compatible with cap:next(), and that since
pcap_dump() doesn't return error indicators only the failure
values from cap:next() will ever be returned.
*/
static int lpcap_dump(lua_State* L)
{
    pcap_dumper_t* dumper = checkdumper(L);
    const char* pkt;
    size_t caplen;
    size_t wirelen;
    struct pcap_pkthdr hdr;

    /* first check if we are echoing the nil,emsg from cap:next()
     * before checking our argument types
     */
    if(lua_isnil(L, 2) && lua_type(L, 3) == LUA_TSTRING) {
        return 2;
    }

    pkt = luaL_checklstring(L, 2, &caplen);
    opttimeval(L, 3, &hdr.ts);
    wirelen = luaL_optint(L, 4, caplen);

    hdr.caplen = caplen;
    hdr.len = wirelen;

    /* Note odd type signature for dumper, its because pcap_dump() is
     * designed to be called from a pcap_handler, where the dumper
     * is received as the user data.
     */
    pcap_dump((u_char*) dumper, &hdr, (u_char*)pkt);

    /* clear the stack above self, and return self */
    lua_settop(L, 1);

    return 1;
}

/*-
  dumper = dumper:flush()

Flush all dumped packets to disk.

Returns self on sucess.
Returns nil and an error msg on failure.
*/
static int lpcap_flush(lua_State* L)
{
    pcap_dumper_t* dumper = checkdumper(L);
    int e = pcap_dump_flush(dumper);

    if(e == 0) {
        return 1;
    }

    lua_pushnil(L);
    lua_pushstring(L, strerror(errno));

    return 2;
}
    

/* Wrap pcap_t */

#define L_PCAP_REGID "wt.pcap"

static pcap_t* checkpcap(lua_State* L)
{
    pcap_t** cap = luaL_checkudata(L, 1, L_PCAP_REGID);

    luaL_argcheck(L, *cap, 1, "pcap has been destroyed");

    return *cap;
}

/*-
- dumper = cap:dump_open([fname])

fname defaults to "-", stdout.

Note that the dumper object is independent of the cap object, once
it's created.
*/
static int lpcap_dump_open(lua_State *L)
{
    pcap_t* cap = checkpcap(L);
    const char* fname = luaL_optstring(L, 2, "-");
    pcap_dumper_t** dumper = lua_newuserdata(L, sizeof(*dumper));

    *dumper = NULL;

    luaL_getmetatable(L, L_PCAP_DUMPER_REGID);
    lua_setmetatable(L, -2);

    *dumper = pcap_dump_open(cap, fname);

    if (!*dumper) {
        lua_pushnil(L);
        lua_pushstring(L, pcap_geterr(cap));
        return 2;
    }

    return 1;
}

/*-
- cap:destroy()

Manually destroy a cap object, freeing it's resources (this will happen on
garbage collection if not done explicitly).
*/
static int lpcap_destroy (lua_State *L)
{
    pcap_t** cap = luaL_checkudata(L, 1, L_PCAP_REGID);

    if(*cap)
        pcap_close(*cap);

    *cap = NULL;

    return 0;
}

static int pushpkt(lua_State* L, struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
    lua_pushlstring(L, (const char*)pkt_data, pkt_header->caplen);
    lua_pushnumber(L, tv2secs(&pkt_header->ts));
    lua_pushinteger(L, pkt_header->len);

    return 3;
}

/*-
- cap:next()

Returns:
  capdata, timestamp, wirelen
    captured data, the timestamp, the wire length
  nil, "timeout"            
    timeout on a live capture
  nil
    no more packets to be read from a file
  nil, emsg
    an error ocurred, emsg describes the error
*/
static int lpcap_next(lua_State* L)
{
    pcap_t* cap = checkpcap(L);
    struct pcap_pkthdr* pkt_header = NULL;
    const u_char* pkt_data = NULL;
    int e = pcap_next_ex(cap, &pkt_header, &pkt_data);

    switch(e) {
        case 1:
            return pushpkt(L, pkt_header, pkt_data);
        case 0:
            lua_pushnil(L);
            lua_pushstring(L, "timeout");
            return 2;
        default: /* default should not occur.. */
        case -1:
            lua_pushnil(L);
            lua_pushstring(L, pcap_geterr(cap));
            return 2;
        case -2:
            lua_pushnil(L);
            return 1;
    }
    return luaL_error(L, "unreachable");
}

/* pcap open helpers */
static pcap_t** pushpcapopen(lua_State* L)
{
    pcap_t** cap = lua_newuserdata(L, sizeof(*cap));
    *cap = NULL;
    luaL_getmetatable(L, L_PCAP_REGID);
    lua_setmetatable(L, -2);
    return cap;
}

static int checkpcapopen(lua_State* L, pcap_t** cap, const char* errbuf)
{
    if (!*cap) {
        lua_pushnil(L);
        lua_pushstring(L, errbuf);
        return 2;
    }
    return 1;
}


/*-
- cap = pcap.open_offline([fname])

fname defaults to "-", stdin

Open a savefile to read packets from.
*/
static int lpcap_open_offline(lua_State *L)
{
    const char *fname = luaL_optstring(L, 1, "-");
    pcap_t** cap = pushpcapopen(L);
    char errbuf[PCAP_ERRBUF_SIZE];
    *cap = pcap_open_offline(fname, errbuf);
    return checkpcapopen(L, cap, errbuf);
}

/*-
- cap = pcap.open_dead([linktype, [caplen]])

linktype is one of the DLT_ numbers, and defaults to 1 ("DLT_EN10MB")
caplen is the maximum size of packet, and defaults to ...

caplen defaults to 0, meaning "no limit" (actually, its changed into
65535 internally, which is what tcpdump does)

TODO should accept strings as the link type, or have a table of the link
types:
    pcap.DLT = { NULL = 0, EN10MB = 1, ... }

Open a pcap that doesn't read from either a live interface, or an offline pcap
file. It can be used to write a pcap file, or to compile a BPF program.
*/
static int lpcap_open_dead(lua_State *L)
{
    int linktype = luaL_optint(L, 1, DLT_EN10MB);
    int snaplen = luaL_optint(L, 2, 0);
    pcap_t** cap = pushpcapopen(L);

    /* this is the value tcpdump uses, its way bigger than any known link size */
    if(!snaplen)
        snaplen = 0xffff;

    *cap = pcap_open_dead(linktype, snaplen);

    return checkpcapopen(L, cap, "open dead failed for unknown reason");
}

static const luaL_reg dumper_methods[] =
{
  {"__gc", lpcap_dump_destroy},
  {"close", lpcap_dump_destroy},
  {"dump", lpcap_dump},
  {"flush", lpcap_flush},
  {NULL, NULL}
};

static const luaL_reg pcap_methods[] =
{
  {"dump_open", lpcap_dump_open},
  {"__gc", lpcap_destroy},
  {"close", lpcap_destroy},
  {"next", lpcap_next},
  {NULL, NULL}
};

static const luaL_reg pcap_module[] =
{
  {"open_offline", lpcap_open_offline},
  {"open_dead", lpcap_open_dead},
  {NULL, NULL}
};

LUALIB_API int luaopen_pcap (lua_State *L)
{
  v_obj_metatable(L, L_PCAP_DUMPER_REGID, dumper_methods);
  v_obj_metatable(L, L_PCAP_REGID, pcap_methods);
  luaL_register(L, "pcap", pcap_module);
  return 1;
}

