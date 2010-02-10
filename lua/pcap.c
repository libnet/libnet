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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

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

#define L_PCAP_REGID "wt.pcap"

static pcap_t* checkudata(lua_State* L)
{
    pcap_t** ud = luaL_checkudata(L, 1, L_PCAP_REGID);

    luaL_argcheck(L, *ud, 1, "pcap has been destroyed");

    return *ud;
}

/*-
- cap:destroy()

Manually destroy a cap object, freeing it's resources (this will happen on
garbage collection if not done explicitly).
*/
static int lpcap_destroy (lua_State *L)
{
    pcap_t** ud = luaL_checkudata(L, 1, L_PCAP_REGID);

    if(*ud)
        pcap_close(*ud);

    *ud = NULL;

    return 0;
}

static int pushpkt(lua_State* L, struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
    const char* data = (const char*) pkt_data;
    double secs = pkt_header->ts.tv_sec;
    
    secs += (double)pkt_header->ts.tv_usec / 1000000.0;

    lua_pushlstring(L, data, pkt_header->caplen);
    lua_pushnumber(L, secs);
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
    pcap_t* ud = checkudata(L);
    struct pcap_pkthdr* pkt_header = NULL;
    const u_char* pkt_data = NULL;
    int e = pcap_next_ex(ud, &pkt_header, &pkt_data);

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
            lua_pushstring(L, pcap_geterr(ud));
            return 2;
        case -2:
            lua_pushnil(L);
            return 1;
    }
    return luaL_error(L, "unreachable");
}

/*-
- cap = pcap.open_offline(fname)
*/
static int lpcap_open_offline(lua_State *L)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *fname = luaL_checkstring(L, 1);

    pcap_t** ud = lua_newuserdata(L, sizeof(*ud));
    *ud = NULL;

    luaL_getmetatable(L, L_PCAP_REGID);
    lua_setmetatable(L, -2);

    *ud = pcap_open_offline(fname, errbuf);

    if (!*ud) {
        lua_pushnil(L);
        lua_pushstring(L, errbuf);
        return 2;
    }

    return 1;
}

static const luaL_reg pcap_methods[] =
{
  {"__gc", lpcap_destroy},
  {"destroy", lpcap_destroy},
  {"next", lpcap_next},
  {NULL, NULL}
};

static const luaL_reg pcap_module[] =
{
  {"open_offline", lpcap_open_offline},
  {NULL, NULL}
};

LUALIB_API int luaopen_pcap (lua_State *L)
{
  v_obj_metatable(L, L_PCAP_REGID, pcap_methods);

  luaL_register(L, "pcap", pcap_module);

  return 1;
}

