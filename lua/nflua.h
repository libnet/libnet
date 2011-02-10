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

