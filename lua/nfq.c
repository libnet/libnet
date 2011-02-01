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

/*

list rules:

sudo iptables -L

delete input rule 1:

sudo iptables -t filter -D INPUT 1

insert input rule 1:

sudo iptables -t filter -I INPUT 1 -p udp -j QUEUE

replace input rule 1:

sudo iptables -t filter -R INPUT 1 -p udp -j QUEUE

*/


#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <linux/netfilter.h>
#include <linux/types.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define NFQ_REGID "wt.nfq"

static int cb(
        struct nfq_q_handle *qh,
        struct nfgenmsg *nfmsg,
        struct nfq_data *nfqdata,
        void *data
        )
{
    static const char* verdict_opt[] = {
        "accept", "drop", NULL
    };
    static int verdict_val[] = {
        NF_ACCEPT, NF_DROP,
    };

    lua_State* L = data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfqdata);
/*  struct nfqnl_msg_packet_hw *hwph = nfq_get_msg_packet_hw(nfdata); */
    u_int32_t id = 0;

    if (ph) {
        /* TODO - why is this conditional in sample source? */
        id = ntohl(ph->packet_id);
    }

    /* Return will be:
     *   [2] "accept", "drop", ..., default is accept
     *   [3] string, the replacement packet, default is 0,NULL
     */

    lua_settop(L, 1); /* Leave only the cb fn on the stack */
    lua_pushvalue(L, 1); /* Push copy of fn */
    lua_pushlightuserdata(L, nfqdata);
    lua_call(L, 1, 2);

    {
        int verdict = luaL_checkoption(L, 2, "accept", verdict_opt);
        size_t replacesz = 0;
        const char* replace = lua_tolstring(L, 3, &replacesz);

        /*printf("verdict %s data %p data_len %zd\n", verdict_opt[verdict], replace, replacesz);*/

        return nfq_set_verdict(qh, id, verdict_val[verdict], replacesz, (void*)replace);
    }
}

/*-
- nfq.loop(cb, copy)

cb - a function called for every queued packet, it returns 
"accept" or "drop" meaning to do that to the packet. For
no return value, the default is "accept". If it returns a second
argument, it must be a string, and replaces the current
packet.

copy - "none", "meta", "packet", default to "packet"
*/
static int loop(lua_State *L)
{
    static const char* copy_opt[] = {
        "none", "meta", "packet", NULL
    };
    static int copy_val[] = {
        NFQNL_COPY_NONE, NFQNL_COPY_META, NFQNL_COPY_PACKET
    };
    int copy = copy_val[luaL_checkoption(L, 2, "packet", copy_opt)];
    int af = AF_INET; /* Could be an argument, if we ever did non-INET. */
    struct nfq_handle *h = NULL;
    struct nfq_q_handle *qh = NULL;
    int fd = -1;
    int nreturn = 0;
    char buf[4096] __attribute__ ((aligned));
    ssize_t recvsz;

    h = nfq_open();

    if(!h)
        goto err;

    if (nfq_unbind_pf(h, af) < 0)
        goto err;

    if (nfq_bind_pf(h, af) < 0)
        goto err;

    qh = nfq_create_queue(h,  0, &cb, L);

    if(!qh)
        goto err;

    if (nfq_set_mode(qh, copy, 0xffff /* larger than an ethernet frame */) < 0)
        goto err;

    fd = nfq_fd(h);

    while ((recvsz = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, recvsz);
    }

    if(recvsz < 0)
        goto err;

    goto cleanup;

err:
    lua_pushnil(L);
    lua_pushstring(L, strerror(errno));
    nreturn = 2;

cleanup:

    if(qh)
        nfq_destroy_queue(qh);

    if(h)
        nfq_close(h);

    return nreturn;
}

struct nfq_data *checkudata(lua_State*L)
{
    struct nfq_data *nfqdata = lua_touserdata(L, 1);

    luaL_argcheck(L, nfqdata, 1, "nfqdata not provided");

    return nfqdata;
}

/*-
str = nfq.get_payload(cbctx)

str is the IP payload, it has been stripped of link-layer headers!
*/
static int get_payload(lua_State* L)
{
    struct nfq_data *nfqdata = checkudata(L);
    char* data = NULL;
    int datasz = nfq_get_payload(nfqdata, &data);
    luaL_argcheck(L, datasz >= 0, 1, "nfqdata not available");

    lua_pushlstring(L, data, datasz);

    return 1;
}

static const luaL_reg nfq[] =
{
    {"loop", loop},
    {"get_payload", get_payload},
    {NULL, NULL}
};

LUALIB_API int luaopen_nfq (lua_State *L)
{
    luaL_register(L, "nfq", nfq);

    return 1;
}

