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

/*-
** nfq - a binding to netfilter's queue subsystem


list rules:

sudo iptables -L

delete input rule 1:

sudo iptables -t filter -D INPUT 1

insert input rule 1:

sudo iptables -t filter -I INPUT 1 -p udp -j QUEUE

replace input rule 1:

sudo iptables -t filter -R INPUT 1 -p udp -j QUEUE
*/

#define WANT_NF_LUA_PF
#include "nflua.h"

#include <libnetfilter_queue/libnetfilter_queue.h>


#define NFQ_REGID "wt.nfq"

static struct nfq_handle *check_handle(lua_State*L)
{
    struct nfq_handle* h = lua_touserdata(L, 1);

    luaL_argcheck(L, h, 1, "qhandle not provided");

    return h;
}

static struct nfq_q_handle *check_queue(lua_State*L)
{
    struct nfq_q_handle* q = lua_touserdata(L, 1);

    luaL_argcheck(L, q, 1, "queue not provided");

    return q;
}

static struct nfq_data *check_qdata(lua_State*L)
{
    struct nfq_data *qdata = lua_touserdata(L, 1);

    luaL_argcheck(L, qdata, 1, "qdata not provided");

    return qdata;
}

static int cb(
        struct nfq_q_handle *qh,
        struct nfgenmsg *nfmsg,
        struct nfq_data *nfqdata,
        void *data
        )
{
    /* TODO - should have an option "delay", to explicitly avoid
       offering a verdict right away */
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

    /* We expect stack to look like:
     *   [1] qhandle
     *   [2] cbfn
     */
    check_handle(L);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    lua_pushvalue(L, 2); /* Push copy of fn */
    lua_pushlightuserdata(L, nfqdata);
    lua_call(L, 1, 2);

    /* Return will be:
     *   [3] "accept", "drop", ..., default is accept
     *   [4] string, the replacement packet, default is 0,NULL
     */

    {
        int verdict = luaL_checkoption(L, 3, "accept", verdict_opt);
        size_t replacesz = 0;
        const char* replace = lua_tolstring(L, 4, &replacesz);

        /*printf("verdict %s data %p data_len %zd\n", verdict_opt[verdict], replace, replacesz);*/

        /* Reset stack, chopping any return values. */
        lua_settop(L, 2);

        return nfq_set_verdict(qh, id, verdict_val[verdict], replacesz, (void*)replace);
    }
}



/*-
-- qhandle = nfq.open()

Return an nfqueue qhandle on success, or nil,emsg,errno on failure.
*/
static int hopen(lua_State* L)
{
    struct nfq_handle *h = nfq_open();

    if(!h) {
        return push_error(L);
    }

    lua_pushlightuserdata(L, h);

    return 1;
}

/*-
-- nfq.close(qhandle)

Close the qhandle, freeing its resources.
*/
static int gc(lua_State* L)
{
    struct nfq_handle* h = check_handle(L);
    nfq_close(h);
    return 0;
}

/*-
- fd = nfq.fd(qhandle)

Return the underlying fd used by the qhandle, useful for
selecting on.
*/
static int fd(lua_State* L)
{
    struct nfq_handle* h = check_handle(L);
    lua_pushinteger(L, nfq_fd(h));
    return 1;
}

/*-
-- qhandle = nfq.setblocking(qhandle, [blocking])

blocking is true to set blocking, and false to set non-blocking (default is false)

Return is qhandle on success, or nil,emsg,errno on failure.
*/
static int setblocking(lua_State* L)
{
    return nfsetblocking(L, nfq_fd(check_handle(L)));
}


/*-
-- qhandle = nfq.unbind_pf(qhandle, family)

Protocol family is one of "inet", "inet6".

Return is qhandle on success and nil,emsg,errno on failure.
*/
static int unbind_pf(lua_State* L)
{
    struct nfq_handle* h = check_handle(L);
    int pf = check_PF(L, 2);

    if(nfq_unbind_pf(h, pf) < 0) {
        return push_error(L);
    }

    lua_settop(L, 1);

    return 1;
}

/*-
-- qhandle = nfq.bind_pf(qhandle, family)

Protocol family is one of "inet", "inet6".

Note that sample code seems to always unbind before binding, I've no idea why,
and there is no indication of whether its possible to bind to multiple address
families.

Return is qhandle on success and nil,emsg,errno on failure.
*/
static int bind_pf(lua_State* L)
{
    struct nfq_handle* h = check_handle(L);
    int pf = check_PF(L, 2);

    if(nfq_bind_pf(h, pf) < 0) {
        return push_error(L);
    }

    lua_settop(L, 1);

    return 1;
}

/*-
-- qhandle = nfq.catch(qhandle, cbfn)
-- verdict = cbfn(qdata)

cbfn - a function called for every queued packet with one argument, qdata. It
returns "accept" or "drop" meaning to do that to the packet. For no return
value, the default is "accept".  If the packet is accepted, the cbfn can
optionally return a second argument, a string that replaces the current packet.

Return qhandle on success and nil,emsg,errno on failure.
*/
/* TODO we allow only one cbfn for all the queues, which differs from
   the underlying library which allows a cbfn per queue. To do that I'd have to
   build a table to map the queues to their lua cbfns, which is possible, but I
   don't have the time for right now.
   */
static int catch(lua_State *L)
{
    struct nfq_handle* h = check_handle(L);
    int nffd = nfq_fd(h);
    char buf[4096] __attribute__ ((aligned));
    ssize_t bufsz;

    lua_settop(L, 2);

    /* Stack when cb from nfq occurs will be:
     *   [1] qhandle
     *   [2] cbfn
     */

    while((bufsz = recv(nffd, buf, sizeof(buf), 0)) > 0) {
        if(nfq_handle_packet(h, buf, bufsz) < 0) {
            return push_error(L);
        }
    }

    /* If we get here bufsz is <= 0, so either the netlink socket
       closed (possible?), would block, or some other error occurred. */
    if(bufsz == 0) {
        lua_pushnil(L);
        lua_pushstring(L, "closed");
        return 2;
    }

    return push_error(L);
}

/*-
-- loop = nfq.loop(cb, copy)

A one shot way to catch on queue zero, the equivalent of:

  h = nfq.open()
  nfq.unbind_pf(h, "inet")
  nfq.bind_pf(h, "inet")
  q = nfq.create_queue(h, 0)
  nfq.set_mode(q, copy, 0xffff)
  ... = nfq.catch(h, cb)
  nfq.destroy_queue(q)
  nfq.close(h)
  return ...

DEPRECATED - don't use it in new code, it will be deleted as soon as
the existing users of it have been updated.

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
    int nlfd = -1;
    int nreturn = 0;
    char buf[4096] __attribute__ ((aligned));
    ssize_t recvsz;

    h = nfq_open();

    if(!h)
        goto err;

    if(nfq_unbind_pf(h, af) < 0)
        goto err;

    if(nfq_bind_pf(h, af) < 0)
        goto err;

    qh = nfq_create_queue(h,  0, &cb, L);

    if(!qh)
        goto err;

    if(nfq_set_mode(qh, copy, 0xffff /* larger than an ethernet frame */) < 0)
        goto err;

    nlfd = nfq_fd(h);

    while((recvsz = recv(nlfd, buf, sizeof(buf), 0)) >= 0) {
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


/*-
-- queue = nfq.create_queue(qhandle, queuenum)

queuenum is number of the queue to bind to.

Return a queue on success, or nil,emsg,errno on failure.
*/
static int create_queue(lua_State* L)
{
    struct nfq_handle* h = check_handle(L);
    int num = luaL_checkint(L, 2);
    struct nfq_q_handle *q = nfq_create_queue(h, num, cb, L);

    if(!q) {
        return push_error(L);
    }

    lua_pushlightuserdata(L, q);

    return 1;
}

/*-
-- nfq.destroy_queue(queue)

Close the queue, freeing its resources.
*/
static int destroy_queue(lua_State* L)
{
    struct nfq_q_handle* q = check_queue(L);
    nfq_destroy_queue(q);
    return 0;
}

/*-
-- queue = nfq.set_mode(queue, copy, range)

queue is returned by nfq.create_queue().

copy is one of "none" (a no-op, don't use it), "meta" (copy just packet
metadata), or "packet" (copy the full packet) (default is currently "packet").

range is the size of the packet to copy, and is optional (it defaults to
0xffff, larger than any ethernet packet can be, and larger than any link
layer packet I'm aware of).

Returns the queue on success and nil,emsg,errno on failure.
*/
static int set_mode(lua_State* L)
{
    static const char* copy_opts[] = {
        "none", "meta", "packet", NULL
    };
    static int copy_vals[] = {
        NFQNL_COPY_NONE, NFQNL_COPY_META, NFQNL_COPY_PACKET
    };
    struct nfq_q_handle *q = check_queue(L);
    int copy_opt = luaL_checkoption(L, 2, "packet", copy_opts);
    int copy_val = copy_vals[copy_opt];
    int range = luaL_optint(L, 3, 0xffff);

    if (nfq_set_mode(q, copy_val, range) < 0) {
        return push_error(L);
    }

    lua_settop(L, 1);

    return 1;
}

/*-
-- str = nfq.get_payload(cbctx)

str is the IP payload, it has been stripped of link-layer headers.
*/
static int get_payload(lua_State* L)
{
    struct nfq_data *nfqdata = check_qdata(L);
    unsigned char* data = NULL;
    int datasz = nfq_get_payload(nfqdata, &data);
    luaL_argcheck(L, datasz >= 0, 1, "nfqdata not available");

    lua_pushlstring(L, (char*)data, datasz);

    return 1;
}

static const luaL_reg nfq[] =
{
    /* return or operate on qhandle */
    {"open", hopen},
    {"close", gc},
    {"fd", fd},
    {"setblocking", setblocking},
    {"unbind_pf", unbind_pf},
    {"bind_pf", bind_pf},
    {"catch", catch},
    {"loop", loop},

    /* return or operate on a queue */
    {"create_queue", create_queue},
    {"destroy_queue", destroy_queue},
    {"set_mode", set_mode},

    /* operate on a callback context */
    {"get_payload", get_payload},

    {NULL, NULL}
};

LUALIB_API int luaopen_nfq (lua_State *L)
{
    luaL_register(L, "nfq", nfq);

    return 1;
}

