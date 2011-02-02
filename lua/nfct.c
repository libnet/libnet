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
** nfct - a binding to netfilter's conntrack subsystem

NOTE I know its confusing that the nfct module has functions that should be
called on a conntrack handle and a conntrack context mixed together, but unless
I make full userdata out of one or both of them, thats what it has to be. Don't
confuse them, or you will segfault!
*/

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include <assert.h>
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

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define NFCT_REGID "wt.nfct"


static void push_error(lua_State* L)
{
    lua_pushnil(L);
    lua_pushstring(L, strerror(errno));
    lua_pushinteger(L, errno);
}

static struct nf_conntrack* check_ct(lua_State*L)
{
    struct nf_conntrack* ct = lua_touserdata(L, 1);

    luaL_argcheck(L, ct, 1, "conntrack not provided");

    return ct;
}

static struct nfct_handle* check_cthandle(lua_State*L)
{
    struct nfct_handle* cth = lua_touserdata(L, 1);

    luaL_argcheck(L, cth, 1, "conntrack handle not provided");

    return cth;
}

static const char* ctmsg_type_string(enum nf_conntrack_msg_type type)
{
    switch(type) {
        case NFCT_T_NEW: return "new";
        case NFCT_T_UPDATE: return "update";
        case NFCT_T_DESTROY: return "destroy";
        case NFCT_T_ERROR: return "error";
        default: return "unknown";
    }
}


/*-
- cthandle = nfct.open(subsys, [subscription...])

subsys is "track" or "expect"

subscription is the groups for which notifications are requested, zero or more of
"none", "new", "update", "destroy", or "all" (default is "none").

Returns a conntrack handle on success, or nil,emsg,errno on failure.

There is no garbage collection, nfct.fini() must be called on the handle to
release it's resources.
*/
static int open(lua_State *L)
{
    static const char* subsys_opts[] = {
        "track", "expect", NULL
    };
    static u_int8_t subsys_vals[] = {
        NFNL_SUBSYS_CTNETLINK, NFNL_SUBSYS_CTNETLINK_EXP,
    };
    int subsys_opt = luaL_checkoption(L, 1, NULL, subsys_opts);
    u_int8_t subsys_val = subsys_vals[subsys_opt];
    static const char*  subscription_opts[] = {
        "none", "new", "update", "destroy", "all", NULL
    };
    unsigned subscription_vals[2][5] = {
        { /* [0] == "track" */
            0,
            NF_NETLINK_CONNTRACK_NEW,
            NF_NETLINK_CONNTRACK_UPDATE,
            NF_NETLINK_CONNTRACK_DESTROY,
            NFCT_ALL_CT_GROUPS
        },
        { /* [1] == "expect" */
            0,
            NF_NETLINK_CONNTRACK_EXP_NEW,
            NF_NETLINK_CONNTRACK_EXP_UPDATE,
            NF_NETLINK_CONNTRACK_EXP_DESTROY,
            NF_NETLINK_CONNTRACK_EXP_NEW
                |NF_NETLINK_CONNTRACK_EXP_UPDATE
                |NF_NETLINK_CONNTRACK_EXP_DESTROY
        }
    };
    unsigned subscription_val = 0;
    int narg = 0;
    struct nfct_handle* ct = NULL;

    /* the check option should have ensured that the opt index is 0 or 1,
     * so we can safely use it to index into the watfor vals
     */
    assert(subsys_opt == 0 || subsys_opt == 1);

    for(narg = 2; narg <= lua_gettop(L); narg++) {
        int subscription_opt = luaL_checkoption(L, 1, "none", subscription_opts);
        subscription_val |= subscription_vals[subsys_opt][subscription_opt];
    }

    ct = nfct_open(subsys_val, subscription_val);

    if(!ct) {
        push_error(L);
        return 3;
    }

    lua_pushlightuserdata(L, ct);

    return 1;
}

/*-
- nfct.close(cthandle)

Close the conntrack handle, freeing its resources.
*/
static int gc(lua_State* L)
{
    struct nfct_handle* cthandle = check_cthandle(L);
    nfct_close(cthandle);
    return 0;
}

/*-
- fd = nfct.fd(cthandle)

Return the underlying fd used by the conntrack handle, useful for
selecting on.
*/
static int fd(lua_State* L)
{
    struct nfct_handle* cthandle = check_cthandle(L);
    lua_pushinteger(L, nfct_fd(cthandle));
    return 1;
}

static int cb(
        enum nf_conntrack_msg_type type,
        struct nf_conntrack *ct,
        void *data
        )
{
    static const char* verdict_opts[] = {
        "failure", "stop", "continue", "stolen", NULL
    };
    static int verdict_vals[] = {
        NFCT_CB_FAILURE, NFCT_CB_STOP, NFCT_CB_CONTINUE, NFCT_CB_STOLEN
    };
    int verdict_val = 0;

    lua_State* L = data;

    /* We expect stack to look like:
     *   [1] cthandle
     *   [2] cbfn
     */

    luaL_checktype(L, 2, LUA_TFUNCTION);

    lua_pushvalue(L, 2); /* Push copy of fn */
    lua_pushstring(L, ctmsg_type_string(type));
    lua_pushlightuserdata(L, ct);

    lua_call(L, 2, 1);

    verdict_val = verdict_vals[
            luaL_checkoption(L, 3, "continue", verdict_opts)
            ];

    /* Reset stack, chopping any return value. */
    lua_settop(L, 2);

    return verdict_val;
}


/*-
- cthandle = nfct.callback_register(cthandle, ctmsgtype)

ctmsgtype is one of "new", "update", "destroy", or "all" (default is "all").

Only one registration can be active at a time, the latest call replaces
any previous ones.

Returns cthandle on success, nil,emsg,errno on failure.
*/
static int callback_register(lua_State* L)
{
    struct nfct_handle* cthandle = check_cthandle(L);
    static const char* msgtype_opts[] = {
        "new", "update", "destroy", "all", "error", NULL
    };
    static enum nf_conntrack_msg_type msgtype_vals[] = {
        NFCT_T_NEW, NFCT_T_UPDATE, NFCT_T_DESTROY, NFCT_T_ALL, NFCT_T_ERROR,
    };
    int msgtype_opt = luaL_checkoption(L, 2, "all", msgtype_opts);
    enum nf_conntrack_msg_type msgtype_val = msgtype_vals[msgtype_opt];
    int ret;
   
    /* Clear any current handler to avoid memory leaks. */
    nfct_callback_unregister(cthandle);

    ret = nfct_callback_register(cthandle, msgtype_val, cb, L);

    if(ret < 0) {
        push_error(L);
        return 3;
    }

    lua_pushvalue(L, 1);

    return 1;
}

/*-
- cthandle = nfct.catch(cthandle, cbfn)

cbfn is the callback function, and will be called as

  function cbfn(ctmsgtype, ct) ...

with a ctmsgtype and conntrack context (NOT a handle!) as arguments.

The callback can return any of "failure", "stop", "continue", or "stolen" (the
default is "continue"):

  "failure" will stop the loop,
  "continue" will continue with the next message, and
  "stolen" is like continue, except the conntrack context will
    not be destroyed (the user must destroy ct later with nfct.destroy() or
    resources will be leaked)

Note that cbfn is optional and will NOT be called unless
nfct.register_callback() was previously called to indicate what msg types are
of interest (in which case cbfn must be provided).

Return is the callback verdict on success ("stop", "continue", or "stolen") and
nil,emsg,errno on failure.
*/
/* TODO - will "failure" cause errno to be set? What will really happen? */
static int catch(lua_State* L)
{
    struct nfct_handle* cthandle = check_cthandle(L);
    int ret;

    /* Ensure that the callbacks expectations about the stack are met. */
    if(lua_isnoneornil(L, 2)) {
        /* There is no cbfn, chop the stack so it contains only the handle. */
        lua_settop(L, 1);
    } else {
        /* Otherwise, ensure stack contains only cthandle,cbfn */
        luaL_checktype(L, 2, LUA_TFUNCTION);
        lua_settop(L, 2);
    }

    ret = nfct_catch(cthandle);

    if(ret < 0) {
        /* Replace whatever is on the return stack with nil, emsg, errno. */
        lua_settop(L, 0);
        push_error(L);
    } else {
        /* Leave just the cthandle on the return stack to indicate successs */
        lua_settop(L, 1);
    }

    return lua_gettop(L);
}

/*-
- nfct.loop(cthandle, ctmsgtype, cbfn)

Equivalent to

  nfct.callback_register(cthandle, ctmsgtype)
  return nfct.catch(cthandle, cbfn)

Registering callbacks repeatedly is unnecessarily slow, so this is best used on
blocking netlink sockets for scripts that do nothing but use the conntrack
subsystem.
*/
static int loop(lua_State* L)
{
    int nret = callback_register(L);

    if(nret > 1) {
        return nret;
    }

    /* Remove ctmsgtype so stack is (cthandle, cbfn), as expected by catch. */
    lua_remove(L, 2);

    return catch(L);
}

/*-
- ct = nfct.new()

Create a new conntrack context (NOT a conntrack handle).

No garbage collection on the context is done, it must be destroyed with
nfct.destroy() or resources will be leaked.

Return is the conntrack context on sucess, and nil,emsg,errno on failure (but
it can only fail if malloc fails).
*/

static int new(lua_State* L)
{
    struct nf_conntrack* ct = nfct_new();
    if(!ct) {
        push_error(L);
        return 3;
    }
    lua_pushlightuserdata(L, ct);
    return 1;
}

/*-
- nfct.destroy(ct)

Destroy a conntrack context.

Note that only contexts created with nfct.new() should be destroyed - in particular,
the ct passed in a nfct.loop() callback should NOT be destroyed.

*/
static int destroy(lua_State* L)
{
    struct nf_conntrack* ct = check_ct(L);
    nfct_destroy(ct);
    return 0;
}

/*-
- ct = nfct.setobjopt(ct, option)

Sets an option on a conntrack context, option is one of:
    "undo-snat",
    "undo-dnat",
    "undo-spat",
    "undo-dpat",
    "setup-original",
    "setup-reply"

Returns ct on success so calls can be chained, and nil,emsg,errno on failure.
*/
int setobjopt(lua_State* L)
{
    struct nf_conntrack* ct = check_ct(L);
    static const char* opts[] = {
        "undo-snat",
        "undo-dnat",
        "undo-spat",
        "undo-dpat",
        "setup-original",
        "setup-reply"
    };
    unsigned vals[] = {
        NFCT_SOPT_UNDO_SNAT,
        NFCT_SOPT_UNDO_DNAT,
        NFCT_SOPT_UNDO_SPAT,
        NFCT_SOPT_UNDO_DPAT,
        NFCT_SOPT_SETUP_ORIGINAL,
        NFCT_SOPT_SETUP_REPLY
    };
    unsigned option = vals[luaL_checkoption(L, 2, NULL, opts)];
    int ret = nfct_setobjopt(ct, option);
    if(ret < 0) {
        push_error(L);
        return 3;
    }
    return 1;
}

static const char* attr_opts[] = {
	"orig-ipv4-src",
	"orig-ipv4-dst",
	"repl-ipv4-src",
	"repl-ipv4-dst",
	"orig-ipv6-src",
	"orig-ipv6-dst",
	"repl-ipv6-src",
	"repl-ipv6-dst",
	"orig-port-src",
	"orig-port-dst",
	"repl-port-src",
	"repl-port-dst",
	"icmp-type",
	"icmp-code",
	"icmp-id",
	"orig-l3proto",
	"repl-l3proto",
	"orig-l4proto",
	"repl-l4proto",
	"tcp-state",
	"snat-ipv4",
	"dnat-ipv4",
	"snat-port",
	"dnat-port",
	"timeout",
	"mark",
	"orig-counter-packets",
	"repl-counter-packets",
	"orig-counter-bytes",
	"repl-counter-bytes",
	"use",
	"id",
	"status",
	"tcp-flags-orig",
	"tcp-flags-repl",
	"tcp-mask-orig",
	"tcp-mask-repl",
	"master-ipv4-src",
	"master-ipv4-dst",
	"master-ipv6-src",
	"master-ipv6-dst",
	"master-port-src",
	"master-port-dst",
	"master-l3proto",
	"master-l4proto",
	"secmark",
	"orig-nat-seq-correction-pos",
	"orig-nat-seq-offset-before",
	"orig-nat-seq-offset-after",
	"repl-nat-seq-correction-pos",
	"repl-nat-seq-offset-before",
	"repl-nat-seq-offset-after",
	"sctp-state",
	"sctp-vtag-orig",
	"sctp-vtag-repl",
	"helper-name",
	"dccp-state",
	"dccp-role",
	"dccp-handshake-seq",
};

enum nf_conntrack_attr attr_vals[] = {
	ATTR_ORIG_IPV4_SRC,
	ATTR_ORIG_IPV4_DST,
	ATTR_REPL_IPV4_SRC,
	ATTR_REPL_IPV4_DST,
	ATTR_ORIG_IPV6_SRC,
	ATTR_ORIG_IPV6_DST,
	ATTR_REPL_IPV6_SRC,
	ATTR_REPL_IPV6_DST,
	ATTR_ORIG_PORT_SRC,
	ATTR_ORIG_PORT_DST,
	ATTR_REPL_PORT_SRC,
	ATTR_REPL_PORT_DST,
	ATTR_ICMP_TYPE,
	ATTR_ICMP_CODE,
	ATTR_ICMP_ID,
	ATTR_ORIG_L3PROTO,
	ATTR_REPL_L3PROTO,
	ATTR_ORIG_L4PROTO,
	ATTR_REPL_L4PROTO,
	ATTR_TCP_STATE,
	ATTR_SNAT_IPV4,
	ATTR_DNAT_IPV4,
	ATTR_SNAT_PORT,
	ATTR_DNAT_PORT,
	ATTR_TIMEOUT,
	ATTR_MARK,
	ATTR_ORIG_COUNTER_PACKETS,
	ATTR_REPL_COUNTER_PACKETS,
	ATTR_ORIG_COUNTER_BYTES,
	ATTR_REPL_COUNTER_BYTES,
	ATTR_USE,
	ATTR_ID,
	ATTR_STATUS,
	ATTR_TCP_FLAGS_ORIG,
	ATTR_TCP_FLAGS_REPL,
	ATTR_TCP_MASK_ORIG,
	ATTR_TCP_MASK_REPL,
	ATTR_MASTER_IPV4_SRC,
	ATTR_MASTER_IPV4_DST,
	ATTR_MASTER_IPV6_SRC,
	ATTR_MASTER_IPV6_DST,
	ATTR_MASTER_PORT_SRC,
	ATTR_MASTER_PORT_DST,
	ATTR_MASTER_L3PROTO,
	ATTR_MASTER_L4PROTO,
	ATTR_SECMARK,
	ATTR_ORIG_NAT_SEQ_CORRECTION_POS,
	ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE,
	ATTR_ORIG_NAT_SEQ_OFFSET_AFTER,
	ATTR_REPL_NAT_SEQ_CORRECTION_POS,
	ATTR_REPL_NAT_SEQ_OFFSET_BEFORE,
	ATTR_REPL_NAT_SEQ_OFFSET_AFTER,
	ATTR_SCTP_STATE,
	ATTR_SCTP_VTAG_ORIG,
	ATTR_SCTP_VTAG_REPL,
	ATTR_HELPER_NAME,
	ATTR_DCCP_STATE,
	ATTR_DCCP_ROLE,
	ATTR_DCCP_HANDSHAKE_SEQ,
};

static enum nf_conntrack_attr check_attr(lua_State* L)
{
    int attr_opt = luaL_checkoption(L, 2, NULL, attr_opts);
    enum nf_conntrack_attr attr_val = attr_vals[attr_opt];
    return attr_val;
}

/*-
- value = nfct.get_attr_u8(ct, attr)
- value = nfct.get_attr_u16(ct, attr)
- value = nfct.get_attr_u32(ct, attr)

No error checking is done, values of zero will be returned for
attributes that aren't present, and undefined values will be returned
for attributes that aren't actually of the type requested. Also,
the attribute value may be in network byte order.

ct is a conntrack context (NOT a conntrack handle, do not mix the two).

attr is one of:
	"orig-ipv4-src",     		-- u32 bits
	"orig-ipv4-dst",		-- u32 bits
	"repl-ipv4-src",		-- u32 bits
	"repl-ipv4-dst",		-- u32 bits
	"orig-ipv6-src",     		-- u128 bits
	"orig-ipv6-dst",		-- u128 bits
	"repl-ipv6-src",		-- u128 bits
	"repl-ipv6-dst",		-- u128 bits
	"orig-port-src",     		-- u16 bits
	"orig-port-dst",		-- u16 bits
	"repl-port-src",		-- u16 bits
	"repl-port-dst",		-- u16 bits
	"icmp-type",     		-- u8 bits
	"icmp-code",			-- u8 bits
	"icmp-id",			-- u16 bits
	"orig-l3proto",			-- u8 bits
	"repl-l3proto",     		-- u8 bits
	"orig-l4proto",			-- u8 bits
	"repl-l4proto",			-- u8 bits
	"tcp-state",			-- u8 bits
	"snat-ipv4",     		-- u32 bits
	"dnat-ipv4",			-- u32 bits
	"snat-port",			-- u16 bits
	"dnat-port",			-- u16 bits
	"timeout",     			-- u32 bits
	"mark",				-- u32 bits
	"orig-counter-packets",		-- u32 bits
	"repl-counter-packets",		-- u32 bits
	"orig-counter-bytes",    	-- u32 bits
	"repl-counter-bytes",		-- u32 bits
	"use",				-- u32 bits
	"id",				-- u32 bits
	"status",     			-- u32 bits 
	"tcp-flags-orig",		-- u8 bits
	"tcp-flags-repl",		-- u8 bits
	"tcp-mask-orig",		-- u8 bits
	"tcp-mask-repl",     		-- u8 bits
	"master-ipv4-src",		-- u32 bits
	"master-ipv4-dst",		-- u32 bits
	"master-ipv6-src",		-- u128 bits
	"master-ipv6-dst",     		-- u128 bits
	"master-port-src",		-- u16 bits
	"master-port-dst",		-- u16 bits
	"master-l3proto",		-- u8 bits
	"master-l4proto",     		-- u8 bits
	"secmark",			-- u32 bits
	"orig-nat-seq-correction-pos",	-- u32 bits
	"orig-nat-seq-offset-before",	-- u32 bits
	"orig-nat-seq-offset-after",    -- u32 bits
	"repl-nat-seq-correction-pos",	-- u32 bits
	"repl-nat-seq-offset-before",	-- u32 bits
	"repl-nat-seq-offset-after",	-- u32 bits
	"sctp-state",     		-- u8 bits
	"sctp-vtag-orig",		-- u32 bits
	"sctp-vtag-repl",		-- u32 bits
	"helper-name",			-- string (30 bytes max)
	"dccp-state",     		-- u8 bits
	"dccp-role",			-- u8 bits
	"dccp-handshake-seq",		-- u64 bits

See enum nf_conntrack_attr (the aliases are not supported)
*/
/* TODO this could have a much better API, but I've no time for this now. */

/*-
- ct = nfct.set_attr_u8(ct, attr, value)
- ct = nfct.set_attr_u16(ct, attr, value)
- ct = nfct.set_attr_u32(ct, attr, value)

No error checking is done, value will be cast to the necessary type, and who
knows what will happen for values that aren't actually of the correct type for
the attribute. The attribute value may need to be in network byte order.

ct is a conntrack context (NOT a conntrack handle, do not mix the two).

See nfct.get_attr_*() for the supported attr names.

Returns the conntrack conntext, so calls can be chained.
*/

/*
static int get_attr_u8(lua_State* L)
{
    lua_pushinteger(L, nfct_get_attr_u8(check_ct(L), check_attr(L)));
    return 1;
}
*/

#define ATTR_UX(ux) \
static int get_attr_##ux(lua_State* L) \
{ lua_pushinteger(L, nfct_get_attr_##ux(check_ct(L), check_attr(L))); return 1; } \
static int set_attr_##ux(lua_State* L) \
{ nfct_set_attr_##ux(check_ct(L), check_attr(L), luaL_checklong(L,3)); return 1; }

ATTR_UX(u8)
ATTR_UX(u16)
ATTR_UX(u32)

/*-
- h = nfct.ntohs(n)
- n = nfct.htons(h)

Convert a short between network and host byte order.  No error or bounds
checking on the numbers is done.
*/
static int ctntohs(lua_State* L)
{
    lua_pushinteger(L, ntohs(luaL_checkint(L, 1)));
    return 1;
}

static int cthtons(lua_State* L)
{
    lua_pushinteger(L, htons(luaL_checkint(L, 1)));
    return 1;
}

static const luaL_reg nfct[] =
{
    /* return or operate on cthandle */
    {"open",            open},
    {"close",           gc},
    {"fd",              fd},
    {"callback_register", callback_register},
    {"catch",           catch},
    {"loop",            loop},

    /* return or operate on ct */
    {"new",             new},
    {"destroy",         destroy},
    {"setobjopt",       destroy},
    {"get_attr_u8",     get_attr_u8},
    {"get_attr_u16",    get_attr_u16},
    {"get_attr_u32",    get_attr_u32},
    {"set_attr_u8",     set_attr_u8},
    {"set_attr_u16",    set_attr_u16},
    {"set_attr_u32",    set_attr_u32},

    /* attr value conversion */
    {"ntohs",           ctntohs},
    {"htons",           cthtons},
    {NULL, NULL}
};

LUALIB_API int luaopen_nfct (lua_State *L)
{
    /* These tables are long, and must agree in length or chaos will ensue,
     * chaos now is better than chaos later.
     */
    assert(sizeof(attr_opts) == sizeof(attr_vals));

    luaL_register(L, "nfct", nfct);

    return 1;
}

