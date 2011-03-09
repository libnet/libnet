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
called on different kinds of objects mixed together, but unless I make full
userdata out of one or both of them, thats what it has to be. Don't confuse
them, or you will segfault!
*/

#define WANT_NF_LUA_PF
#define WANT_NF_LUA_PF_PUSH
#define WANT_NF_LUA_IPPROTO
#include "nflua.h"

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#define NFCT_REGID "wt.nfct"


static struct nfct_handle* check_cthandle(lua_State*L)
{
    struct nfct_handle* cth = lua_touserdata(L, 1);

    luaL_argcheck(L, cth, 1, "conntrack handle not provided");

    return cth;
}

static struct nf_conntrack* check_ct_argn(lua_State*L, int argn, const char* emsg)
{
    struct nf_conntrack* ct = lua_touserdata(L, 1);

    luaL_argcheck(L, ct, argn, emsg);

    return ct;
}

static struct nf_conntrack* check_ct(lua_State*L)
{
    return check_ct_argn(L, 1, "conntrack not provided");
}

static struct nf_expect* check_exp(lua_State* L, int argn)
{
    struct nf_expect* exp = lua_touserdata(L, argn);

    luaL_argcheck(L, exp, argn, "expect not provided");

    return exp;
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


static const char* ATTR_opts[] = {
  "orig-ipv4-src",
  "ipv4-src",
  "orig-ipv4-dst",
  "ipv4-dst",
  "repl-ipv4-src",
  "repl-ipv4-dst",
  "orig-ipv6-src",
  "ipv6-src",
  "orig-ipv6-dst",
  "ipv6-dst",
  "repl-ipv6-src",
  "repl-ipv6-dst",
  "orig-port-src",
  "port-src",
  "orig-port-dst",
  "port-dst",
  "repl-port-src",
  "repl-port-dst",
  "icmp-type",
  "icmp-code",
  "icmp-id",
  "orig-l3proto",
  "l3proto",
  "repl-l3proto",
  "orig-l4proto",
  "l4proto",
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
  "grp-orig-ipv4",
  "grp-repl-ipv4",
  "grp-orig-ipv6",
  "grp-repl-ipv6",
  "grp-orig-port",
  "grp-repl-port",
  "grp-icmp",
  "grp-master-ipv4",
  "grp-master-ipv6",
  "grp-master-port",
  "grp-orig-counters",
  "grp-repl-counters",
  "grp-max",
  "exp-master",
  "exp-expected",
  "exp-mask",
  "exp-timeout",
  "exp-max",
  NULL
};

static int ATTR_vals[] = {
  ATTR_ORIG_IPV4_SRC,
  ATTR_IPV4_SRC,
  ATTR_ORIG_IPV4_DST,
  ATTR_IPV4_DST,
  ATTR_REPL_IPV4_SRC,
  ATTR_REPL_IPV4_DST,
  ATTR_ORIG_IPV6_SRC,
  ATTR_IPV6_SRC,
  ATTR_ORIG_IPV6_DST,
  ATTR_IPV6_DST,
  ATTR_REPL_IPV6_SRC,
  ATTR_REPL_IPV6_DST,
  ATTR_ORIG_PORT_SRC,
  ATTR_PORT_SRC,
  ATTR_ORIG_PORT_DST,
  ATTR_PORT_DST,
  ATTR_REPL_PORT_SRC,
  ATTR_REPL_PORT_DST,
  ATTR_ICMP_TYPE,
  ATTR_ICMP_CODE,
  ATTR_ICMP_ID,
  ATTR_ORIG_L3PROTO,
  ATTR_L3PROTO,
  ATTR_REPL_L3PROTO,
  ATTR_ORIG_L4PROTO,
  ATTR_L4PROTO,
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
  ATTR_GRP_ORIG_IPV4,
  ATTR_GRP_REPL_IPV4,
  ATTR_GRP_ORIG_IPV6,
  ATTR_GRP_REPL_IPV6,
  ATTR_GRP_ORIG_PORT,
  ATTR_GRP_REPL_PORT,
  ATTR_GRP_ICMP,
  ATTR_GRP_MASTER_IPV4,
  ATTR_GRP_MASTER_IPV6,
  ATTR_GRP_MASTER_PORT,
  ATTR_GRP_ORIG_COUNTERS,
  ATTR_GRP_REPL_COUNTERS,
  ATTR_GRP_MAX,
  ATTR_EXP_MASTER,
  ATTR_EXP_EXPECTED,
  ATTR_EXP_MASK,
  ATTR_EXP_TIMEOUT,
  ATTR_EXP_MAX,
};

/*static int ATTR_vals_size = 85;*/
static int check_ATTR(lua_State* L, int argn)
{
  int opt = luaL_checkoption(L, argn, NULL /* default? */, ATTR_opts);
  int val = ATTR_vals[opt];
  return val;
}

static enum nf_conntrack_attr check_attr(lua_State* L)
{
    return check_ATTR(L, 2);
}


static const char* NFCT_Q_opts[] = {
  "create",
  "update",
  "destroy",
  "get",
  "flush",
  "dump",
  "dump-reset",
  "create-update",
  NULL
};

static int NFCT_Q_vals[] = {
  NFCT_Q_CREATE,
  NFCT_Q_UPDATE,
  NFCT_Q_DESTROY,
  NFCT_Q_GET,
  NFCT_Q_FLUSH,
  NFCT_Q_DUMP,
  NFCT_Q_DUMP_RESET,
  NFCT_Q_CREATE_UPDATE,
};

/*static int NFCT_Q_vals_size = 8;*/
static int check_NFCT_Q(lua_State* L, int argn)
{
  int opt = luaL_checkoption(L, argn, NULL /* default? */, NFCT_Q_opts);
  int val = NFCT_Q_vals[opt];
  return val;
}


/*-
-- cthandle = nfct.open(subsys, [subscription...])

subsys is "track" or "expect"

subscription is the groups for which notifications are requested, zero or more of
"none", "new", "update", "destroy", or "all" (default is "none").

Returns a conntrack handle on success, or nil,emsg,errno on failure.

There is no garbage collection, nfct.fini() must be called on the handle to
release it's resources.
*/
static int hopen(lua_State *L)
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
        int subscription_opt = luaL_checkoption(L, narg, NULL, subscription_opts);
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
-- nfct.close(cthandle)

Close the conntrack handle, freeing its resources.
*/
static int gc(lua_State* L)
{
    struct nfct_handle* cthandle = check_cthandle(L);
    nfct_close(cthandle);
    return 0;
}

/*-
-- fd = nfct.fd(cthandle)

Return the underlying fd used by the conntrack handle, useful for
selecting on.
*/
static int fd(lua_State* L)
{
    struct nfct_handle* cthandle = check_cthandle(L);
    lua_pushinteger(L, nfct_fd(cthandle));
    return 1;
}

/*-
-- cthandle = nfct.setblocking(cthandle, [blocking])

blocking is true to set blocking, and false to set non-blocking (default is false)

Return is cthandle on success, or nil,emsg,errno on failure.
*/
static int setblocking(lua_State* L)
{
    return nfsetblocking(L, nfct_fd(check_cthandle(L)));
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
-- cthandle = nfct.callback_register(cthandle, ctmsgtype)

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
-- cthandle = nfct.catch(cthandle, cbfn)
-- verdict = cbfn(ctmsgtype, ct)

cbfn - the callback function, and will be called as

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
-- nfct.loop(cthandle, ctmsgtype, cbfn)

Equivalent to

  nfct.callback_register(cthandle, ctmsgtype)
  return nfct.catch(cthandle, cbfn)

Registering callbacks repeatedly is unnecessarily slow, so this is best used on
blocking netlink sockets by scripts that use only the conntrack subsystem.
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
-- ct = nfct.new()

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
-- nfct.destroy(ct)

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
-- ct = nfct.setobjopt(ct, option)

Sets an option on a conntrack context, option is one of:
    "undo-snat",
    "undo-dnat",
    "undo-spat",
    "undo-dpat",
    "setup-original",
    "setup-reply"

Returns ct on success so calls can be chained, and nil,emsg,errno on failure.
*/
static int setobjopt(lua_State* L)
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

    lua_settop(L, 1);

    return 1;
}

/*
   TODO
   get_attr_ip() -- ip in presentation format
   get_attr_port() -- port as a number (cvt to host byte order)
   get_attr_l3proto() -- protocol as string (or number if unrecognized)
   get_attr_l4proto() -- "" ""
*/
/*-
-- value = nfct.get_attr_u8(ct, attr)
-- value = nfct.get_attr_u16(ct, attr)
-- value = nfct.get_attr_u32(ct, attr)
-- value = nfct.get_attr_n16(ct, attr)
-- value = nfct.get_attr_n32(ct, attr)
-- value = nfct.get_attr_port(ct, attr)

No error checking is done, values of zero will be returned for
attributes that aren't present, and undefined values will be returned
for attributes that aren't actually of the type requested. Also,
the attribute value may be in network byte order.

ct is a conntrack context (NOT a conntrack handle, do not mix the two).

get_attr_n#() is like the "u" version, but it converts the number from network
to host byte order.

get_attr_port() is an alias for get_attr_n16(), since TCP and UDP ports are n16.

attr is one of the enum nf_conntrack_attr values, where some aliases are
provided for the more commonly used origin attributes:
  orig-ipv4-src                -- ATTR_ORIG_IPV4_SRC, u32 bits
  ipv4-src                     -- ATTR_IPV4_SRC, alias
  orig-ipv4-dst                -- ATTR_ORIG_IPV4_DST, u32 bits
  ipv4-dst                     -- ATTR_IPV4_DST, alias
  repl-ipv4-src                -- ATTR_REPL_IPV4_SRC, u32 bits
  repl-ipv4-dst                -- ATTR_REPL_IPV4_DST, u32 bits
  orig-ipv6-src                -- ATTR_ORIG_IPV6_SRC, u128 bits
  ipv6-src                     -- ATTR_IPV6_SRC, alias
  orig-ipv6-dst                -- ATTR_ORIG_IPV6_DST, u128 bits
  ipv6-dst                     -- ATTR_IPV6_DST, alias
  repl-ipv6-src                -- ATTR_REPL_IPV6_SRC, u128 bits
  repl-ipv6-dst                -- ATTR_REPL_IPV6_DST, u128 bits
  orig-port-src                -- ATTR_ORIG_PORT_SRC, u16 bits
  port-src                     -- ATTR_PORT_SRC, alias
  orig-port-dst                -- ATTR_ORIG_PORT_DST, u16 bits
  port-dst                     -- ATTR_PORT_DST, alias
  repl-port-src                -- ATTR_REPL_PORT_SRC, u16 bits
  repl-port-dst                -- ATTR_REPL_PORT_DST, u16 bits
  icmp-type                    -- ATTR_ICMP_TYPE, u8 bits
  icmp-code                    -- ATTR_ICMP_CODE, u8 bits
  icmp-id                      -- ATTR_ICMP_ID, u16 bits
  orig-l3proto                 -- ATTR_ORIG_L3PROTO, u8 bits
  l3proto                      -- ATTR_L3PROTO, alias
  repl-l3proto                 -- ATTR_REPL_L3PROTO, u8 bits
  orig-l4proto                 -- ATTR_ORIG_L4PROTO, u8 bits
  l4proto                      -- ATTR_L4PROTO, alias
  repl-l4proto                 -- ATTR_REPL_L4PROTO, u8 bits
  tcp-state                    -- ATTR_TCP_STATE, u8 bits
  snat-ipv4                    -- ATTR_SNAT_IPV4, u32 bits
  dnat-ipv4                    -- ATTR_DNAT_IPV4, u32 bits
  snat-port                    -- ATTR_SNAT_PORT, u16 bits
  dnat-port                    -- ATTR_DNAT_PORT, u16 bits
  timeout                      -- ATTR_TIMEOUT, u32 bits
  mark                         -- ATTR_MARK, u32 bits
  orig-counter-packets         -- ATTR_ORIG_COUNTER_PACKETS, u32 bits
  repl-counter-packets         -- ATTR_REPL_COUNTER_PACKETS, u32 bits
  orig-counter-bytes           -- ATTR_ORIG_COUNTER_BYTES, u32 bits
  repl-counter-bytes           -- ATTR_REPL_COUNTER_BYTES, u32 bits
  use                          -- ATTR_USE, u32 bits
  id                           -- ATTR_ID, u32 bits
  status                       -- ATTR_STATUS, u32 bits
  tcp-flags-orig               -- ATTR_TCP_FLAGS_ORIG, u8 bits
  tcp-flags-repl               -- ATTR_TCP_FLAGS_REPL, u8 bits
  tcp-mask-orig                -- ATTR_TCP_MASK_ORIG, u8 bits
  tcp-mask-repl                -- ATTR_TCP_MASK_REPL, u8 bits
  master-ipv4-src              -- ATTR_MASTER_IPV4_SRC, u32 bits
  master-ipv4-dst              -- ATTR_MASTER_IPV4_DST, u32 bits
  master-ipv6-src              -- ATTR_MASTER_IPV6_SRC, u128 bits
  master-ipv6-dst              -- ATTR_MASTER_IPV6_DST, u128 bits
  master-port-src              -- ATTR_MASTER_PORT_SRC, u16 bits
  master-port-dst              -- ATTR_MASTER_PORT_DST, u16 bits
  master-l3proto               -- ATTR_MASTER_L3PROTO, u8 bits
  master-l4proto               -- ATTR_MASTER_L4PROTO, u8 bits
  secmark                      -- ATTR_SECMARK, u32 bits
  orig-nat-seq-correction-pos  -- ATTR_ORIG_NAT_SEQ_CORRECTION_POS, u32 bits
  orig-nat-seq-offset-before   -- ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE, u32 bits
  orig-nat-seq-offset-after    -- ATTR_ORIG_NAT_SEQ_OFFSET_AFTER, u32 bits
  repl-nat-seq-correction-pos  -- ATTR_REPL_NAT_SEQ_CORRECTION_POS, u32 bits
  repl-nat-seq-offset-before   -- ATTR_REPL_NAT_SEQ_OFFSET_BEFORE, u32 bits
  repl-nat-seq-offset-after    -- ATTR_REPL_NAT_SEQ_OFFSET_AFTER, u32 bits
  sctp-state                   -- ATTR_SCTP_STATE, u8 bits
  sctp-vtag-orig               -- ATTR_SCTP_VTAG_ORIG, u32 bits
  sctp-vtag-repl               -- ATTR_SCTP_VTAG_REPL, u32 bits
  helper-name                  -- ATTR_HELPER_NAME, string (30 bytes max)
  dccp-state                   -- ATTR_DCCP_STATE, u8 bits
  dccp-role                    -- ATTR_DCCP_ROLE, u8 bits
  dccp-handshake-seq           -- ATTR_DCCP_HANDSHAKE_SEQ, u64 bits

*/

/*-
-- ct = nfct.set_attr_u8(ct, attr, value)
-- ct = nfct.set_attr_u16(ct, attr, value)
-- ct = nfct.set_attr_u32(ct, attr, value)
-- ct = nfct.set_attr_n16(ct, attr, value)
-- ct = nfct.set_attr_n32(ct, attr, value)
-- ct = nfct.set_attr_port(ct, attr, value)

No error checking is done, value will be cast to the necessary type, and who
knows what will happen for values that aren't actually of the correct type for
the attribute. The attribute value may need to be in network byte order.

ct is a conntrack context (NOT a conntrack handle, do not mix the two).

See nfct.get_attr_*() for the supported attr names and types.

Returns the conntrack conntext, so calls can be chained.
*/

/* Pretent nfct implements these, so I can construct setters/getters using my macro. */
static u_int16_t nfct_get_attr_n16(struct nf_conntrack* ct, enum nf_conntrack_attr attr)
{
    return ntohs(nfct_get_attr_u16(ct, attr));
}
static u_int32_t nfct_get_attr_n32(struct nf_conntrack* ct, enum nf_conntrack_attr attr)
{
    return ntohl(nfct_get_attr_u32(ct, attr));
}
static void nfct_set_attr_n16(struct nf_conntrack* ct, enum nf_conntrack_attr attr, u_int16_t value)
{
    nfct_set_attr_u16(ct, attr, htons(value));
}
static void nfct_set_attr_n32(struct nf_conntrack* ct, enum nf_conntrack_attr attr, u_int32_t value)
{
    nfct_set_attr_u32(ct, attr, htonl(value));
}

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
{ nfct_set_attr_##ux(check_ct(L), check_attr(L), luaL_checklong(L,3)); lua_settop(L, 1); return 1; }

/* should I add checks for existence of the attribute? I doubt performance is
 * an issue, so why not return
 * nil and emsg when attr isn't present
 */

ATTR_UX(u8)
ATTR_UX(u16)
ATTR_UX(u32)
ATTR_UX(n16)
ATTR_UX(n32)

/*-
-- ct = nfct.set_attr_ipv4(ct, attr, value)

Get an attribute as a string, the internet address in presentation format.

See inet_ntop(3) for more information.

Return is the presentation address, or nil,emsg,errno on failure.
*/
static int get_attr_ipvx(lua_State* L, int af, const void* src)
{
    char dst[INET6_ADDRSTRLEN];
    const char* p = inet_ntop(af, src, dst, sizeof(dst));
    if(!p)  {
        return push_error(L);
    }
    lua_pushstring(L, p);
    return 1;
}

static int get_attr_ipv4(lua_State* L)
{
    return get_attr_ipvx(L,
            AF_INET,
            nfct_get_attr(check_ct(L), check_attr(L)));
}

static int get_attr_ipv6(lua_State* L)
{
    return get_attr_ipvx(L,
            AF_INET6,
            nfct_get_attr(check_ct(L), check_attr(L)));
}

/*-
-- ct = nfct.set_attr_ipv4(ct, attr, value)
-- ct = nfct.set_attr_ipv6(ct, attr, value)

Set an attribute as a string, the internet address in presentation format.

See inet_ntop(3) for more information.

Returns the conntrack conntext, so calls can be chained.
*/
static int set_attr_ipvx(lua_State* L, int af)
{
    unsigned char buf[sizeof(struct in6_addr)];

    if(!inet_pton(af, luaL_checkstring(L, 3), buf)) {
        return push_error(L);
    }

    nfct_set_attr(check_ct(L), check_attr(L), buf);

    lua_settop(L, 1);

    return 1;
}

static int set_attr_ipv4(lua_State* L)
{
    return set_attr_ipvx(L, AF_INET);
}

static int set_attr_ipv6(lua_State* L)
{
    return set_attr_ipvx(L, AF_INET6);
}

/*-
-- value = nfct.get_attr_pf(ct, attr)
-- ct = nfct.set_attr_pf(ct, attr, value)

Set or get attributes with address family/protocol values as a string, for
example, the "l3proto".

The address families, such as AF_INET and AF_INET6, are defined in the system
headers to be identical to the equivalent protocol family.

Value is one of:
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

Get returns the value as a string if it is known, or a number if it is not.

Set returns the conntrack conntext, so calls can be chained.
*/
static int get_attr_pf(lua_State* L)
{
    push_PF(L,
            nfct_get_attr_u8(check_ct(L), check_attr(L)));
    return 1;
}
static int set_attr_pf(lua_State* L)
{
    nfct_set_attr_u8(
            check_ct(L),
            check_attr(L),
            check_PF(L,3));
    lua_settop(L, 1);
    return 1;
}

/*-
-- value = nfct.get_attr_ipproto(ct, attr)
-- ct = nfct.set_attr_ipproto(ct, attr, value)

Set or get attributes with IP protocol values as a string, for example, the
"l4proto" attribute if the "l3proto" is "inet" or "inet6".

Value is one of:

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

Get returns the value as a string if it is known, or a number if it is not.

Set returns the conntrack conntext, so calls can be chained.
*/
static int get_attr_ipproto(lua_State* L)
{
    push_IPPROTO(L,
            nfct_get_attr_u8(check_ct(L), check_attr(L)));
    return 1;
}
static int set_attr_ipproto(lua_State* L)
{
    nfct_set_attr_u8(
            check_ct(L),
            check_attr(L),
            check_IPPROTO(L,3));
    lua_settop(L, 1);
    return 1;
}

static int exp_new(lua_State* L)
{
    struct nf_expect* exp = nfexp_new();

    if(!exp) {
        return push_error(L);
    }

    lua_pushlightuserdata(L, exp);

    lua_insert(L, 1);

    /*
     * [1] exp
     * [2] master
     * [3] expected
     * [4] mask
     * [5] timeout
     */
    switch(lua_gettop(L)) {
        case 5: nfexp_set_attr_u32(exp, ATTR_EXP_TIMEOUT, luaL_checklong(L, 5));
        case 4: nfexp_set_attr(exp, ATTR_EXP_MASK,     check_ct_argn(L, 4, "mask"));
        case 3: nfexp_set_attr(exp, ATTR_EXP_EXPECTED, check_ct_argn(L, 3, "expected"));
        case 2: nfexp_set_attr(exp, ATTR_EXP_MASTER,   check_ct_argn(L, 2, "master"));
    }

    lua_settop(L, 1);

    return 1;
}

static int exp_destroy(lua_State* L)
{
    struct nf_expect* exp = check_exp(L, 1);

    nfexp_destroy(exp);

    return 0;
}

/*-
-- cthandle = nfct.exp_query(cthandle, qtype, data)

Currently, only create and destroy is supported.

  create         -- NFCT_Q_CREATE, data must be an exp object
  update         -- NFCT_Q_UPDATE
  destroy        -- NFCT_Q_DESTROY, data must be an exp object
  get            -- NFCT_Q_GET
  flush          -- NFCT_Q_FLUSH
  dump           -- NFCT_Q_DUMP
  dump-reset     -- NFCT_Q_DUMP_RESET
  create-update  -- NFCT_Q_CREATE_UPDATE
*/
static int exp_query(lua_State* L)
{
    struct nfct_handle* h = check_cthandle(L);
    enum nf_conntrack_query qt = check_NFCT_Q(L, 2);
    int eret;

    /* this api is hideous, the documentation of the types required is incomplete, and buried
       deep
       */
    switch(qt) {
        case NFCT_Q_CREATE:
        case NFCT_Q_DESTROY:
            eret = nfexp_query(h, qt, check_exp(L, 3));
            break;
        default:
            return luaL_argerror(L, 2, "unsupported query type");
    }

    if(eret < 0) {
        return push_error(L);
    }

    lua_settop(L, 1);

    return 1;
}


/*-
-- h = nfct.ntohs(n)
-- n = nfct.htons(h)

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
    {"open",            hopen},
    {"close",           gc},
    {"fd",              fd},
    {"setblocking",     setblocking},
    {"callback_register", callback_register},
    {"catch",           catch},
    {"loop",            loop},

    /* return or operate on ct */
    {"new",             new},
    {"destroy",         destroy},
    {"setobjopt",       setobjopt},
    {"get_attr_u8",     get_attr_u8},
    {"get_attr_u16",    get_attr_u16},
    {"get_attr_u32",    get_attr_u32},
    {"set_attr_u8",     set_attr_u8},
    {"set_attr_u16",    set_attr_u16},
    {"set_attr_u32",    set_attr_u32},

    {"get_attr_n16",    get_attr_n16},
    {"get_attr_n32",    get_attr_n32},
    {"set_attr_n16",    set_attr_n16},
    {"set_attr_n32",    set_attr_n32},

    /* TODO should probably use service names as strings */
    {"get_attr_port",   get_attr_n16},
    {"set_attr_port",   set_attr_n16},

    {"get_attr_ipv4",   get_attr_ipv4},
    {"get_attr_ipv6",   get_attr_ipv6},
    {"set_attr_ipv4",   set_attr_ipv4},
    {"set_attr_ipv6",   set_attr_ipv6},

    {"get_attr_ipproto",get_attr_ipproto},
    {"set_attr_ipproto",set_attr_ipproto},

    {"get_attr_pf",     get_attr_pf},
    {"set_attr_pf",     set_attr_pf},

    /* return or operate on a exp */
    {"exp_new",         exp_new},
    {"exp_destroy",     exp_destroy},
    {"exp_query",       exp_query},

    /* attr value conversion */
    {"ntohs",           ctntohs},
    {"htons",           cthtons},
    {NULL, NULL}
};

LUALIB_API int luaopen_nfct (lua_State *L)
{
    luaL_register(L, "nfct", nfct);

    return 1;
}

