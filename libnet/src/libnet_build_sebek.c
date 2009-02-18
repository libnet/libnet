/*
 *  libnet
 *  libnet_build_sebek.c - sebek packet assembler
 *
 *  Copyright (c) 2004 Frederic Raynal <pappy@security-labs.org>
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif
#if (!(_WIN32) || (__CYGWIN__)) 
#include "../include/libnet.h"
#else
#include "../include/win32/libnet.h"
#endif

libnet_ptag_t
libnet_build_sebek(u_int32_t magic, u_int16_t version, u_int16_t type, 
u_int32_t counter, u_int32_t time_sec, u_int32_t time_usec, u_int32_t pid,
u_int32_t uid, u_int32_t fd, u_int8_t cmd[SEBEK_CMD_LENGTH], u_int32_t length,
u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
    u_int32_t n;
    libnet_pblock_t *p;
    struct libnet_sebek_hdr sebek_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 

    n = LIBNET_SEBEK_H + payload_s;               /* size of memory block */

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_SEBEK_H);
    if (p == NULL)
    {
        return (-1);
    }

    memset(&sebek_hdr, 0, sizeof(sebek_hdr));
    sebek_hdr.magic     = htonl(magic);
    sebek_hdr.version   = htons(version);
    sebek_hdr.type      = htons(type);
    sebek_hdr.counter   = htonl(counter);
    sebek_hdr.time_sec  = htonl(time_sec);
    sebek_hdr.time_usec = htonl(time_usec);
    sebek_hdr.pid       = htonl(pid);
    sebek_hdr.uid       = htonl(uid);
    sebek_hdr.fd        = htonl(fd);
    memcpy(sebek_hdr.cmd, cmd, SEBEK_CMD_LENGTH*sizeof(u_int8_t));
    sebek_hdr.length = htonl(length);

    n = libnet_pblock_append(l, p, (u_int8_t *)&sebek_hdr, LIBNET_SEBEK_H);
    if (n == -1)
    {
        goto bad;
    }

    /* boilerplate payload sanity check / append macro */
    LIBNET_DO_PAYLOAD(l, p);
 
    return (ptag ? ptag : libnet_pblock_update(l, p, 0, LIBNET_PBLOCK_SEBEK_H));
bad:
    libnet_pblock_delete(l, p);
    return (-1);
}
/* EOF */
