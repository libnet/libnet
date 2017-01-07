/*
 *  libnet_test.h
 *
 *  Copyright (c) 1998 - 2001 Mike D. Schiffman <mike@infonexus.com>
 */

#ifndef __LIBNET_TEST_H
#define __LIBNET_TEST_H

#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif

#include "../include/libnet.h"

#if !defined(__WIN32__)
# include <netinet/in.h>
#endif

#define libnet_timersub(tvp, uvp, vvp)                                  \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)

u_char enet_src[6] = {0x0d, 0x0e, 0x0a, 0x0d, 0x00, 0x00};
u_char enet_dst[6] = {0x00, 0x10, 0x67, 0x00, 0xb1, 0x86};
u_char ip_src[4]   = {0x0a, 0x00, 0x00, 0x01};
u_char ip_dst[4]   = {0x0a, 0x00, 0x00, 0x02};
u_char fddi_src[6] = {0x00, 0x0d, 0x0e, 0x0a, 0x0d, 0x00};
u_char fddi_dst[6] = {0x00, 0x10, 0x67, 0x00, 0xb1, 0x86};
u_char tr_src[6]   = {0x00, 0x0d, 0x0e, 0x0a, 0x0d, 0x00};
u_char tr_dst[6]   = {0x00, 0x10, 0x67, 0x00, 0xb1, 0x86};

u_char org_code[3] = {0x00, 0x00, 0x00};

void usage(char *);

#if defined(__WIN32__)
  #include <getopt.h>  /* For non-MingW, this is a local libnet/win32/getopt.h */
  #include <winsock2.h>
  #include <ws2tcpip.h>

  #ifndef _MSC_VER
  #include <sys/time.h>
  #endif
#endif  /* __WIN32__ */

#endif  /* __LIBNET_TEST_H */

/* EOF */