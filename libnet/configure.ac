dnl
dnl Libnet autoconfiguration information file
dnl Copyright (c) 1998 - 2002 Mike D. Schiffman <mike@infonexus.com>
dnl Modified by Ali Abdulkadir <autostart.ini@gmail.com>
dnl All rights reserved.
dnl
dnl Process this file with autoconf to produce a configure script.

AC_INIT(
    [libnet],
    [1.2-rc3],
    [autostart.ini@gmail.com],
    [libnet],
    [https://github.com/sgeto/libnet])

AC_CONFIG_AUX_DIR([build-aux])

dnl the autotools and libtool should be at least these versions
AC_PREREQ([2.69])
LT_PREREQ([2.4.2])

AC_COPYRIGHT([Copyright 1998 - 2017 The libnet Developer Community])
AC_MSG_RESULT(Beginning autoconfiguration process for libnet-${PACKAGE_VERSION} ...)

dnl test and adjust for Android (this needs to happen quite early)
dnl In the future, if we want to support other architectures/compilers as well,
dnl we should consider using AC_CANONICAL_BUILD instead
if test "${SHELL}" = "/bin/sh" -a "$build" = "armv7a--linux-android"; then
    AC_MSG_NOTICE([Setting the correct SHELL variable for Android...])
    SHELL=/data/data/com.termux/files/usr/bin/sh
fi

AC_CANONICAL_TARGET
AC_CONFIG_SRCDIR([src/libnet_build_ip.c])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.14 foreign no-dependencies nostdinc tar-ustar dist-zip])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([include/config.h])
AM_MAINTAINER_MODE

dnl the default compiler flags are "-O2 -g" if the user does not set anything.
dnl IMO O2 optimizations are fine, but debugging should be up to the user.
: ${CFLAGS="-O2"}

dnl Check for the usual programs
AC_PROG_CC
AC_PROG_INSTALL
AC_USE_SYSTEM_EXTENSIONS
dnl The default is to use only PIC objects.
dnl This can still be overwritten with --without-pic
LT_INIT([pic-only])

AC_CHECK_HEADERS(sys/sockio.h)
AC_CHECK_FUNCS([gethostbyname2])
AC_CHECK_FUNCS([getifaddrs])
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

AC_MSG_CHECKING(for socklen_t)
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <sys/types.h>
        #include <sys/socket.h>
        ]], [[ socklen_t x; ]])],[have_socklen_t=yes],[have_socklen_t=no])
if test "x$have_socklen_t" = "xyes"; then
        AC_DEFINE(HAVE_SOCKLEN_T, 1, [define if socklen_t is defined])
fi
AC_MSG_RESULT($have_socklen_t)

dnl
dnl And some custom things
dnl

AC_LIBNET_ENDIAN_CHECK
dnl AC_LBL_LIBRARY_NET
AC_SUBST(ENDIANESS)
AC_SUBST(HAVE_PACKET_SOCKET)
AC_SUBST(ADDITIONAL_LIBS)
AC_SUBST(LIBNET_CONFIG_DEFINES)
AC_SUBST(LIBNET_CONFIG_LIBS)
dnl FIXME this variable is unused
AC_SUBST(LIBNET_CONFIG_CFLAGS)
AC_SUBST(LTLIBOBJS)

dnl
dnl Set the root install directory
if test "${prefix}" = "NONE"; then
    prefix=/usr/local
fi
if test "${exec_prefix}" = "NONE"; then
    exec_prefix=$prefix
fi
dnl libdir must be a fully qualified path (not ${exec_prefix}/lib)
eval libdir="$libdir"

dnl Get link-layer interface type
AC_ARG_WITH(
	[link-layer],
	[AS_HELP_STRING([--with-link-layer],[when cross-compiling, one of * from libnet_link_*.c @<:@autodetect@:>@])]
)

AC_CHECK_HEADERS([net/pfilt.h sys/net/nit.h net/raw.h sys/dlpi.h linux/socket.h])

AC_MSG_CHECKING(link-layer packet interface type)

if test -n "${with_link_layer}"; then
    case "${with_link_layer}" in
        bpf)   AC_LIBOBJ([libnet_link_bpf]) ;;
        pf)    AC_LIBOBJ([libnet_link_pf]) ;;
        snit)  AC_LIBOBJ([libnet_link_snit]) ;;
        nit)   AC_LIBOBJ([libnet_link_nit]) ;;
        snoop) AC_LIBOBJ([libnet_link_snoop]) ;;
        dlpi)  AC_LIBOBJ([libnet_link_dlpi]) ;;
        win32) AC_LIBOBJ([libnet_link_win32]) ;;
        none)  AC_LIBOBJ([libnet_link_none]) ;;
        linux) AC_LIBOBJ([libnet_link_linux])
           AC_LIBNET_CHECK_PF_PACKET
           AC_LIBNET_LINUX_PROCFS ;;
        none) AC_LIBOBJ([libnet_link_none]) ;;
        *) AC_MSG_ERROR([Invalid link type "${with_link_layer}"]) ;;
    esac
    AC_MSG_RESULT(user selected link layer ${with_link_layer})
elif test "${cross_compiling}" != "yes" -a -r /dev/bpf0 ; then
    AC_LIBOBJ([libnet_link_bpf])
    AC_MSG_RESULT(found link layer bpf)
elif test "${ac_cv_header_net_pfilt_h}" = "yes" ; then
    AC_LIBOBJ([libnet_link_pf])
    AC_MSG_RESULT(found link layer pf)
elif test "${cross_compiling}" != "yes" -a -r /dev/nit ; then
    AC_LIBOBJ([libnet_link_snit])
    AC_MSG_RESULT(found link layer snit)
elif test "${ac_cv_header_sys_net_nit_h}" = "yes" ; then
    AC_LIBOBJ([libnet_link_nit])
    AC_MSG_RESULT(found link layer nit)
elif test "${ac_cv_header_net_raw_h}" = "yes" ; then
    AC_LIBOBJ([libnet_link_snoop])
    AC_MSG_RESULT(found link layer snoop)
elif test "${ac_cv_header_sys_dlpi_h}" = "yes" ; then
    AC_LIBOBJ([libnet_link_dlpi])
    AC_MSG_RESULT(found link layer dlpi)
    AC_DEFINE(HAVE_DLPI, 1, [Define if the <sys/dlpi.h> header exists.])
elif test "${ac_cv_header_linux_socket_h}" = "yes" ; then
    AC_LIBOBJ([libnet_link_linux])
    AC_MSG_RESULT(found link layer linux)
    AC_LIBNET_CHECK_PF_PACKET
    AC_LIBNET_LINUX_PROCFS
elif test "${cross_compiling}" != "yes" -a -c /dev/bpf0 ; then           # check again in case not readable
    AC_LIBOBJ([libnet_link_bpf])
    AC_MSG_RESULT(found link layer bpf)
elif test "${cross_compiling}" != "yes" -a -c /dev/nit ; then            # check again in case not readable
    AC_LIBOBJ([libnet_link_snit])
    AC_MSG_RESULT(found link layer snit)
elif test "$target_os" = "cygwin" ; then
    AC_LIBOBJ([libnet_link_win32])
    AC_MSG_RESULT(found link layer win32 wpcap)
elif test "$host" = "i686-w64-mingw32" -o "x86_64-w64-mingw32" -o "x86_64-pc-mingw64"; then
    AC_LIBOBJ([libnet_link_win32])
    AC_MSG_RESULT(found link layer win32 @<:@WinPcap@:>@)
else
    AC_LIBOBJ([libnet_link_none])
    AC_MSG_WARN(could not find a link-layer packet interface)
    AC_MSG_WARN(link-layer packet injection will not be available)
fi

dnl This is necessary so that .o files in LIBOBJS are also built via
dnl the ANSI2KNR-filtering rules.
dnl FIXME Isn't this nowadays already taken care of by AC_PROG_CC?
LIB@&t@OBJS=`echo "$LIB@&t@OBJS" |
       sed 's,\.[[^.]]* ,$U&,g;s,\.[[^.]]*$,$U&,'`
LTLIBOBJS=`echo "$LIB@&t@OBJS" |
       sed 's,\.[[^.]]* ,.lo ,g;s,\.[[^.]]*$,.lo,'`

dnl Inform user about the packet builders we've got
echo -n "scanning available packet construction modules: "
for dir in src/*build*c ; do
    echo $dir | sed -e /src\\/libnet_build_/s/// | sed -e /\\.c/s/// | tr \\n \\040
done
echo ""

dnl Check for sample building
AC_MSG_CHECKING([whether to build sample programs])
AC_ARG_ENABLE([samples],
    [AS_HELP_STRING([--disable-samples],[do not build sample programs @<:@default=no@:>@])],
    [enable_samples=$enableval],
    [enable_samples=yes]
)
AC_MSG_RESULT([$enable_samples])

AM_CONDITIONAL([ENABLE_SAMPLES], [test "$enable_samples" = "yes"])


dnl Check for pkgconfig
AC_ARG_ENABLE([pkgconfig],
    [AS_HELP_STRING([--disable-pkgconfig],[do not generate pkg-config .pc file @<:@default=no@:>@])])
    [enable_pkgconfig=$enableval],
    [enable_pkgconfig=yes]
AM_CONDITIONAL([ENABLE_PKGCONFIG], [test "$enable_pkgconfig" = "yes"])


dnl Check for debug
dnl FIXME make it do any actual debuging
AC_MSG_CHECKING([whether to compile in debug mode])
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],[compile with extra debugging output @<:@default=no@:>@])],
    [use_debug=$enableval],
    [use_debug=no]
)
AC_MSG_RESULT([$use_debug])

dnl Check for max speed
dnl FIXME add more flags
AC_MSG_CHECKING([whether to enable additional optimizations])
AC_ARG_ENABLE([fast],
    [AS_HELP_STRING([--enable-fast],[compile with optimizations @<:@default=no@:>@])],
    [use_fast=$enableval],
    [use_fast=no]
)
AC_MSG_RESULT([$use_fast])

if test "x${use_fast}" != "xno"
then
    if test "x${use_debug}" != "xno"
    then
        AC_MSG_ERROR([Cannot specify --enable-fast and --enable-debug at the same time.])
    fi
fi

if test "x$use_fast" = "xyes"
then
    OPT_FLAGS="-O2 -g -fno-strict-aliasing"
else
    OPT_FLAGS="-O0 -ggdb"
    AM_CFLAGS="${AM_CFLAGS} -fkeep-inline-functions"
    if test "x$use_debug" = "xyes"
    then
        AM_CPPFLAGS="${AM_CPPFLAGS} -DDEBUG -DTRACE"
    fi
fi

dnl what (not) to do if the user disables shared libaries
AM_CONDITIONAL([COND_SHARED], [test "x$enable_shared" != xno])

dnl Check and set OS specific parameters
case "$target_os" in

*linux*)
    AC_DEFINE(_BSD_SOURCE, 1,
        [Define as necessary to "unhide" header symbols.])
    AC_DEFINE(__BSD_SOURCE, 1,
        [Define as necessary to "unhide" header symbols.])
    AC_DEFINE(__FAVOR_BSD, 1,
        [Define if we should favor the BSD APIs when possible in Linux.])

    LIBNET_CONFIG_DEFINES="-D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD"
    AC_CHECK_HEADERS(net/ethernet.h, \
        LIBNET_CONFIG_DEFINES="$LIBNET_CONFIG_DEFINES -DHAVE_NET_ETHERNET_H")
    ;;

*freebsd*)
    AC_DEFINE(LIBNET_BSDISH_OS, 1,
        [Define if our build OS supports the BSD APIs])
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1,
        [Define if libnet should byteswap data.])
    AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1,
        [Define if the sockaddr structure includes a sa_len member.])

    LIBNET_CONFIG_DEFINES="-DLIBNET_BSDISH_OS -DLIBNET_BSD_BYTE_SWAP -DHAVE_SOCKADDR_SA_LEN"
    ;;

*netbsd*)
    AC_DEFINE(LIBNET_BSDISH_OS, 1,
        [Define if our build OS supports the BSD APIs])
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1,
        [Define if libnet should byteswap data.])

    LIBNET_CONFIG_DEFINES="-DLIBNET_BSDISH_OS -DLIBNET_BSD_BYTE_SWAP"
    ;;

*openbsd*)
    AC_DEFINE(LIBNET_BSDISH_OS, 1,
        [Define if our build OS supports the BSD APIs])
    AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1,
        [Define if the sockaddr structure includes a sa_len member.])
    LIBNET_CONFIG_DEFINES="-DLIBNET_BSDISH_OS"
    ;;

*bsdi*)
    AC_DEFINE(LIBNET_BSDISH_OS, 1,
        [Define if our build OS supports the BSD APIs])
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1,
        [Define if libnet should byteswap data.])
    LIBNET_CONFIG_DEFINES="-DLIBNET_BSDISH_OS -DLIBNET_BSD_BYTE_SWAP"
    ;;

*darwin*)
    AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1,
        [Define if the sockaddr structure includes a sa_len member.])
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1, [Define if libnet should byteswap data.])
    AC_DEFINE(LIBNET_BSDISH_OS)
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP)
    LIBNET_CONFIG_DEFINES="-DHAVE_SOCKADDR_SA_LEN -DLIBNET_BSDISH_OS -DLIBNET_BSD_BYTE_SWAP"
    ;;

*solaris*)
    AC_DEFINE(HAVE_SOLARIS, 1, [Define if we are running on Solaris.])
    AC_CHECK_HEADERS(sys/bufmod.h sys/dlpi_ext.h)
    AC_MSG_CHECKING(for /dev/dlpi device)
    if test -c /dev/dlpi; then
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_DEV_DLPI, 1, [Define if /dev/dlpi is available.])
    else
        AC_MSG_RESULT(no)
        dir="/dev/dlpi"
        AC_MSG_CHECKING(for $dir directory)
        if test -d $dir ; then
            AC_MSG_RESULT(yes)
            AC_DEFINE_UNQUOTED(DLPI_DEV_PREFIX, "$dir",
                [Define if /dev/dlpi is a directory.])
        else
            AC_MSG_RESULT(no)
        fi
    fi
    AC_CHECK_LIB(socket, socket, ,AC_MSG_ERROR(libsocket not found.))
    AC_CHECK_LIB(nsl, gethostbyname, ,AC_MSG_ERROR(libnsl not found.))
    AC_CHECK_LIB(resolv, hstrerror, ,AC_MSG_ERROR(libresolv not found.))

dnl 
dnl Broken checksums?
dnl
    case "`uname -r`" in
    5.4)
        AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG, 1,
            [Define if our version of Solaris has broken checksums.])
        ;;
    5.5*)
        AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG, 1,
            [Define if our version of Solaris has broken checksums.])
        ;;
    5.8)
        AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG, 1,
            [Define if our version of Solaris has broken checksums.])
        AC_DEFINE(HAVE_SOLARIS_IPV6, 1,
            [Define if our version of Solaris supports IPv6.])

        ;;
    5.9)
        AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG, 1,
            [Define if our version of Solaris has broken checksums.])
        AC_DEFINE(HAVE_SOLARIS_IPV6, 1,
            [Define if our version of Solaris supports IPv6.])
        ;;
    5.10|5.11|5.12)
        AC_DEFINE(HAVE_SOLARIS_IPV6, 1,
            [Define if our version of Solaris supports IPv6.])
        ;;

    esac

    ADDITIONAL_LIBS="-lresolv -lsocket -lnsl"
    LIBNET_CONFIG_LIBS="$LIBNET_CONFIG_LIBS -lresolv -lsocket -lnsl"

    ;;

*hpux11*)
    AC_DEFINE(HAVE_HPUX11, 1, [Define if we are building on HP/UX.])
    AC_CHECK_HEADERS(sys/dlpi_ext.h)
    ;;

*cygwin*)
    AC_DEFINE(LIBNET_BSDISH_OS, 1,
        [Define if our build OS supports the BSD APIs])
    AC_DEFINE(NO_SNPRINTF, 1,
        [Define if snprintf() is unavailable on our system.])
    LIBNET_CONFIG_DEFINES="-DLIBNET_BSDISH_OS -DNO_SNPRINTF"
    CFLAGS="$CFLAGS -mno-cygwin -O0 -fnative-struct -DNO_SNPRINTF -I/usr/include/pcap"
    AC_CHECK_LIB(packet, PacketSetMode, ,AC_MSG_ERROR(packet lib not found.))
    AC_CHECK_LIB(wpcap, pcap_setmode, ,AC_MSG_ERROR(pcap lib not found.))
    LIBS="$LIBS -lws2_32"
    ;;

*mingw*)
    WIN32="yes"
    AC_SUBST(WIN32)
    if test "$enable_shared" = "yes"; then
        AC_CHECK_TOOL(WINDRES, windres, :)
    fi

    AC_DEFINE(WIN32_LEAN_AND_MEAN, 1, 
        [Define to limit the scope of <windows.h>])

    AC_CHECK_LIB(packet, PacketSetMode, ,AC_MSG_ERROR(libpacket.a not found. See README.win32 for more information))
    AC_CHECK_LIB(wpcap, pcap_setmode, ,AC_MSG_ERROR(libwpcap.a not found. See README.win32 for more information))
    LIBS="$LIBS -lws2_32 -liphlpapi"

    if test "$host" = "i686-w64-mingw32" ; then
    CFLAGS="$CFLAGS -march=i686 -mwin32"
    else
    CFLAGS="$CFLAGS -mwin32"
dnl the default GCC toolchains on Debian & Co are so old
     AX_CHECK_LINK_FLAG([-Wl,--high-entropy-va],
     [LDFLAGS="$LDFLAGS -Wl,--high-entropy-va"],
     [AC_MSG_NOTICE([Consider updating your toolchain.])])
    fi

    if test "${cross_compiling}" = "yes" ; then
    CFLAGS="$CFLAGS -static-libgcc"
    fi
    ;;

*irix*)
    CFLAGS="$CFLAGS -DINET6=1"
    ;;

*)
    AC_MSG_WARN(apparently your OS is not officially supported yet)
    AC_MSG_WARN(this may not work)
    AC_MSG_RESULT(please send diffs to autostart.ini@gmail.com)
    ;;

esac

dnl this only matters if we are building for Windows...
AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])

AC_CONFIG_FILES([Makefile src/Makefile \
	include/Makefile \
	include/libnet/Makefile win32/Makefile \
	sample/Makefile doc/Makefile \
	doc/man/Makefile doc/man/man3/Makefile doc/html/Makefile \
	include/libnet.h libnet-config libnet.pc])
AC_OUTPUT

AC_MSG_RESULT([
-=-=-=-=-=-=-=-=-=-= $PACKAGE Configuration Complete =-=-=-=-=-=-=-=-=-=-=-


Configuration Summary

    Version : ..................... ${VERSION}
    Protocols: .................... 32

    Host : ........................ ${host}
    Operating System: ............. ${host_os}
    Host CPU : .................... ${host_cpu}
    Host Vendor : ................. ${host_vendor}
    Host OS : ..................... ${host_os}
    Prefix: ....................... ${prefix}

Compilation Environment

    Cross-compiling: .............. ${cross_compiling}
    Compiler is GCC: .............. ${ac_cv_c_compiler_gnu}
    CC: ........................... ${CC}
    CFLAGS:........................ ${CFLAGS}
    LD: ........................... ${LD}
    LDFLAGS: ...................... ${LDFLAGS}
    LIBS: ......................... ${LIBS}

Features and Examples

    Link Layer: ...................${LTLIBOBJS}
    Shared Libraries: ............. ${enable_shared}
    Static Libraries: ............. ${enable_static}
    PIC ........................... ${pic_mode}
    Debugging: .................... ${use_debug}
    Additional Optimizations: ..... ${use_fast}
    Build Sample Programs: ........ ${enable_samples}
    Generate pkg-config: .......... ${enable_pkgconfig}

To override options, see ./configure --help

To disable silent building and print the full command line of every stage, run "make V=1"
])

case "$target_os" in

*mingw*)
    AC_MSG_WARN([To compile shared libaries on MinGW, use the WinPcap libaries in $(pwd)/win32/.
GCC is NOT able to produce x64 compatible images using the official WinPcap Developer Pack.
See README.win32 for more information.])
    ;;

*)
    AC_MSG_RESULT([Report bugs to https://github.com/sgeto/libnet/issues])
    ;;

esac

dnl EOF
