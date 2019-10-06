#
# Libnet autoconfiguration information file
# Copyright (c) 1998 - 2002 Mike D. Schiffman <mike@infonexus.com>
# Modified by Ali Abdulkadir <autostart.ini@gmail.com>
# All rights reserved.
#
# Process this file with autoconf to produce a configure script.

AC_INIT([libnet],[1.2-rc3],[https://github.com/libnet/libnet/issues],,[https://github.com/libnet/libnet])

# the autotools and libtool should be at least these versions
AC_PREREQ([2.69])
LT_PREREQ([2.4.2])

AC_COPYRIGHT([Copyright 1998 - 2019 The libnet Developer Community])
AC_MSG_RESULT(Beginning autoconfiguration process for libnet-${PACKAGE_VERSION} ...)
AC_PROG_SHELL
AC_PROG_SED
AC_CHECK_PROGS([CHMOD],[chmod],[true])
AC_CANONICAL_TARGET
AC_CONFIG_SRCDIR([src/libnet_build_ip.c])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.14 foreign subdir-objects no-dependencies dist-zip])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([include/config.h])

AC_CONFIG_FILES([Makefile \
		 Doxyfile \
		 bin/Makefile \
                 doc/Makefile \
                 include/Makefile \
                 include/libnet.h \
		 libnet.pc \
                 src/Makefile \
                 sample/Makefile \
		 win32/Makefile])
AC_CONFIG_FILES([doc/fixmanpages], [chmod a+x doc/fixmanpages])

# Check for the usual programs
AC_PROG_CC
AC_PROG_INSTALL
AC_USE_SYSTEM_EXTENSIONS
# The default is to use only PIC objects.
# This can still be overwritten with --without-pic
LT_INIT([pic-only])

#
# Check for headers
#

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

#
# And some custom things
#

AC_LIBNET_ENDIAN_CHECK
# AC_LBL_LIBRARY_NET
AC_SUBST(ENDIANESS)
AC_SUBST(HAVE_PACKET_SOCKET)
AC_SUBST(ADDITIONAL_LIBS)
AC_SUBST(PKG_CONFIG_DEFINES)
AC_SUBST(PKG_CONFIG_LIBS)
# FIXME this variable is unused
AC_SUBST(LIBNET_CONFIG_CFLAGS)
AC_SUBST(LTLIBOBJS)

# Get link-layer interface type
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

# This is necessary so that .o files in LIBOBJS are also built via
# the ANSI2KNR-filtering rules.
# FIXME Isn't this nowadays already taken care of by AC_PROG_CC?
LIB@&t@OBJS=`echo "$LIB@&t@OBJS" |
       sed 's,\.[[^.]]* ,$U&,g;s,\.[[^.]]*$,$U&,'`
LTLIBOBJS=`echo "$LIB@&t@OBJS" |
       sed 's,\.[[^.]]* ,.lo ,g;s,\.[[^.]]*$,.lo,'`

link_layer=`"echo"${LTLIBOBJS}"" | cut -c 13- | awk -F$ '/U.lo/ {print $1}'`

# Inform user about the packet builders we've got
echo -n "scanning available packet construction modules: "
for dir in src/*build*c ; do
    echo $dir | sed -e /src\\/libnet_build_/s/// | sed -e /\\.c/s/// | tr \\n \\040
done
echo ""

# Check for Doxygen and enable its features.
# For details, see m4/ax_prog_doxygen.m4 and
# http://www.bioinf.uni-freiburg.de/~mmann/HowTo/automake.html#doxygenSupport
DX_DOXYGEN_FEATURE(ON)
DX_DOT_FEATURE(ON)
DX_CHI_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_CHM_FEATURE(OFF)
DX_HTML_FEATURE(ON)
DX_MAN_FEATURE(ON)
DX_INIT_DOXYGEN(${PACKAGE_NAME}, [${top_builddir}/Doxyfile], [doc])
AM_CONDITIONAL(ENABLE_DOXYGEN,[test "x${DX_FLAG_doc}" = x1])

if test ${DX_FLAG_doc} -eq 1; then
    rebuild_docs=yes
else
    rebuild_docs=no
fi

# Check for sample building
AC_MSG_CHECKING([whether to build sample programs])
AC_ARG_ENABLE([samples],
    [AS_HELP_STRING([--enable-samples],[do not build sample programs @<:@default=no@:>@])],
    [enable_samples=$enableval],
    [enable_samples=no]
)
AC_MSG_RESULT([$enable_samples])

AM_CONDITIONAL([ENABLE_SAMPLES], [test "$enable_samples" = "yes"])

# what (not) to do if the user disables shared libraries
AM_CONDITIONAL([COND_SHARED], [test "x$enable_shared" != xno])

# Check and set OS specific parameters
case "$target_os" in
*linux*)
    AC_DEFINE(_BSD_SOURCE, 1,
        [Define as necessary to "unhide" header symbols.])
    AC_DEFINE(_DEFAULT_SOURCE, 1,
        [Define as necessary to "unhide" header symbols.])

    PKG_CONFIG_DEFINES="-D_BSD_SOURCE -D_DEFAULT_SOURCE"
    AC_CHECK_HEADERS(net/ethernet.h, \
        PKG_CONFIG_DEFINES="$PKG_CONFIG_DEFINES -DHAVE_NET_ETHERNET_H")
    ;;

*freebsd*)
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1,
        [Define if libnet should byteswap data.])
    AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1,
        [Define if the sockaddr structure includes a sa_len member.])

    PKG_CONFIG_DEFINES="-DLIBNET_BSD_BYTE_SWAP -DHAVE_SOCKADDR_SA_LEN"
    ;;

*netbsd*)
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1,
        [Define if libnet should byteswap data.])

    PKG_CONFIG_DEFINES="-DLIBNET_BSD_BYTE_SWAP"
    ;;

*openbsd*)
    AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1,
        [Define if the sockaddr structure includes a sa_len member.])
    ;;

*bsdi*)
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1,
        [Define if libnet should byteswap data.])
    PKG_CONFIG_DEFINES="-DLIBNET_BSD_BYTE_SWAP"
    ;;

*darwin*)
    AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1,
        [Define if the sockaddr structure includes a sa_len member.])
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1, [Define if libnet should byteswap data.])
    PKG_CONFIG_DEFINES="-DHAVE_SOCKADDR_SA_LEN -DLIBNET_BSD_BYTE_SWAP"
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

# 
# Broken checksums?
#
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
    PKG_CONFIG_LIBS="$PKG_CONFIG_LIBS -lresolv -lsocket -lnsl"

    ;;

*hpux11*)
    AC_DEFINE(HAVE_HPUX11, 1, [Define if we are building on HP/UX.])
    AC_CHECK_HEADERS(sys/dlpi_ext.h)
    ;;

*cygwin* | *msys*)
    WIN32="yes"
    AC_SUBST(WIN32)
    CFLAGS="$CFLAGS -mwin32"
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
# the default GCC toolchains on Debian & Co are so old
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

# this only matters if we are building for Windows...
AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])

# Create all files from AC_CONFIG_FILES()
AC_OUTPUT

AC_MSG_RESULT([
-=-=-=-=-=-=-=-=-= $PACKAGE Configuration Complete =-=-=-=-=-=-=-=-=-=-


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

    Link Layer: ................... ${link_layer}
    Shared Libraries: ............. ${enable_shared}
    Static Libraries: ............. ${enable_static}
    PIC ........................... ${pic_mode}
    Build Sample Programs: ........ ${enable_samples}
    Rebuild docs: ................. ${rebuild_docs}

To override options, see ./configure --help

To disable silent building and print the full command line of every stage, run "make V=1"
])
if test "$WIN32" = "yes" ; then
AC_MSG_WARN([To compile shared libraries on MinGW, use the WinPcap libraries in $(pwd)/win32/.
GCC is NOT able to produce x64 compatible images using the official WinPcap Developer Pack.
See README.win32 for more information.

Report bugs to ${PACKAGE_BUGREPORT}])
elif test "$rebuild_docs" = "yes" ; then
AC_MSG_RESULT([To build just the Documentation run "make doc"

Report bugs to ${PACKAGE_BUGREPORT}])
else
AC_MSG_RESULT([Report bugs to ${PACKAGE_BUGREPORT}])
fi
