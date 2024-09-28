#
# Libnet autoconfiguration information file
# Copyright (c) 1998 - 2002 Mike D. Schiffman <mike@infonexus.com>
# Modified by: Ali Abdulkadir <autostart.ini@gmail.com>,
#              Joachim Wiberg <troglobit@gmail.com>
# All rights reserved.
#
# Process this file with autoconf to produce a configure script.

# Update VERSION for new releases, used also by the win32 build system.
AC_INIT([libnet], m4_esyscmd([sed -n '1p' VERSION | tr -d '\n']),
	[https://github.com/libnet/libnet/issues],[],
	[https://github.com/libnet/libnet])

# Visible in resulting configure script, e.g. with ./configure --version
AC_COPYRIGHT([Copyright (C) 1998 - 2022 The libnet Developer Community.])
AC_REVISION(${VERSION})

# the autotools and libtool should be at least these versions
AC_PREREQ([2.69])
LT_PREREQ([2.4.2])

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
		 libnet-config \
		 doc/Doxyfile \
                 doc/Makefile \
                 include/Makefile \
                 include/libnet.h \
		 libnet.pc \
                 src/Makefile \
                 sample/Makefile \
		 test/Makefile \
		 win32/Makefile])
AC_CONFIG_FILES([doc/fixmanpages], [chmod a+x doc/fixmanpages])

# For CMocka tests to fit in with autotools `make check`
AC_REQUIRE_AUX_FILE([tap-driver.sh])

# Check for the usual programs
AC_PROG_CC
AC_PROG_INSTALL
AC_USE_SYSTEM_EXTENSIONS
# The default is to use only PIC objects.
# This can still be overwritten with --without-pic
LT_INIT([pic-only])

# Check for pkg-config first, warn if it's not installed
PKG_PROG_PKG_CONFIG

#
# Check for headers
#
AC_CHECK_HEADERS([sys/sockio.h net/if.h sys/ioctl.h])
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
AS_IF([test "x$have_socklen_t" = "xyes"], [
        AC_DEFINE(HAVE_SOCKLEN_T, 1, [define if socklen_t is defined])])
AC_MSG_RESULT($have_socklen_t)

#
# And some custom things
#
AC_LIBNET_ENDIAN_CHECK
AC_SUBST(ENDIANESS)
AC_SUBST(ADDITIONAL_LIBS)
AC_SUBST(PKG_CONFIG_DEFINES)
AC_SUBST(PKG_CONFIG_LIBS)
AC_SUBST(PKG_CONFIG_CFLAGS)
AC_SUBST(LTLIBOBJS)

# Get link-layer interface type
AC_ARG_WITH([link-layer], [
	AS_HELP_STRING([--with-link-layer], [
		when cross-compiling, one of * from libnet_link_*.c @<:@autodetect@:>@])])

AC_CHECK_HEADERS([net/pfilt.h sys/net/nit.h net/raw.h sys/dlpi.h linux/socket.h])

AC_MSG_CHECKING(link-layer packet interface type)

AS_IF([test -n "${with_link_layer}"], [
    AS_CASE([${with_link_layer}],
        [bpf],   [AC_LIBOBJ([libnet_link_bpf])],
        [pf],    [AC_LIBOBJ([libnet_link_pf])],
        [snit],  [AC_LIBOBJ([libnet_link_snit])],
        [nit],   [AC_LIBOBJ([libnet_link_nit])],
        [snoop], [AC_LIBOBJ([libnet_link_snoop])],
        [dlpi],  [AC_LIBOBJ([libnet_link_dlpi])],
        [win32], [AC_LIBOBJ([libnet_link_win32])],
        [none],  [AC_LIBOBJ([libnet_link_none])],
        [linux], [AC_LIBOBJ([libnet_link_linux])
                  AC_LIBNET_LINUX_PROCFS],
        [AC_MSG_ERROR([Invalid link type "${with_link_layer}"])])
     AC_MSG_RESULT(user selected link layer ${with_link_layer})],
[test "${cross_compiling}" != "yes" -a -r /dev/bpf0], [
    AC_LIBOBJ([libnet_link_bpf])
    AC_MSG_RESULT(found link layer bpf)],
[test "${ac_cv_header_net_pfilt_h}" = "yes"], [
    AC_LIBOBJ([libnet_link_pf])
    AC_MSG_RESULT(found link layer pf)],
[test "${cross_compiling}" != "yes" -a -r /dev/nit], [
    AC_LIBOBJ([libnet_link_snit])
    AC_MSG_RESULT(found link layer snit)],
[test "${ac_cv_header_sys_net_nit_h}" = "yes"], [
    AC_LIBOBJ([libnet_link_nit])
    AC_MSG_RESULT(found link layer nit)],
[test "${ac_cv_header_net_raw_h}" = "yes"], [
    AC_LIBOBJ([libnet_link_snoop])
    AC_MSG_RESULT(found link layer snoop)],
[test "${ac_cv_header_sys_dlpi_h}" = "yes"], [
    AC_LIBOBJ([libnet_link_dlpi])
    AC_MSG_RESULT(found link layer dlpi)
    AC_DEFINE(HAVE_DLPI, 1, [Define if the <sys/dlpi.h> header exists.])],
[test "${ac_cv_header_linux_socket_h}" = "yes"], [
    AC_LIBOBJ([libnet_link_linux])
    AC_MSG_RESULT(found link layer linux)
    AC_LIBNET_LINUX_PROCFS],
[test "${cross_compiling}" != "yes" -a -c /dev/bpf0], [
    # check again in case not readable
    AC_LIBOBJ([libnet_link_bpf])
    AC_MSG_RESULT(found link layer bpf)],
[test "${cross_compiling}" != "yes" -a -c /dev/nit], [
    # check again in case not readable
    AC_LIBOBJ([libnet_link_snit])
    AC_MSG_RESULT(found link layer snit)],
[test "$target_os" = "cygwin"], [
    AC_LIBOBJ([libnet_link_win32])
    AC_MSG_RESULT(found link layer win32 wpcap)],
[test "$host" = "i686-w64-mingw32" -o "x86_64-w64-mingw32" -o "x86_64-pc-mingw64"], [
    AC_LIBOBJ([libnet_link_win32])
    AC_MSG_RESULT(found link layer win32 @<:@WinPcap@:>@)],[
    AC_LIBOBJ([libnet_link_none])
    AC_MSG_WARN(could not find a link-layer packet interface)
    AC_MSG_WARN(link-layer packet injection will not be available)])

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
DX_INIT_DOXYGEN(${PACKAGE_NAME}, [${top_builddir}/doc/Doxyfile], [${top_builddir}/doc])
AM_CONDITIONAL(ENABLE_DOXYGEN, [test "x${DX_FLAG_doc}"  = x1])
AM_CONDITIONAL(ENABLE_HTML,    [test "x${DX_FLAG_html}" = x1])
AM_CONDITIONAL(ENABLE_MAN,     [test "x${DX_FLAG_man}"  = x1])

# Check for sample building
AC_MSG_CHECKING([whether to build sample programs])
AC_ARG_ENABLE([samples],
    [AS_HELP_STRING([--enable-samples],[build sample programs @<:@default=no@:>@])],
    [enable_samples=$enableval],
    [enable_samples=no]
)
AC_MSG_RESULT([$enable_samples])
AM_CONDITIONAL([ENABLE_SAMPLES], [test "$enable_samples" = "yes"])

# Check for tests enabling
AC_MSG_CHECKING([enable tests])
AC_ARG_ENABLE([tests],
    [AS_HELP_STRING([--enable-tests],[enable unit tests @<:@default=no@:>@])],
    [enable_tests=$enableval],
    [enable_tests=no]
)
AC_MSG_RESULT([$enable_tests])
AM_CONDITIONAL([ENABLE_TESTS], [test "$enable_tests" = "yes"])
AS_IF([test "$enable_tests" = "yes"], [
    PKG_CHECK_MODULES([cmocka], [cmocka >= 1.0.0])
    AC_DEFINE(LIBNET_ENABLE_TESTS, 1, [Useful define for testing purposes.])
])

# what (not) to do if the user disables shared libraries
AM_CONDITIONAL([COND_SHARED], [test "x$enable_shared" != xno])

# Enable some extra features.
CFLAGS="$CFLAGS -D_DEFAULT_SOURCE=1"

# Check and set OS specific parameters
AS_CASE([$target_os],
[*linux*], [
    LINUX="yes"
    AC_DEFINE(_BSD_SOURCE, 1,
        [Define as necessary to "unhide" header symbols.])
    AC_DEFINE(_DEFAULT_SOURCE, 1,
        [Define as necessary to "unhide" header symbols.])

    PKG_CONFIG_DEFINES="-D_BSD_SOURCE -D_DEFAULT_SOURCE"
    AC_CHECK_HEADERS(net/ethernet.h, \
        PKG_CONFIG_DEFINES="$PKG_CONFIG_DEFINES -DHAVE_NET_ETHERNET_H")
    ],

[*freebsd*], [
    PKG_CONFIG_DEFINES="-DHAVE_SOCKADDR_SA_LEN"
    AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1, [FreeBSD has sa_len in struct sockaddr.])

    AC_MSG_CHECKING([FreeBSD version, is SOCK_RAW really raw?])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <sys/param.h>]], [[
#if (__FreeBSD_version >= 1100030)
    return 0;
#else
#error FreeBSD pre-11, SOCK_RAW isn't really raw, see https://www.freebsd.org/cgi/man.cgi?ip(4)#end
#endif]])],[AC_MSG_RESULT(yes)],[AC_MSG_RESULT(no)
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1, FreeBSD pre-11, libnet must byteswap raw ip_len, ip_off)
    PKG_CONFIG_DEFINES="${PKG_CONFIG_DEFINES} -DLIBNET_BSD_BYTE_SWAP"])],

[*netbsd*], [
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1,
        [Define if libnet should byteswap data.])

    PKG_CONFIG_DEFINES="-DLIBNET_BSD_BYTE_SWAP"
    ],

[*openbsd*], [
    AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1,
        [Define if the sockaddr structure includes a sa_len member.])
    ],

[*bsdi*], [
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1,
        [Define if libnet should byteswap data.])
    PKG_CONFIG_DEFINES="-DLIBNET_BSD_BYTE_SWAP"
    ],

[*darwin*], [
    AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1,
        [Define if the sockaddr structure includes a sa_len member.])
    AC_DEFINE(LIBNET_BSD_BYTE_SWAP, 1, [Define if libnet should byteswap data.])
    PKG_CONFIG_DEFINES="-DHAVE_SOCKADDR_SA_LEN -DLIBNET_BSD_BYTE_SWAP"
    ],

[*solaris*], [
    AC_DEFINE(HAVE_SOLARIS, 1, [Define if we are running on Solaris.])
    AC_CHECK_HEADERS(sys/bufmod.h sys/dlpi_ext.h)
    AC_MSG_CHECKING(for /dev/dlpi device)
    AS_IF([test -c /dev/dlpi], [
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_DEV_DLPI, 1, [Define if /dev/dlpi is available.])
    ], [
        AC_MSG_RESULT(no)
        dir="/dev/dlpi"
        AC_MSG_CHECKING(for $dir directory)
        AS_IF([test -d $dir], [
            AC_MSG_RESULT(yes)
            AC_DEFINE_UNQUOTED(DLPI_DEV_PREFIX, "$dir",
                [Define if /dev/dlpi is a directory.])
        ], [
            AC_MSG_RESULT(no)
        ])
    ])
    AC_CHECK_LIB(socket, socket, ,AC_MSG_ERROR(libsocket not found.))
    AC_CHECK_LIB(nsl, gethostbyname, ,AC_MSG_ERROR(libnsl not found.))
    AC_CHECK_LIB(resolv, hstrerror, ,AC_MSG_ERROR(libresolv not found.))

    #
    # Broken checksums?
    #
    AS_CASE([`uname -r`],
    [5.4], [
        AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG, 1,
            [Define if our version of Solaris has broken checksums.])
        ],
    [5.5*], [
        AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG, 1,
            [Define if our version of Solaris has broken checksums.])
        ],
    [5.8], [
        AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG, 1,
            [Define if our version of Solaris has broken checksums.])
        AC_DEFINE(HAVE_SOLARIS_IPV6, 1,
            [Define if our version of Solaris supports IPv6.])

        ],
    [5.9], [
        AC_DEFINE(STUPID_SOLARIS_CHECKSUM_BUG, 1,
            [Define if our version of Solaris has broken checksums.])
        AC_DEFINE(HAVE_SOLARIS_IPV6, 1,
            [Define if our version of Solaris supports IPv6.])
        ],
    [5.10 | 5.11 | 5.12], [
        AC_DEFINE(HAVE_SOLARIS_IPV6, 1,
            [Define if our version of Solaris supports IPv6.])
        ])

    ADDITIONAL_LIBS="-lresolv -lsocket -lnsl"
    PKG_CONFIG_LIBS="$PKG_CONFIG_LIBS -lresolv -lsocket -lnsl"
    ],

[*hpux11*], [
    AC_DEFINE(HAVE_HPUX11, 1, [Define if we are building on HP/UX.])
    AC_CHECK_HEADERS(sys/dlpi_ext.h)
    ],

[*cygwin* | *msys*], [
    WIN32="yes"
    AC_SUBST(WIN32)
    CFLAGS="$CFLAGS -mwin32"
    AC_CHECK_LIB(packet, PacketSetMode, ,AC_MSG_ERROR(packet lib not found.))
    AC_CHECK_LIB(wpcap, pcap_setmode, ,AC_MSG_ERROR(pcap lib not found.))
    LIBS="$LIBS -lws2_32"
    ],

[*mingw*], [
    WIN32="yes"
    AC_SUBST(WIN32)

    AS_IF([test "$enable_shared" = "yes"], [AC_CHECK_TOOL(WINDRES, windres, :)])

    AC_DEFINE(WIN32_LEAN_AND_MEAN, 1, [Define to limit the scope of <windows.h>])

    AC_CHECK_LIB(packet, PacketSetMode, ,AC_MSG_ERROR(libpacket.a not found. See README.win32 for more information))
    AC_CHECK_LIB(wpcap, pcap_setmode, ,AC_MSG_ERROR(libwpcap.a not found. See README.win32 for more information))
    LIBS="$LIBS -lws2_32 -liphlpapi"

    AS_IF([test "$host" = "i686-w64-mingw32"], [
        CFLAGS="$CFLAGS -march=i686 -mwin32"], [
	CFLAGS="$CFLAGS -mwin32"

	AX_CHECK_LINK_FLAG([-Wl,--high-entropy-va],
            [LDFLAGS="$LDFLAGS -Wl,--high-entropy-va"],
            [AC_MSG_NOTICE([Consider updating your toolchain.])])
    ])

    AS_IF([test "${cross_compiling}" = "yes"], [
        CFLAGS="$CFLAGS -static-libgcc"])
    ],

[*irix*], [
    CFLAGS="$CFLAGS -DINET6=1"
    ], [
    AC_MSG_WARN(${target_os} is not officially supported yet.)
    AC_MSG_RESULT(Please report this to ${PACKAGE_BUGREPORT})])

# Automake conditionals for different operating systems
AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([LINUX], [test "${LINUX}" = "yes"])

# Create all files from AC_CONFIG_FILES()
AC_OUTPUT

# Helper variables for summary, below
AS_IF([test ${DX_FLAG_doc} -eq 1], [build_docs=yes], [build_docs=no])
link_layer=`"echo"${LTLIBOBJS}"" | sed 's/.*libnet_link_\(.*\)\$.*/\1/'`

AC_MSG_RESULT([
-=-=-=-=-=-=-=-=-=-= $PACKAGE Configuration Complete =-=-=-=-=-=-=-=-=-=-

    Version ....................... ${VERSION}

    Host .......................... ${host}
    Operating System .............. ${host_os}
    Host CPU ...................... ${host_cpu}
    Host Vendor ................... ${host_vendor}
    Host OS ....................... ${host_os}
    Prefix ........................ ${prefix}

    Cross-compiling ............... ${cross_compiling}
    Compiler is GNU (compatible) .. ${ac_cv_c_compiler_gnu}
    CC ............................ ${CC}
    CFLAGS ........................ ${CFLAGS}
    LD ............................ ${LD}
    LDFLAGS ....................... ${LDFLAGS}
    LIBS .......................... ${LIBS}

    Link Layer .................... ${link_layer}
    Shared Libraries .............. ${enable_shared}
    Static Libraries .............. ${enable_static}
    PIC ........................... ${pic_mode}
    Build Sample Programs ......... ${enable_samples}
    Build Doxygen documentation.... ${build_docs}
    Run Unit Tests................. ${enable_tests}

To override options

	$0 --help

Report bugs to ${PACKAGE_BUGREPORT}

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
To disable silent build and print the full command line of every stage

	make V=1
])
AS_IF([test "$WIN32" = "yes"], [AC_MSG_RESULT(
[To compile shared libraries on MinGW use the bundled WinPcap libraries
in ./win32/.  GCC can NOT produce x64 compatible images with official
WinPcap Developer Pack.  See README.win32 for more info.
])])
AS_IF([test "$build_docs" = "yes"], [AC_MSG_RESULT(
[To build/update the documentation

	make doc
])])
