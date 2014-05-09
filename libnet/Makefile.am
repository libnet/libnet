# $Id: Makefile.am,v 1.7 2004/03/01 20:26:11 mike Exp $
#
# Libnet automake information file
# Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
# All rights reserved.
#
# Process this file with automake to produce a Makefile.in script.

include $(top_srcdir)/Makefile.am.common

SUBDIRS = include src sample doc win32

EXTRA_DIST = Makefile.am.common msvcbuild.bat

EXTRA_DIST += README.win32 autogen.sh map-pblock-types

bin_SCRIPTS = libnet-config

MOSTLYCLEANFILES =

if ENABLE_DOXYGEN
# Include DOxygen support
all: @DX_DOCDIR@/@PACKAGE@.tag
@DX_RULES@
endif

if ENABLE_PKGCONFIG
# support "pkg-config net"
net.pc:
	echo 'prefix=$(prefix)'						>  $@
	echo 'exec_prefix=$(exec_prefix)'				>> $@
	echo 'includedir=$(includedir)'					>> $@
	echo 'libdir=$(libdir)'						>> $@
	echo								>> $@
	echo 'Name: $(PACKAGE_TARNAME)'					>> $@
	echo 'Description: $(PACKAGE_NAME)'				>> $@
	echo 'URL: $(PACKAGE_URL)'					>> $@
	echo 'Version: $(PACKAGE_VERSION)'				>> $@
	echo 'Cflags: -I$(includedir)'					>> $@
	echo 'Libs: -L$(libdir) -lnet'					>> $@
	echo 'Libs.private: $(LDFLAGS) $(LIBS) $(LIBNET_CONFIG_LIBS)'	>> $@
	echo '# compiled with: $(LIBNET_CONFIG_DEFINES)'		>> $@
pkgconfig_DATA = net.pc
MOSTLYCLEANFILES += net.pc
endif ENABLE_PKGCONFIG
