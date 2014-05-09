# $Id: Makefile.am,v 1.7 2004/03/01 20:26:11 mike Exp $
#
# Libnet automake information file
# Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
# All rights reserved.
#
# Process this file with automake to produce a Makefile.in script.

include $(top_srcdir)/Makefile.am.common

pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = libnet.pc
SUBDIRS = include src sample doc win32

EXTRA_DIST  = Makefile.am.common msvcbuild.bat
EXTRA_DIST += README.win32 map-pblock-types

if ENABLE_DOXYGEN
all: @DX_DOCDIR@/@PACKAGE@.tag
@DX_RULES@
endif
