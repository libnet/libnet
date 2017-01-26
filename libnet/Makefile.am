#
# Libnet automake information file
# Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
# All rights reserved.
#
# Process this file with automake to produce a Makefile.in script.

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

include $(top_srcdir)/Makefile.am.common

SUBDIRS = include src doc win32

if ENABLE_SAMPLES
SUBDIRS += sample
endif

EXTRA_DIST = Makefile.am.common msvcbuild.bat # m4/NOTES

bin_SCRIPTS = libnet-config

