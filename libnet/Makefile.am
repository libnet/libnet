#
# Libnet automake information file
# Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
# All rights reserved.
#
# Process this file with automake to produce a Makefile.in script.

EXTRA_DIST = msvcbuild.bat README.win32 \
             autogen.sh map-pblock-types \
             win32/getopt.h win32/libnet.h \
             win32/config.h win32/stdint.h \
             win32/wpdpack $(m4data_DATA) \
             $(man_MANS)


# Include macros implemented in the directory m4
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

SUBDIRS = include src

if ENABLE_SAMPLES
SUBDIRS += sample
endif

EXTRA_DIST = msvcbuild.bat README.win32 autogen.sh map-pblock-types m4/ax_check_link_flag.m4

bin_SCRIPTS = libnet-config

if ENABLE_PKGCONFIG
pkgconfigdir=$(libdir)/pkgconfig
pkgconfig_DATA=libnet.pc
DISTCLEANFILES = libnet.pc
endif

# (GNU make only) Unless we say otherwise, spare us the
# “Entering/Leaving directory ...” messages
GNUMAKEFLAGS = $(if $(value VERBOSE),,--no-print-directory)