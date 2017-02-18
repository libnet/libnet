#
# Libnet automake information file
# Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
# All rights reserved.
#
# Process this file with automake to produce a Makefile.in script.

# Include macros implemented in the directory m4
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

SUBDIRS = include src doc win32

if ENABLE_SAMPLES
SUBDIRS += sample
endif

EXTRA_DIST = msvcbuild.bat README.win32 autogen.sh map-pblock-types m4/ax_check_link_flag.m4

bin_SCRIPTS = libnet-config

# DISTCLEANFILES=  remove also *~ when execute make clean
DISTCLEANFILES = *~

# (GNU make only) Unless we say otherwise, spare us the
# “Entering/Leaving directory ...” messages
GNUMAKEFLAGS = $(if $(value VERBOSE),,--no-print-directory)