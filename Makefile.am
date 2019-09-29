#
# Libnet automake information file
# Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
# All rights reserved.
#
DISTCHECK_CONFIGURE_FLAGS = --enable-doxygen-doc --disable-samples
ACLOCAL_AMFLAGS           = -I m4 ${ACLOCAL_FLAGS}

pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = libnet.pc
doc_DATA       = README.md LICENSE
EXTRA_DIST     = README.md LICENSE \
                 msvcbuild.bat \
                 README.win32 \
                 autogen.sh \
                 map-pblock-types
SUBDIRS        = include src win32

if ENABLE_DOXYGEN
SUBDIRS       += doc
endif
if ENABLE_SAMPLES
SUBDIRS       += sample
endif

#
# Doxygen rules from m4/ax_prog_doxygen.m4
# 
@DX_RULES@

doc: doxygen-doc
	$(AM_V_GEN)cd $(DX_DOCDIR) && ./fixmanpages && cd -

# (GNU make only) Unless we say otherwise, spare us the
# “Entering/Leaving directory ...” messages
GNUMAKEFLAGS = $(if $(value VERBOSE),,--no-print-directory)
