#
# Libnet automake information file
# Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
# All rights reserved.
#
# Process this file with automake to produce a Makefile.in script.


DISTCHECK_CONFIGURE_FLAGS = \
            --enable-doxygen-doc \
            --disable-samples

# Include macros implemented in the directory m4
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

SUBDIRS = include src

if ENABLE_SAMPLES
SUBDIRS += sample
endif

bin_SCRIPTS = libnet-config

# deleting doc/libnet.tag forces make to rebuild all docs (if enabled)
CLEANFILES     = doc/libnet.tag
DISTCLEANFILES = libnet-config \
                 libnet.pc \
                 fixmanpages

pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = libnet.pc

if ENABLE_DOXYGEN
# Include DOxygen support
all: doxygen-doc
@DX_RULES@

all:
	$(AM_V_GEN)cd $(DX_DOCDIR) && ./fixmanpages && cd -
endif

doc: doxygen-doc
	$(AM_V_GEN)cd $(DX_DOCDIR) && ./fixmanpages && cd -

EXTRA_DIST    = msvcbuild.bat \
                README.win32 \
                autogen.sh \
                map-pblock-types \
                $(WIN32) \
                $(m4data_DATA) \
                $(man_MANS) \
                $(APIDOC_DEPS)

WIN32         = win32/getopt.h \
                win32/libnet.h \
                win32/config.h \
                win32/stdint.h \
                win32/wpdpack

APIDOCS       = doc/api/*.html \
                doc/api/*.css \
                doc/api/*.png

APIDOC_DEPS   = doc/libnet.doxygen.conf \
                doc/libnet.Pod \
                doc/libnet-config.Pod \
                doc/libnet_api_header.html_tmpl \
                doc/libnet_api_footer.html_tmpl \
                doc/libnet_api_stylesheet.css_tmpl

dist_doc_DATA = doc/CHANGELOG \
                doc/CONTRIB \
                doc/COPYING \
                doc/DESIGN_NOTES \
                doc/MIGRATION \
                doc/PACKET_BUILDING \
                doc/PORTED \
                doc/RAWSOCKET_NON_SEQUITUR \
                doc/TODO \
                doc/libnet.pdf

man_MANS      = doc/man/man3/libnet.3 \
                doc/man/man3/libnet-functions.3 \
                doc/man/man3/libnet-macros.3 \
                doc/man/man1/libnet-config.1

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(docdir)/api
	$(INSTALL_DATA) `test -f doc/api/index.html || echo $(srcdir)/`doc/api/*.png $(DESTDIR)$(docdir)/api
	$(INSTALL_DATA) `test -f doc/api/index.html || echo $(srcdir)/`doc/api/*.css $(DESTDIR)$(docdir)/api
	$(INSTALL_DATA) `test -f doc/api/index.html || echo $(srcdir)/`doc/api/*.html $(DESTDIR)$(docdir)/api

uninstall-local:
	rm -rf $(DESTDIR)$(docdir)/api

# (GNU make only) Unless we say otherwise, spare us the
# “Entering/Leaving directory ...” messages
GNUMAKEFLAGS = $(if $(value VERBOSE),,--no-print-directory)
