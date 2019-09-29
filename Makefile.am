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

SUBDIRS = include src doc win32

if ENABLE_SAMPLES
SUBDIRS += sample
endif

# deleting doc/libnet.tag forces make to rebuild all docs (if enabled)
CLEANFILES     = doc/libnet.tag libnet.pc
DISTCLEANFILES = fixmanpages

pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = libnet.pc

@DX_RULES@

doc: doxygen-doc
	$(AM_V_GEN)cd $(DX_DOCDIR) && ./fixmanpages && cd -

doc_DATA      = README.md LICENSE
EXTRA_DIST    = README.md LICENSE \
                msvcbuild.bat \
                README.win32 \
                autogen.sh \
                map-pblock-types

APIDOCS       = $(top_srcdir)/doc/api/*.html \
                $(top_srcdir)/doc/api/*.css \
                $(top_srcdir)/doc/api/*.png

APIDOC_DEPS   = $(top_srcdir)/doc/libnet.doxygen.conf \
                $(top_srcdir)/doc/libnet.Pod \
                $(top_srcdir)/doc/libnet-config.Pod \
                $(top_srcdir)/doc/libnet_api_header.html_tmpl \
                $(top_srcdir)/doc/libnet_api_footer.html_tmpl \
                $(top_srcdir)/doc/libnet_api_stylesheet.css_tmpl

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
