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
CLEANFILES     = doc/libnet.tag libnet-config libnet.pc
DISTCLEANFILES = fixmanpages

pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = libnet.pc

# For list of the strings to substitute via sed in libnet.pc.in, try ...
# $ cat libnet.pc.in libnet-config.in | tr '" ' '\n\n' | egrep '@.*@' | sed 's:^[^@]*@:@:' | sort | uniq

INCOMMAND = $(SED) \
	 -e 's|[@]configure_input[@]|$(configure_input)|g' \
	 -e 's|[@]exec_prefix[@]|$(exec_prefix)|g' \
	 -e 's|[@]includedir[@]|$(includedir)|g' \
	 -e 's|[@]LDFLAGS[@]|$(LDFLAGS)|g' \
	 -e 's|[@]libdir[@]|$(libdir)|g' \
	 -e 's|[@]LIBNET_CONFIG_CFLAGS[@]|$(LIBNET_CONFIG_CFLAGS)|g' \
	 -e 's|[@]LIBNET_CONFIG_DEFINES[@]|$(LIBNET_CONFIG_DEFINES)|g' \
	 -e 's|[@]LIBNET_CONFIG_LIBS[@]|$(LIBNET_CONFIG_LIBS)|g' \
	 -e 's|[@]LIBS[@]|$(LIBS)|g' \
	 -e 's|[@]PACKAGE_URL[@]|$(PACKAGE_URL)|g' \
	 -e 's|[@]prefix[@]|$(prefix)|g' \
	 -e 's|[@]SHELL[@]|$(SHELL)|g' \
	 -e 's|[@]VERSION[@]|$(VERSION)|g'

libnet.pc: libnet.pc.in
	$(INCOMMAND) <$< > $@

libnet-config: libnet-config.in
	$(INCOMMAND) <$< > $@
	$(CHMOD) a+x $@

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
		libnet.pc.in \
		libnet-config.in \
                $(WIN32) \
                $(m4data_DATA) \
                $(man_MANS) \
                $(APIDOCS) \
                $(APIDOC_DEPS)

WIN32         = win32/getopt.h \
                win32/libnet.h \
                win32/config.h \
                win32/stdint.h \
                win32/wpdpack

APIDOCS       = $(top_srcdir)/doc/api/*.html \
                $(top_srcdir)/doc/api/*.css \
                $(top_srcdir)/doc/api/*.png

APIDOC_DEPS   = $(top_srcdir)/doc/libnet.doxygen.conf \
                $(top_srcdir)/doc/libnet.Pod \
                $(top_srcdir)/doc/libnet-config.Pod \
                $(top_srcdir)/doc/libnet_api_header.html_tmpl \
                $(top_srcdir)/doc/libnet_api_footer.html_tmpl \
                $(top_srcdir)/doc/libnet_api_stylesheet.css_tmpl

dist_doc_DATA = doc/CHANGELOG \
                doc/CONTRIB \
                doc/COPYING \
                doc/DESIGN_NOTES \
                doc/MIGRATION \
                doc/PACKET_BUILDING \
                doc/PORTED \
                doc/RAWSOCKET_NON_SEQUITUR \
                doc/TODO \
                doc/libnet.pdf \
                doc/libnet.chm

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
