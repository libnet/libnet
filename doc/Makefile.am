dist_doc_DATA  = MIGRATION.md RAWSOCKET.md
dist_man1_MANS = man/man1/libnet-config.1
man3_MANS      = man/man3/libnet.3 \
		 man/man3/libnet-functions.3 \
		 man/man3/libnet-macros.3
EXTRA_DIST     = fixmanpages.in libnet.Pod
EXTRA_DIST    += api-main.md api-head.html api-foot.html api-style.css
DISTCLEANFILES = libnet.tag $(man3_MANS)

if ENABLE_HTML
pkghtmldir     = $(docdir)/html
pkghtml_DATA   = html/*

$(pkghtml_DATA): doxygen-doc
endif

#
# Doxygen rules from m4/ax_prog_doxygen.m4
#
@DX_RULES@

doc $(man3_MANS): doxygen-doc

all-local: doc
	$(AM_V_at)./fixmanpages

clean-local:
	$(AM_V_at)-rm -rf html
