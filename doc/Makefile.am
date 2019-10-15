SUBDIRS        = man
dist_doc_DATA  = MIGRATION.md RAWSOCKET.md
EXTRA_DIST     = fixmanpages.in libnet.Pod
EXTRA_DIST    += api-main.md api-head.html api-foot.html api-style.css
DISTCLEANFILES = libnet.tag

if ENABLE_HTML
pkghtmldir     = $(docdir)/html
pkghtml_DATA   = html/*

all-local: doc

clean-local:
	-rm -rf html

doc:
	$(MAKE) -C @top_builddir@ $@
endif
