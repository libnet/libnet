SUBDIRS        = man
dist_doc_DATA  = MIGRATION.md RAWSOCKET_NON_SEQUITUR
EXTRA_DIST     = fixmanpages.in libnet.Pod
EXTRA_DIST    += api-main.md api-head.html api-foot.html api-style.css
DISTCLEANFILES = libnet.tag

if ENABLE_HTML
pkgdata_DATA   = html/*

clean-local:
	-rm -rf html
endif
