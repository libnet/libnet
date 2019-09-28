SUBDIRS       = man html
dist_doc_DATA = CHANGELOG CONTRIB DESIGN_NOTES \
	libnet.doxygen.conf MIGRATION PACKET_BUILDING PORTED \
	RAWSOCKET_NON_SEQUITUR TODO

doc:
	cd $(top_srcdir) && $(DX_ENV) DOCDIR=$(DX_DOCDIR) doxygen doc/libnet.doxygen.conf

