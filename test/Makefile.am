bin_PROGRAMS = libnet_unit_tests libnet_udld_unit_tests

libnet_unit_tests_SOURCES = unit_tests.c
libnet_udld_unit_tests_SOURCES = udld_unit_tests.c

libnet_unit_tests_LDFLAGS = -lcmocka
libnet_udld_unit_tests_LDFLAGS = -lcmocka

LDADD = $(top_builddir)/src/libnet.la
