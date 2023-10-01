LOG_DRIVER        = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/tap-driver.sh

AM_LDFLAGS        = -lcmocka $(top_builddir)/src/libnet.la
TESTS             = unit_tests
TESTS            += udld_unit_tests

check_PROGRAMS    = $(TESTS)

if LINUX
TESTS_ENVIRONMENT = unshare -mrun $(top_srcdir)/test/setup.sh
else
TESTS_ENVIRONMENT = $(top_srcdir)/test/setup.sh
all: $(check_PROGRAMS)
endif
