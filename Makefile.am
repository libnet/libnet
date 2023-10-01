#
# Libnet automake information file
# Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
# All rights reserved.
#
DISTCHECK_CONFIGURE_FLAGS = --enable-doxygen-doc --disable-doxygen-html --disable-samples
ACLOCAL_AMFLAGS           = -I m4 ${ACLOCAL_FLAGS}

bin_SCRIPTS    = libnet-config
pkgconfigdir   = $(libdir)/pkgconfig
pkgconfig_DATA = libnet.pc
dist_doc_DATA  = README.md ChangeLog.md LICENSE
EXTRA_DIST     = README.win32 autogen.sh libnet-config.in
SUBDIRS        = include src win32

if ENABLE_SAMPLES
SUBDIRS       += sample
endif

if ENABLE_TESTS
SUBDIRS       += test
endif

if ENABLE_DOXYGEN
SUBDIRS       += doc

#
# Doxygen rules from m4/ax_prog_doxygen.m4
# 
@DX_RULES@

doc: doxygen-doc
	$(AM_V_GEN)cd $(DX_DOCDIR) && ./fixmanpages && cd -

## The distribution should include man pages, which are generated
dist-hook: doc
else
doc:
	@echo "Doxygen documentation (html + man) disabled, skipping ..."
endif

## Generate MD5 checksum file
MD5 = md5sum
md5-dist:
	@for file in $(DIST_ARCHIVES); do		\
		$(MD5) $$file > $$file.md5;		\
	done

## Check if tagged in git
release-hook:
	@if [ ! `git tag | grep v$(PACKAGE_VERSION)` ]; then				\
		echo;									\
		printf "\e[1m\e[41mCannot find release tag v$(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[5mDo release anyway?\e[0m "; read yorn;			\
		if [ "$$yorn" != "y" -a "$$yorn" != "Y" ]; then				\
			printf "OK, aborting release.\n";				\
			exit 1;								\
		fi;									\
		echo;									\
	else										\
		echo;									\
		printf "\e[1m\e[42mFound GIT release tag v$(PACKAGE_VERSION)\e[0m\n";	\
		printf "\e[1m\e[44m>>Remember to push tags!\e[0m\n";			\
		echo;									\
	fi

## Target to run when building a release
release: doc distcheck release-hook md5-dist
	@echo
	@echo "Resulting release files:"
	@echo "================================================================="
	@for file in $(DIST_ARCHIVES); do						\
		printf "%-32s Distribution tarball\n" $$file;				\
		printf "%-32s " $$file.md5; cat $$file.md5 | cut -f1 -d' ';		\
		mv $$file* ../;								\
	done

# (GNU make only) Unless we say otherwise, spare us the
# “Entering/Leaving directory ...” messages
GNUMAKEFLAGS = $(if $(value VERBOSE),,--no-print-directory)
