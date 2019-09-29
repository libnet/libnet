#!/bin/sh
#
# A bootstrapping script that can be used to generate the autoconf,
# automake and libtool-related scripts of the build process.  Only
# useful for developers updating Makefile.am, configure.ac etc.
# Regular users building from released tarballs can use the shipped
# configure script, that generates Makefile's from Makefile.in's

autoreconf -W portability -vifm $*
