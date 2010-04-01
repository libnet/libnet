#!/bin/sh -ex
#
# A bootstrapping script that can be used to generate the autoconf,
# automake and libtool-related scripts of the build process.
#
# $Id: autogen.sh,v 1.2 2004/08/10 13:57:46 gkeramidas Exp $

set -x
set -e

autoreconf -ivf -I . -I /sw/share/aclocal

