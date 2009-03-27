#!/bin/sh
#
# A bootstrapping script that can be used to generate the autoconf,
# automake and libtool-related scripts of the build process.
#

trap "/bin/rm -fr autom4te.cache ; \
    echo 'Failed to regenerate autoconf/automake stuff.'" 0 1 2 15

set -x
set -e

rm -fr autom4te.cache
libtoolize --copy --force
aclocal -I .
autoconf
autoheader
automake --add-missing -a -c --foreign

set +e
trap "echo $0 ok" 0 1 2 15

