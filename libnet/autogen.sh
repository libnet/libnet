#!/bin/sh

# A bootstrapping script that can be used to generate the autoconf 
# and automake-related scripts of the build process.
# The result of using "autoreconf -fiW all" should be identical to using this
# script.

set -e -x

aclocal --force --warnings=all -I m4 ${ACLOCAL_FLAGS} || exit 1
libtoolize --copy --force || glibtoolize --copy --force || exit 1
autoconf --force --warnings=all || exit 1
autoheader --force --warnings=all || exit 1
automake --add-missing --copy --force-missing --foreign --warnings=all || exit 1

