#!/bin/sh

set -x

aclocal
autoconf
autoheader
automake --add-missing

