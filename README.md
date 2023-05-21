[![1b][]][1] [![2b][]][2] [![3b][]][3] [![CodeDocs Status][]][CodeDocs] <img align="right" src="doc/libnet.gif">

Packet Construction and Injection
=================================

Libnet is an API to help with the construction and injection of network
packets.  It provides a portable framework for low-level network packet
writing and handling (use libnet in conjunction with libpcap and you can
write some really cool stuff).  Libnet includes packet creation at the
IP layer and at the link layer as well as a host of supplementary and
complementary functionality.

Libnet is very handy with which to write network tools and network test
code.  Some projects, available in Debian/Ubuntu and OpenBSD, using
libnet are:

- [arping](https://github.com/ThomasHabets/arping)
- [ettercap](https://www.ettercap-project.org/)
- [ipguard](http://ipguard.deep.perm.ru/)
- [isic](http://isic.sourceforge.net/)
- [nemesis](https://github.com/libnet/nemesis/)
- [packit](http://packetfactory.openwall.net/projects/packit/)
- [tcptraceroute](https://web.archive.org/web/20130424094134/http://michael.toren.net/code/tcptraceroute/)
- [yersinia](https://web.archive.org/web/20180522141004/http://www.yersinia.net/)

> **NOTE:** Legacy code written for *libnet-1.0.x* is unfortunately
>           **incompatible** with *libnet-1.1.x* and later.  
>           See the [Migration Guide](doc/MIGRATION.md) for porting help.


Using -lnet
-----------

Libnet is installed as a library and a set of include files.  The main
include file to use in your program is:

    #include <libnet.h>

To get the correct search paths to both the header and library files,
use the standard `pkg-config` tool (old `libnet-config` is deprecated):

    $ pkg-config --libs --static --cflags libnet
    -I/usr/local/include -L/usr/local/lib -lnet

The prefix path `/usr/local/` shown here is only the default.  Use the
`configure` script to select a different prefix when installing libnet.

For GNU autotools based projects, use the following in `configure.ac`:

    # Check for required libraries
    PKG_CHECK_MODULES([libnet], [libnet >= 1.2])

and in your `Makefile.am`:

    proggy_CFLAGS = $(libnet_CFLAGS)
    proggy_LDADD  = $(libnet_LIBS)

> Online docs available at <https://codedocs.xyz/libnet/libnet/>.  See
> the man page and [sample test code](sample/) for more information.


Building
--------

First download the [latest release][] from GitHub.  Libnet employs the
[GNU configure and build system][autotools].  The release tarballs and
zip files ship with a pre-built `configure` script:

    $ tar xf libnet-x.y.z.tar.gz
    $ cd libnet-x.y.z/
    $ ./configure && make
    $ sudo make install

To list available options, type <kbd>./configure --help</kbd>

### Building from GIT/GitHub

When building from GIT, use <kbd>./autogen.sh</kbd> to generate the
`configure` script.  For this you need the full suite of the GNU
autotools: autoconf (>=2.69), automake (>=1.14), libtool (>=2.4.2).

How to install the dependencies varies by system, but on many Debian derived
systems, `apt` can be used:

    $ sudo apt install autoconf automake libtool
    $ ./autogen.sh
    $ ./configure && make
    $ sudo make install


### Using Conan

Libnet is available on [Conan Center](https://conan.io/center/libnet).  To use,
add `libnet/1.2` to your `conanfile.txt`

### Building with Docker

First build the dev. contrainer:

    $ cd .devcontainer
    $ docker build -t libnet-builder .

Then compile libnet with docker:

    $ cd ..
    $ docker run -it --rm -v $(pwd):$(pwd) --workdir=$(pwd) libnet-builder
    $ ./autogen.sh
    $ ./configure
    $ make


### Running Unit Tests with CMocka

Running tests in the dev. container (above):

    $ ./autogen.sh
    $ ./configure --enable-tests
    $ make
    $ sudo ./tests/libnet_unit_tests

Approximate output:

    $ ./tests/libnet_unit_tests
    [==========] Running 1 test(s).
    [ RUN      ] test_libnet_build_ethernet
    [       OK ] test_libnet_build_ethernet
    [==========] 1 test(s) run.
    [  PASSED  ] 1 test(s).

### Building the Documentation

To build the documentation (optional) you need doxygen and pod2man:

    $ sudo apt install doxygen
    $ sudo apt install pod2man || sudo apt install perl

For neat graphics in the HTML documentation, also install graphviz.
There is also a PDF version of the docs, to build that you need quite a
few more packages:

    $ sudo apt install texlive-extra-utils texlive-latex-extra \
                       texlive-fonts-recommended latex-xcolor  \
                       texlive-font-utils

For Microsoft CHM docs you need the HTML Help Workshop, which is part
of Visual Studio: http://go.microsoft.com/fwlink/p/?linkid=154968, on
UNIX and GNU/Linux systems, see `chmcmd`, which is available in the
[FreePascal](http://www.freepascal.org/) suite:

    $ sudo apt install fp-utils-3.0.4


Origin & References
-------------------

Libnet is widely used, but had been unmaintained for a long time and its
author unreachable.  This version was forked from the 1.1.3 release
candidate from [packetfactory.net][origin], bug fixed, developed, and
re-released.

Use GitHub issues and pull request feature for questions and patches:

  http://github.com/libnet/libnet

Some old docs are available at:

  http://packetfactory.openwall.net/projects/libnet/index.html

-------------------------------------------------------------------------
- v1.1 (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>  
  http://www.packetfactory.net/libnet
- v1.1.3 and later (c) 2009 - 2013 Sam Roberts <vieuxtech@gmail.com>  
  http://github.com/libnet/libnet
-------------------------------------------------------------------------

[latest release]:  https://github.com/libnet/libnet/releases
[autotools]:       https://autotools.io/
[origin]:          http://packetfactory.openwall.net/projects/libnet/
[1]:               https://github.com/libnet/libnet/actions/workflows/build.yml/
[1b]:              https://github.com/libnet/libnet/actions/workflows/build.yml/badge.svg
[2]:               https://github.com/libnet/libnet/actions/workflows/build-freebsd.yml/
[2b]:              https://github.com/libnet/libnet/actions/workflows/build-freebsd.yml/badge.svg
[3]:               https://github.com/libnet/libnet/actions/workflows/build-windows.yml/
[3b]:              https://github.com/libnet/libnet/actions/workflows/build-windows.yml/badge.svg
[CodeDocs]:        https://codedocs.xyz/libnet/libnet/
[CodeDocs Status]: https://codedocs.xyz/libnet/libnet.svg
