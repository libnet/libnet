# BUILD FROM GIT #

I build from git using some top-level scripts. Refer to libnet/INSTALL for additional information and libnet/README.win32 if you're building for/on Windows.

## Minimum requirements are: ##

- A C compiler (obviously)

The Autotools:
- autoconf 2.69
- automake 1.14
- libtool 2.4.2


## To build the documentation (optional): ##

- doxygen 1.8.14
- pod2man
    
**...and optionally:**

**For Graphics:**  
- graphviz

**For PDF/PS:**
(The tools found in) The doxygen-latex Package:             

- texlive-extra-utils,
- texlive-latex-extra,
- texlive-fonts-recommended,
- latex-xcolor,
- texlive-font-utils,
- ghostscript

**For CHM:**
On Windows:
- Microsoft HTML Help Workshop (Part of Visual Studio)
Standalone: http://go.microsoft.com/fwlink/p/?linkid=154968

On *nix:
- chmcmd (Part of the Free Pascal Compiler (http://www.freepascal.org/)


## To build LUA bindings (optional): ##

- libdumbnet-dev
(consider using my fork https://github.com/sgeto/libdnet)
    
- liblua5.1-0-dev (See lua/Makefile)

## **To create Debian packages:** ##

- debhelper
- sharutils
- quilt

## General procedure is: ##

`git clone https://github.com/sgeto/libnet.git`

`cd libnet/libnet`

`../Prepare`

`../Build`

and then, one of the following, depending on how you like to install local packages:

`sudo make install`

`../Stow`

`../Package`

**Again, see libnet/INSTALL and libnet/README.win32 for more detailed instructions.**
