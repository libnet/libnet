Change Log
==========

All relevant changes are documented in this file.  For a complete list
of contributors, see the GIT commit log.


[v1.3][UNRELEASED]
---------------------

### Changes

- License change of critical files from 4-clause BSD to 3-clause and
  2-clause BSD.  This fixes issue #85: "GPL license compatibility".
- Migrate from Travis-CI (Linux) and Appveyor (Win32) to GitHub Actions
- Win32 changes:
  - switch to npcap from winpcap
  - Simplify and update build scripts
  - Encode version in DLL instead of in filename

**Valery Ivanov:**
- Add support for LLDP, mandatory TLVs.
- Add support for Cisco UniDirectional Link Detection (UDLD), RFC5171
- Initial support for unit tests:
  - `libnet-build_ethernet()`
  - Complete UDLD API tests
- Initial "devcontainer": provide VS Code development environment for
  rapid setup of a development environment
- Run unit tests in GitHub Actions
- New  GitHub Action for FreeBSD 13 clang/gcc

**Beniamin Sandu:**
- Calling `libnet_init()` with a RAW type no longer sets a TX buffer max
  size.  Use the new `libnet_setfd_max_sndbuf()` instead when needed.

**Hervé Boisse:**
- Remove support for `SOCK_PACKET` sockets causing invalid builds on,
  e.g., musl libc.  We assume everyone on Linux has `PF_PACKET` now.

### Fixes

- Fix #139: fail-to-build-from-source on FreeBSD

**Valery Ivanov:**
- Fix #122: unused parameter warnings
- Fix #123: potential memory leak in `libnet_cq_add()`
- Fix #124: potential name conflict with C++ keyword `new`

**Thomas Habets:**
- Fix #96: pointer type warnings when dumping raw data with `%p`
- Fix #97: non-standard types:
  - `int64_t` instead of `__int64_t` for mingw cross build
  - `uint32_t` instead of `u_int` and `uint16_t` instead of `u_short`
- Fix #98: lots of signed vs unsigned comparisons
- Fix #102: possible buffer overflows in `libnet_plist_chain_dump_string()`

**Bernhard M. Wiedemann:**
- Reproducible build fixes for man-page generation, use LC_ALL=C and UTC
- Simplify `fixmanpages`

**Adrian Reber:**
- Fix #120: possible NULL pointer dereference in `libnet_cq_add()`
- Fix #120: memory leak in `libnet_plist_chain_new()`

**Stephan Hartmann:**
- Fix segmentation fault in `libnet_ifaddrlist()`

**Andy Roulin:**
- Fix #150: segfault when number of IPs > 512


[v1.2][] - 2019-10-16
---------------------

Release curated by Sam Roberts and Joachim Nilsson.

### Changes

- Removed Lua bindings from repo and dist files, now available separately
- Removed generated HTML and Nroff (man pages) documentation files, must
  be regenerated with Doxygen using `make doc`
- Add `pkg-config` support with `libnet.pc`, replaces `libnet-config`
  tool, although it is kept for compatibility for now
- Factorize socket setup code for socket opening to provide output
  device selection for IPv4
- Make `libnet_get_hwaddr()` work with 802.1q interfaces in bpf (BSD)
- New API for OSPF HELLO messages, with neighbor

### Fixes

- Use `getifaddrs()` on OpnBSD and Linux
- For samples, `netinet/in.h` is not on windows
- Fix errors with missing `IPPROTO_MH` on windows
- Fix build error on Mac OS X
- Fix #34 checksum caculation when IPv6 extension headers being used
- Remove unneeded trailing `-Wl` from `-version-info` line
- `libnet_build_snmp()` fix warning
- Use `LIBNET_*RESOLVE` const in `libnet_name2addr*`
- Fix i486 sample synflood6 warning
- Some samples need `#include<netinet/in.h>` for `IPPROTO_*` on OpenBSD 5.2
- Fix gcc warnings
- Check for `socklen_t`.  Suggested by g.esp and Stefanos Harhalakis
- libnet: update for obsolete INCLUDE directive
- Fix warning inside comment
- Automatic link options `#pragma comment(lib, ...)` are only for MSVC
- Fix several warnings for MS C/C++ compiler
- `libnet_open_raw4()` doesn't return a SOCKET on win32
- Fixes error messages sometimes include newline, sometimes not
- Properly set `l->err_buf` if `libnet_ifaddrlist()` fails
- dlpi: Try harder to find the device for the interface
- dlpi: Correctly extract unit number from devices with numbers in their name
- Make interface selection work for interfaces with multiple addresses
- Fix memory leak, device list needs to freed after use
- Fix file descriptor leak in `libnet_ifaddrlist()`
- Fix `libnet_get_hwaddr()` for large(!) number of interfaces
- Fix to support musl libc, removes support for GLIBC <2.1
- Fix win32 buffer overrun in `libnet_get_ipaddr4()`
- Interface selection was ignoring interfaces with IPv6
- Use `LIBNET_API` on public functions, instead of an export file
- Add Visual Studio 2010 project files, with build instructions
- Define INET6 on IRIX, making libnet compile cleanly
- Check for FreeBSD pre-11 before enabling `LIBNET_BSD_BYTE_SWAP`
- Use `LIBNET_BSDISH_OS` and `LIBNET_BSD_BYTE_SWAP` on Darwin
- Add BSD byteswap for Darwin. Otherwise `sendto(` returns `EINVAL`
- `netinet/in.h` is needed for `IPPROTO_` and `sockaddr_in`


[v1.1.6][] - 2012-03-06
-----------------------

Release curated by Sam Roberts.

### Changes
- Note about why including libnet.h breaks dnet.h/dumbnet.h (Sam Roberts)
- Clean up use of single and bracket quotes. (Sam Roberts)
- FreeBSD and Solaris volunteers to contibute. (Sam Roberts)
- Prep for 1.1.6 release, such as bumping version (Sam Roberts)
- Add people who have volunteered to check release candidates. (Sam Roberts)
- Rework libnet_autobuild_ipv6() to eliminate code duplication. (Sam Roberts)
- Implemented libnet_autobuild_ipv6() (repolho)
- Implemented unix version of libnet_get_ipaddr6() (repolho)
- Reintroduce libnet_pblock_record_ip_offset() which is empty. (Sam Roberts)
- Make clear that all contributions are under libnet copyright. (Sam Roberts)
- Update for doxygen 1.7.4. (Sam Roberts)
- Note that PORTED is no longer maintained. (Sam Roberts)
- Note that CONTRIB is no longer maintained. (Sam Roberts)
- Prep for upcoming 1.1.6 release. (Sam Roberts)
- Remove BUGS, it referred to non-existent code. (Sam Roberts)
- Reworked icmpv6 patch to parallel the form of icmpv4 support. (Sam Roberts)
- Don't depend on netinet/ip.h. (Sam Roberts)
- Remove unused variable. (Sam Roberts)
- Support building ICMPv6 packets. (someone)
- Use SO_BINDTODEVICE to force packets out opened device. (someone)
- Always use an IPPROTO of TCP when calculating TCP checksums. (Sam Roberts)
- Use correct addr type for addrlen calculation. (someone)
- libnet_build_igmp reserved field was mistakenly called 'code' (Sam Roberts)
- Documentation doesn't include any gif files. (Sam Roberts)
- Enable IPV6 support on Solaris 11. (Rich Burridge)
- Presence of linux's PF_PACKET sockets is now detected. The acinclude.m4
  merged in from packetfactory's 1.1.3-rc branch mysteriously assumed that
  that there was no PF_PACKET if the target OS was linux, which is the
  opposite of what we want. (Sam Roberts)
- pblock_append deals with raw memory and structs, so declare it correctly
  (Sam Roberts)
- Clarified types and sizes of DHCP/BOOTP chaddr, sname, and file. chaddr is a
  hardware address, with size specified separately, whereas sname and file are
  null terminated strings. (Sam Roberts)
- Explicitly ignore return value of write (some systems now warn about this).
  (Sam Roberts)
- Synchronize comment about h_len with parameter name in function. (Sam Roberts)
- mkinstalldirs is replaced by autogen.sh. Maybe it shouldn't be checked in?
  (Sam Roberts)
- autogen retries if /sw/... doesn't exist (Sam Roberts)

### Fixes

- Only use getifaddrs() if it exists. (reported by Dagobert Michelsen) (Sam Roberts)
- ICMPv6 struct is too long, so use length macro (sickmind@lavabit.com) (Sam Roberts)
- ICMPv6 pblock sizes are needed to calculate IPv6's ip_len (reported by
  sickmind@lavabit.com) (Sam Roberts)
- Fix doc comment format errors reported by doxygen. (Sam Roberts)
- Fixed typo in error message. (Thomas Habets)
- Trying to fix write errors (Víctor Martínez)
- Fix libnet_build_igmp() to not reverse the order of the ip address. libnet
  APIs that take IP addresses as a uint32_t expect them to already be in
  network byte order. (Sam Roberts)
- Fixes a buffer overflow issue when copying chaddr, file, and sname fields to
  the DHCP header. (allfro)
- Fixes improper calculation of header size when libnet_pblock_probe is
  called. payload_s must be added to the header length in order to accommodate
  for the existence of a non-NULL payload. Otherwise the user is prompted with
  a 'memcpy would cause overflow' error and the program exits. (allfro)
- Fixes incorrect memory block size set in the timeexceed and redirect
  builders. The n variable does not add the size of the payload (payload_s)
  for proper allocation of the buffer when payload is not NULL and payload_s
  is greater than 0. This results in a memcpy buffer overflow error when
  libnet_pblock_append is called exiting the program. (allfro)
- Fixes a bug that incorrectly converts the addr, mask, and next_hop fields to
  network byte order. Users will usually call libnet_name2addr4 to fill these
  fields and this function already provides a network byte-ordered
  value. (allfro)
- snap parameter was getting copied into the dhost field. (Sam Roberts)
- h_len is no longer used, so pass zero. Coverity noticed that stack garbage
  was being passed instead of a valid value, its just that the value isn't
  used, and incluing l->total_size is wrong when the pblock is being updated
  (though it will work on pblock creation). (Sam Roberts)
- Length n should include the value_hdr. (Sam Roberts)
- Coverity: UNINIT (Jiri Popelka)
- Coverity: REVERSE_INULL (Jiri Popelka)
- Coverity: RESOURCE_LEAK (Jiri Popelka)
- Coverity: OVERRUN_STATIC (Jiri Popelka)
- Coverity: OVERRUN_STATIC (Jiri Popelka)
- Coverity: OVERRUN_STATIC (Jiri Popelka)
- Coverity: FORWARD_NULL (Jiri Popelka)
- Coverity: FORWARD_NULL (Jiri Popelka)
- Coverity: CHECKED_RETURN (Jiri Popelka)
- build_ipv6: set higher traffic class bits (Ulrich Weber)
- Fix missing uint instead of u_int (Dagobert Michelsen)


[v1.1.5][] - 2010-11-03
-----------------------

Release curated by Sam Roberts.

### Changes
- IRIX: Get MAC address from `ioctl()`, not by spawning shell. (Thomas Habets)
- Cleaned up implementations of `libnet_get_hwaddr()`, some leaked
  memory, one returned a pointer to data on the stack, and the others
  return a pointer to static data. I'm settling on the non-reentrant
  static data form. (Sam Roberts)
- Further simplify `autogen.sh` (Sam Roberts)
- Removed dependency on `net/bpf.h`, and on `pcap.h`. (Sam Roberts)
- `LBL_ALIGN` check is unused, removing. (Sam Roberts)
- Don't include `pcap.h` if we've already got `net/bpf.h`, pcap has it's
  own bpf. (Sam Roberts)
- Get DLT types from the source, `pcap.h`. (Sam Roberts)
- Use `autoconf -ivf` in autogen.sh (suggested by alon.barlev@gmail.com)
  (Sam Roberts)
- Add a link to the old docs. (Sam Roberts)
- Added links to github and sourceforge. (Sam Roberts)
- Replace C99/C++ comments with traditional C
  comments. (alon.barlev@gmail.com) (Sam Roberts)
- Closer backwards compat, assume its ipv4 if it's not ipv6. This seems
  totally wrong, but so it goes. (Sam Roberts)
- Try using the `ip_len` header field to guess the input buffer's
  size. (Sam Roberts)
- `libnet_do_checksum()`, despite being "internal", is used by external
  code. libnet needs to maintain backwards API compatibility, tcpsic
  from the isic package is an example of a binary failing when calling
  the new API with the old arguments. (Sam Roberts)
- Use libtool-1 or libtool-2 whatever available (alon.barlev@gmail.com)
  (Sam Roberts)
- Remove dead code. (Sam Roberts)
- h_len is calculated for ip, udp, tcp, icmp, and igmp, so is allowed to
  be zero. (Sam Roberts)
- Avoid mallocing zero bytes, it perturbs electric fence. (Sam Roberts)
- `ip_offset` is now calculated on the fly, and UDP and TCP no longer
  use `h_len` (Sam Roberts)
- IP offset calculation should allow nesting of IP protocols. (Sam Roberts)
- Remove gccisms in bitfield definitions. (Sam Roberts)
- injection type `of LIBNET_NONE`, for packet construction without
  injection (also, more const correctness) (Sam Roberts)
- Notes about checksumming. (Sam Roberts)
- Updated comments and notes. (Sam Roberts)
- Added missing pblock types, and made strings consistent with
  definitions. (Sam Roberts)
- Change version policy, we will be 1.1.4 until 1.1.5 is released. (Sam Roberts)
- Bring CHANGELOG up to date with today, and script used to generated
  it. (Sam Roberts)
- Begin implementation and tests for repairing pblocks after an
  update. (Sam Roberts)
- Clarifications in document comments. (Sam Roberts)
- Don't doxygen process internal header libnet-headers.h (Sam Roberts)
- Note about `build_data`, which doesn't update `ip_offset`, among other
  problems. (Sam Roberts)
- Why don't TCP and UDP use the DATA pblock type? (Sam Roberts)
- whitespace cleanup (Sam Roberts)
- Summarize changes for log. (Sam Roberts)
- Reindented, removing hard tabs, and using consistent brace
  positioning. (Sam Roberts)
- configure.in: Check for `uint{16,32,64}_t` (Thomas Habets)
- Use `uint64_t`, not `u_int64_t` (Thomas Habets)
- configure.in: check for `gethostbyname2()` (Thomas Habets)
- define a lying `gethostbyname2()` if it's not defined (Thomas Habets)
- define `STDOUT_FILENO` if it's not defined (Thomas Habets)
- Configure switch to install samples (Sam Roberts)
- Attempt at applying a patch to get installable samples, which doesn't
  work. (Sam Roberts)
- Convert CRLF to LF. (Sam Roberts)
- Auto* changes to work on OS X from git checkout. (Sam Roberts)
- Add srcdir to include path. (Sam Roberts)
- Beginning 1.1.5 development. (Sam Roberts)

### Fixes
- Compile fix for IRIX (added includes) (Thomas Habets)
- Don't explicitly check for UID 0, we may have capabilities even if not
  root. (Thomas Habets) (Sam Roberts)
- Visual C++ compiler(v9.0) uses bitfield type as a hint to pad the
  bitfield, so struct was too long. (Sam Roberts)
- Make `libnet_get_hwaddr()` work in the last few releases of OpenBSD
  (stu@spacehopper.org) (Sam Roberts)
- Don't distribute `libnet.h`, it is generated by `configure`
  (alon.barlev@gmail.com) (Sam Roberts)
- AIX build failures fixed, cause was inclusion of system headers libnet
  no longer uses (alon.barlev@gmail.com) (Sam Roberts)
- checksum would segfault if a IP checksum was requested for a non-ipv4
  header (Sam Roberts)
- merged icmpv6 patch in, but I believe either it or the
  `sample/icmp6_unreach` generates the cksum incorrectly
  (victor@inliniac.net) (Sam Roberts)
- Avoid looking at `/dev` and `/usr/include` when cross-compiling
  (alon.barlev@gmail.com) Alon: The following code support cross
  compiling: 1. You CANNOT check for `/usr/include` stuff as cross
  compiler is installed else-where. Autoconf know how to do this, use
  its header detection logic and ask the result. 2. Testing for `/dev/`
  can be done only when not cross compiling... (Sam Roberts)
- Corrected `target_os` check, it was broke for linuxgnu, and m4 syntax
  was invalid (alon.barlev@gmail.com) Alon:The following change is
  needed in order to solve two issues: 1. linuxgnu and such target
  os. 2. You cannot set variable with space before '=' as it tries to
  execute the variable... 3. Print result of test in case of linux (Sam
  Roberts)
- `--with-link-layer` broken, was using wrong macro name, and didn't
  include all link types (Sam Roberts)
- `ac_cv_c_bigendian` is yes, not "big" (alon.barlev@gmail.com) (Sam Roberts)
- `libnet_t`'s fd should be initialized to an invalid value, or
  `libnet_destroy()` will close stdin. (Sam Roberts)
- Alon's use of `AC_CHECK_HEADERS` fails to detect headers. Reverted
  part of 57acd56f09158decb69f301e7547ce8cde6ac63f (Sam Roberts)
- With `link_none`, the link apis were failing with not error
  message. (Sam Roberts)
- man doc makefile wasn't correctly referring to the srcdir
  (alon.barlev@gmail.com) (Sam Roberts)
- autotools patches for cross compiling and separate builddir
  (alon.barlev@gmail.com) (Sam Roberts)
- html doc makefile wasn't correctly referring to the srcdir
  (alon.barlev@gmail.com) (Sam Roberts)
- `libnet_build_tcp()` was not returning the ptag. (Sam Roberts)
- Packet boundaries are now passed to `_do_checksum()`, so it can
  validate its input. Hopefully, this will end the recurring
  segmentation faults due to buffer overruns. (Sam Roberts)
- TCP building is triggering memory overwrites; closer examination shows
  the link list manipulation to be wrong, and the checksumming approach
  to be incapable of working. I reworked code to simplify and clarify
  how it works currently, in preparation to fixing it. (Sam Roberts)
- Null the pointer in the about-to-be-freed structure, not the one on
  the stack. (Sam Roberts)
- libnet_pblock_insert_before() didn't remove ptag2 from old location (Sam Roberts)
- Declared many constant arguments as const, const-correct code spews
  warnings when built against libnet. (Sam Roberts)
- Include pcap DLT_ types from correct header, was using an internal one
  before. (Sam Roberts)
- Declared many constant arguments as const, const-correct code spews
  warnings when built against libnet. (Sam Roberts)
- `libnet_clear_packet()` wasn't clearing all packet context. (Sam Roberts)
- Add `libnet_dll.c` as extra, so its there for win32, and build
  `libnet_link.c` (Sam Roberts)
- This file wasn't being built, and needed to include bpf to build. (Sam Roberts)
- Forgot to make device a const string here, too. (Sam Roberts)
- make string argument constant (Sam Roberts)
- only ignore Makefile in `libnet/` (Sam Roberts)
- Replace `u_intX_t` with C99 `uintX_t`. (Thomas Habets)
- `pclose()` following `popen()`, not `fclose()` (Thomas Habets)
- snoof & dlpi: don't free on `libnet_link_close()` (Thomas Habets)
- The non-standard types are no longer used. (Sam Roberts)
- `/sw/..` path doesn't always exist (Sam Roberts)
- `src/libnet_link_snoop.c`: Only fclose if `f!=NULL  (Thomas Habets)
-  rc/libnet_link_snoop.c`: fixed snoop-based backend. Works on
   IRIX. (Thomas Habets)
- Pointers not cleared after free could lead to double
  deallocation. (Sam Roberts)
- Update autobuild endianness and unaligned checks. (Mike Frysinger)
  (Sam Roberts)
- Adjust srcdir and builddir so libnet can build out-of-tree (Robin
  Getz/Mike Frysinger) (Sam Roberts)


[v1.1.4][] - 2009-06-09
-----------------------

Release curated by Sam Roberts.

### Changes
- Strip CRLF from files not in win32/ (Robert Scheck)

### Fixes
- libnet was using `HAVE_CONFIG_H` in a public header to deal with
  platform types.  https://bugzilla.redhat.com/show_bug.cgi?id=501633
- Patch to `libnet.h.in` for compilation on HURD (David Paleino)


[v1.1.3][] - 2009-05-11
-----------------------

Merged 1.1.3 release candidate from packet factory, 1.1.2, debian
patches, and my own fixes, including bugs causing memory corruption.

Release curated by Sam Roberts.

### Changes
- Convert from latin-1 to utf-8, from Robert Scheck. (Sam Roberts)
- Removed CVS crud, again. (Sam Roberts)
- Applied autotools cleanup patch from Stefanos. (Sam Roberts)
- Applied patch from Stefanos to remove the autotools ephemera that leaked
  back in. (Sam Roberts)
- Updated .so revision to be one backwards compatible interface after
  1.1.2.1-fork's. (Sam Roberts)
- merged autogen.sh from 1.1.3, now ltmain.sh comes from autogen.sh (Sam
  Roberts)
- Update .so version to be one src change past the last debian release.
  Debian patches to v1.1.2.1 used 4:0:3, in error, so we use 5:0:4, as per
  the rules. See Makefile.am comments for reference. (Sam Roberts)
- autotools merged from v1.1.3 to v1.1.2 (Sam Roberts)
- Remove autotools. And some garbage local files that should not have been
  in upstream tarball. (Sam Roberts)
- Removed object files and cvs conflict residue contained in original
  package. (Sam Roberts)
- doxygen configuration updated, html seems fine - I don't know about the
  man pages. (Sam Roberts)
- strip CVS subdirectories from upstream package (Sam Roberts)
- Added a `libnet_version()` function
- Internals:
  - added a payload builder macro
  - Added an HSRP builder
- Added `AC_PREREQ(2.50)` to `configure.in` to come correct
- Added a libnet UDP header prototype. We need to add an entire exported
  interface for the sole purpose of casting captured packets, this will
  presumably be a part of the pcap integration.
- Added `libnet_adv_write_raw_ipv4()`
- Updated the autoconf/automake stuff to be up to date with the latest
  versions. We now use libtool.
- Changed all empty function prototypes to contain the void keyword
- Removed all C++ style comments
- Removed the configure.in check for `strerror()`

### Fixes
- Fixed various errors, including memory corruption, when IPv4 options
  are modified.  (Sam Roberts)
- Fixed doxygen errors and warnings, and added a deveoper script to
  prepare libnet. (Sam Roberts)
- Patches from Stefanos. (Sam Roberts)
- Fix for debian bug 418975, IPv6 wasn't updating `ip_offset`. See
  http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=418975 and sample
  `test_ipv6_icmpv4.c` for more info and reproduction. (Sam Roberts)
- 802.1Q and 802.1X header documentation was incorrectly using `/** /**`
  is reserved for doxygen documentation comments, and they didn't have
  any.  That those packet headers, and no others, were marked that way
  was causing man pages to be generated for them, incomplete man pages
  that then were being hacked by debian patches 02- and 03-. (Sam
  Roberts)
- Bug fixes and reproduction code for `ip_offset` accounting problem in
  `libnet_build_ipv4()` (Sam Roberts)
- debian patch 06 attempts to free the wrong pointer, and also leaks memory
  from the inner loop. (Sam Roberts)
- libnet (inconsistently) uses various signed and/or unsigned typedefs
  instead of char ANSI C uses char for string literals and the standard
  library, so this generates many warnings. I've fixed a number of the
  places where types representing null-terminated strings weren't typed
  correctly. (Sam Roberts)
- Merged Debian fixes:
  - 09-fix_hurd-i386_build.patch from debian source package See
    http://packages.debian.org/source/sid/libnet (Sam Roberts)
  - 08-fix_libnet_checksum.c.patch from debian source package See
    http://packages.debian.org/source/sid/libnet (Sam Roberts)
  - 07-add_libnet-cq-end-loop.patch from debian source package See
    http://packages.debian.org/source/sid/libnet (Sam Roberts)
  - 06-fix_libnet_pblock_coalesce_leak.patch from debian source package See
    http://packages.debian.org/source/sid/libnet (Sam Roberts)
  - 04-fix_libnet_build_ntp.patch from debian source package See
    http://packages.debian.org/source/sid/libnet (Sam Roberts)
  - 03-fix_libnet_802_1x_hdr.3.patch from debian source package See
    http://packages.debian.org/source/sid/libnet (Sam Roberts)
  - 02-fix_libnet_802_1q_hdr.3.patch See
    http://packages.debian.org/source/sid/libnet (Sam Roberts)
  - 01-fix_libnet-functions.h.3.patch from debian source package See
    http://packages.debian.org/source/sid/libnet (Sam Roberts)
- Fixed a bug in `libnet_build_ntp()` where two arguments werent used
  due to a typo
- Fixed a bug ln `libnet_name2addr4()` in which it didnt call hstrerror
- Fixed a memory leak in `libnet_if_addr.c`
- Fixed the `cdp.c` sample code
- Fixed the checksum function
- Fixed a signed/unsigned comparison warning in the
  `LIBNET_DO_PAYLOAD()` macro


[UNRELEASED]: https://github.com/libnet/libnet/compare/v1.2...HEAD
[v1.2]:       https://github.com/libnet/libnet/compare/v1.1.6...v1.2
[v1.1.6]:     https://github.com/libnet/libnet/compare/v1.1.5...v1.1.6
[v1.1.5]:     https://github.com/libnet/libnet/compare/v1.1.4...v1.1.5
[v1.1.4]:     https://github.com/libnet/libnet/compare/v1.1.3...v1.1.4
