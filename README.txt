Upstream on libnet was dead.

Debian and Fedora had unmerged patches.

I had patches to ip_offset handling (used for IP checksumming) to fix memory
corruption bugs, and I had the start of Lua bindings.

I forked from packetfactory.net and am maintaining and rereleasing libnet.

Contact Sam Roberts <vieuxtech@gmail.com> if you have bugs or patches to contribute.

Newest code is at:

  http://github.com/sam-github/libnet

Releases are at:

  http://sourceforge.net/projects/libnet-dev/

In progress:

- confirm AIX fixes worked for Alon
- add me and up-to-date links to copyright and docs
- rerelease
- lua bindings, to libnet, libpcap, and libnfq: these will allow construction,
  capture, modification, injection and reinjection of packets (as well as unit
  testing libnet)


Incomplete:

- redo error handling in net binding
- icmpv6 patches: cksum is wrong
- cksum bug? generally, I don't trust the checksums are correct
- unit test framework
- Rework the internal data structures, they have so much redundancy in their
  internal linking that keeping them correct as pblocks get updated isn't
  possible. Specifically, get rid of ip_offset and h_len, and have pblocks
  find information they need from upper/lower layers when they are coalesced.

