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

- make a mailing list
- make libnet-1.1.6 release candidate
- make libnet-1.1.6 release

Incomplete:

- icmpv6 patches: cksum is wrong
- cksum bug? generally, I don't trust the checksums are correct
- unit test framework
- Rework the internal data structures, they have so much redundancy in their
  internal linking that keeping them correct as pblocks get updated isn't
  possible. Specifically, get rid of ip_offset and h_len, and have pblocks
  find information they need from upper/lower layers when they are coalesced.

