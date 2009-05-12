Upstream on libnet is dead.

Debian and Fedora have unmerged patches.

I have patches to ip_offset handling (used for IP checksumming) to fix memory
corruption bugs, and I have the start of Lua bindings.

I've forked from packetfactory.net and am maintaining and rereleasing libnet.

Contact Sam Roberts <vieuxtech@gmail.com> if you have bugs or patches to contribute.


Complete:

- debian patches merged to v1.1.2.1-fork
- autotools from upstream v1.1.3-RC-01 merged to v1.1.2.1-fork
- completed ip_offset patches being merged into ip_offset-patch
- merge to master
- completed ip4 options fixes
- update changelog
- get host for release tarballs: sourceforge
- confirm installation works
- re-release


In progresss:


Incomplete:

- lua bindings
- debian packaging

