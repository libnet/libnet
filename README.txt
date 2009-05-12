Upstream on libnet is dead.

Debian has unmerged patches.

I have patches to ip_offset handling (used for IP checksumming) to fix memory
corruption bugs.

I also have the start of Lua bindings.

Maybe it's ready to release?

The known bugs aren't worse than it used to be...

Complete:

- debian patches merged to v1.1.2.1-fork
- autotools from upstream v1.1.3-RC-01 merged to v1.1.2.1-fork
- completed ip_offset patches being merged into ip_offset-patch
- merge to master
- completed ip4 options fixes
- update changelog
- get host for release tarballs: sourceforge


In progresss:

- confirm installation works
- re-release


Incomplete:

- lua bindings

