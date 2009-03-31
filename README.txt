Upstream on libnet is dead.

Debian has unmerged patches.

I have patches to ip_offset handling (used for IP checksumming) to fix memory
corruption bugs.

I also have the start of Lua bindings.


Complete:

- debian patches merged to v1.1.2.1-fork
- autotools from upstream v1.1.3-RC-01 merged to v1.1.2.1-fork
- completed ip_offset patches being merged into ip_offset-patch
- merge to master


In progresss:


Incomplete:

- lua bindings
- build_ipv4_options is known to cause memory corruption under some conditions,
  but fix is more complicated than others and is not merged
- cleanup of in source comments/documentation of libnet data structures
- re-release

