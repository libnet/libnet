libnet API Documentation {#mainpage}
============================
1998 - 2017 The libnet Developer Community


Content(s)
-----
- [Main Page](index.html)
- Files
  - [File List](files.html)
  - [Globals](globals.html)
- Stuff
  - [Rawsocket Non Sequitur](rawsocket_non_sequitur.html)
	  - Some Sub-sub-page
  - Design Notes
  - Hacking
  - TODO
- Bindings
	- Lua
	- [Python](https://github.com/allfro/pylibnet "pylibnet")
- Page
- More Page!
	- Me Another Sub-page, yay!
- [TODO](index.html#Topics-TODO)


Introduction
------------

**Attention:** Most on the stuff on this page is either placeholder text and/or
work in progress.
At best, you should take the content on this page half-serious.
I invite you to help expand/improve it.

This manual documents the low-level libnet API. **If you're planning to this API
directly, you're signing up for some pain.** Just kidding. (I'm not kidding)

Although there aren't many up-to-date places to look for libnet information these
days (yet), you still might not want to get started learning about libnet by reading 
this document. These pages provide an overview of (some) the internals of libnet
with links to the relevant parts of the code. If you "just want it to work"
or if this is all very new to you, then you should first refer to [these](http://www.yomama.com)
(more or less) separate set of pages.
Be sure to check out the man pages as well.

The libnet API deliberately lacks most convenient functions. As further explained
in [Design Notes](Design_Notes.html "Design Notes"), those happen behind the 
scenes, are left to complementary libraries, higher-level libraries or to
"bindings" such as pcap, Python, Lua, etc. and have features such as ~~object
systems and main loops~~ that allow a much more convenient API.

The low-level API also contains plenty of clutter to support integration with
arbitrary ~~object systems, languages, main loops~~, and so forth. These features
add a lot of noise to the API that you probably don't care about unless you're
coding a binding.

For now, and probably never will there be similar docs for libnet's internals.
So if you want to get oriented with the libnet source code (because you're interested
in patching the code for example), you should dive straight into each source file, 
read the source and the comments surrounding it, and... just... figure the rest out!
Or ask about it [here](https://github.com/sgeto/libnet/issues "Report bugs").
If that's something you think you're you can see yourself doing then **Welcome Aboard!**
By the way, it's also a good idea to go through some of the commits to understand
the purpose or aim of whoever had their hands on the source before you.
There will be a "[Hacking](Hacking.html)" section soon that is intended to
guide and assist developers through this adventures journey. 

That is, if I don't lose interest, any hope or my sanity before that. 
Just kidding. (I'm not kidding)

Stay tuned.

**Last Modified:** *Wed, 26 Apr 2017 02:58:54 +0300*


TODO
----

- try to make it sound smart
- replace stuff inside ~~ with stuff that is actually true
- call mom and dad
- try to get Inbal back :-(
- re-install Windows
- create a separate "doc" branch and never ever (ever) commit anything relate to it directly to master (lesson learnt)