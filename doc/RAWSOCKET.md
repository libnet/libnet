Raw Socket Non-Sequitur
=======================
by Mike D. Schiffman <mike@infonexus.com>

Raw sockets are horribly non-standard across implementations.  Here is
an incomplete list of some of the differences (corrections welcomed).

Solaris, for example, has terrible support for this packet interface.
Older OpenBSD versions and FreeBSD before 11 versions have the
`BSD_BYTE_SWAP` issue where the `ip_len` and `ip_frag` fields must be in
host byte order.  Linux apparently doesn't allow for the injection of
broadcast IP datagrams.  Whenever complete control over the IP header is
desired, use the link layer API.


Linux 2.2+
----------

    IP fragmentation:       performed if packet is larger than MTU
    IP checksum:            always filled in
    IP total length:        always filled in
    IP ID:                  filled in when zero
    IP source address:      filled in when zero
    IP destination address: filled in when zero

    Max packet size before kernel complains: 1500 bytes


Solaris 2.6+
------------

    IP fragmentation bits:  can't specify 
    IP fragmentation:       performed if packet is larger than MTU
    IP DF bit:              always set
    IP checksum:            always filled in

    Max packet size before kernel complains: ?


OpenBSD 2.8+
------------

    IP fragmentation:       performed if packet is larger than MTU

    Max packet size before kernel complains: 8192 bytes

