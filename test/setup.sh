#!/bin/sh
# Set up a virtual world in an unshare for the unit tests to run in.

# http://staskobzar.blogspot.com/2017/04/test-anything-protocol-tap-with.html
export CMOCKA_MESSAGE_OUTPUT=TAP

ip link add eth0 type dummy
ip link set eth0 up
ip link set lo up

ip addr  add 192.168.2.200/24 dev eth0
ip route add default via 192.168.2.1

exec "$@"
