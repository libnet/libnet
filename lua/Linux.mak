# Linux
CC = gcc
LDFLAGS = -fPIC -fno-common -shared
BINDING += nfq.so
CLUA=-I/usr/include/lua5.1
LLUA=-llua5.1

# Example:
# cc -Wall -Werror -g -I wurldtech/rst `libnet-config --cflags --defines`
# `dnet-config --cflags` -O0 -DNDEBUG -fPIC -fno-common -shared
# -I/usr/include/lua5.1 -o wurldtech/lgram/net.so wurldtech/lgram/net.c -lrt
#  -lm `dnet-config --libs` `libnet-config --libs` -llua5.1

