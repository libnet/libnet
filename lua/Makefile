
.PHONY: default build

default: build

BINDING=net.so pcap.so

# OS X
CC = MACOSX_DEPLOYMENT_TARGET="10.3" gcc
LDFLAGS = -fno-common -bundle -undefined dynamic_lookup

# Linux
CC = gcc
LDFLAGS = -fPIC -fno-common -shared


BINDING += nfq.so

build: $(BINDING)

prefix=/usr/local

SODIR = $(DESTDIR)$(prefix)/lib/lua/5.1/

.PHONY: install
install: $(BINDING)
	mkdir -p $(SODIR)
	install -t $(SODIR) $(BINDING)

.PHONY: net pcap nfq

net: net.so
	./recoding-test
	sudo ./net-test

pcap: pcap.so
	#./pcap-test

nfq: nfq.so
	#sudo ./nfq-test

# Example:
# cc -Wall -Werror -g -I wurldtech/rst `libnet-config --cflags --defines`
# `dnet-config --cflags` -O0 -DNDEBUG -fPIC -fno-common -shared
# -I/usr/include/lua5.1 -o wurldtech/lgram/net.so wurldtech/lgram/net.c -lrt
#  -lm `dnet-config --libs` `libnet-config --libs` -llua5.1

CWARNS = -Wall \
  -pedantic \
  -Wcast-align \
  -Wnested-externs \
  -Wpointer-arith \
  -Wshadow \
  -Wwrite-strings

CDEFS=`sh ../libnet/libnet-config --cflags --defines` `dnet-config --cflags`
COPT=-O2 -DNDEBUG -g
CLUA=-I/usr/include/lua5.1
CFLAGS=$(CWARNS) $(CDEFS) $(CLUA) $(LDFLAGS) -I../libnet/include -L../libnet/src/.libs/
LDLIBS=`dnet-config --libs` `sh ../libnet/libnet-config --libs` -llua5.1

CC.SO := $(CC) $(COPT) $(CFLAGS)

%.so: %.c
	$(CC.SO) -o $@ $< $(LDLIBS)

net.so: net.c
pcap.so: pcap.c
pcap.so: LDLIBS+=-lpcap
nfq.so: nfq.c
nfq.so: LDLIBS+=-lnetfilter_queue

test: test.lua net.so
	lua test.lua

