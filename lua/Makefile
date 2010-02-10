
.PHONY: default build

default: build

BINDING=net.so pcap.so

# OS X
CC = MACOSX_DEPLOYMENT_TARGET="10.3" gcc
LDFLAGS = -fno-common -bundle -undefined dynamic_lookup

# Linux
CC = gcc `libnet-config --cflags --defines` `dnet-config --cflags`
LDFLAGS = -fPIC -fno-common -shared `dnet-config --libs` `libnet-config --libs` -llua5.1

BINDING += nfq.so

build: $(BINDING)

PREFIX=/usr/local

SODIR = $(DESTDIR)$(PREFIX)/lib/lua/5.1/

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

COPT = -O2 -DNDEBUG -g
LUADIR = /usr/include/lua5.1
CFLAGS = $(CWARNS) -I$(LUADIR) $(LDFLAGS)
LDLIBS=-ldnet -lnet

CC.SO := $(CC) $(COPT) $(CFLAGS)

%.so: %.c
	$(CC.SO) -o $@ $< $(LDLIBS)

net.so: net.c
pcap.so: pcap.c
nfq.so: nfq.c
nfq.so: LDLIBS+=-lnetfilter_queue

test: test.lua net.so
	lua test.lua

