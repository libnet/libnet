.PHONY: default build test

-include local.mak

default: build

BINDING+=net.so

UNAME=$(shell uname)

include $(UNAME).mak

build: $(BINDING)

prefix=/usr

SODIR = $(DESTDIR)$(prefix)/lib/lua/5.1/

.PHONY: install
install: $(BINDING)
	mkdir -p $(SODIR)
	../libnet/build-aux/install-sh -t $(SODIR) $(BINDING)

CWARNS = -Wall \
  -Wcast-align \
  -Wnested-externs \
  -Wpointer-arith \
  -Wshadow \
  -Wwrite-strings

DNETDEFS=$(shell dnet-config --cflags)
LNETDEFS=$(shell sh ../libnet/libnet-config --cflags --defines) 
COPT=-O2 -DNDEBUG -g
CFLAGS=$(CWARNS) $(CDEFS) $(CLUA) $(LDFLAGS) -I../libnet/include -L../libnet/src/.libs/
LDLIBS=$(LLUA)

LDDNET=$(shell dnet-config --libs)
LDLNET=$(shell sh ../libnet/libnet-config --libs)

CC.SO := $(CC) $(COPT) $(CFLAGS)

%.so: %.c
	$(CC.SO) -o $@ $^ $(LDLIBS)

net.so: net.c libnet_decode.c
net.so: LDLIBS+=$(LDDNET) $(LDLNET)
net.so: CDEFS=$(DNETDEFS) $(LNETDEFS)
net.so: dnet.h

dnet.h:
	if test -e /usr/include/dumbnet.h; then echo '#include<dumbnet.h>' > dnet.h; \
	else echo '#include<dnet.h>' > dnet.h; fi

TNET=$(wildcard test-*.lua)
TOUT=$(TNET:.lua=.test)

echo:
	echo $(TOUT)

test: net.test $(TOUT)

%.test: %.lua net.so
	lua $<
	touch $@

%.test: %-test %.so
	lua $<
	touch $@

%.test: %-test net.so
	lua $<
	touch $@

