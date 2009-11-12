CWARNS = -Wall \
	 -pedantic \
        -Wcast-align \
        -Wnested-externs \
        -Wpointer-arith \
        -Wshadow \
        -Wwrite-strings

COPT = -O2 -DNDEBUG -g
CFLAGS = $(CWARNS) -ansi -I$(LUADIR) -fno-common -bundle -undefined dynamic_lookup
CC = gcc
LDLIBS=-ldnet -lnet

.PHONY: net.so
net.so: net.c
	MACOSX_DEPLOYMENT_TARGET="10.3" $(CC) $(COPT) $(CFLAGS) -o $@ $< $(LDLIBS)

deb:	net.c	
	$(CC) -g $(CFLAGS) net.c; touch deb; rm -f opt

opt:	net.c	
	$(CC) $(COPT) $(CFLAGS) net.c; touch opt; rm -f deb

test: test.lua net.so
	lua test.lua

