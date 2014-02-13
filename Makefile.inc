SHELL = /bin/sh
CC    = gcc

INSTALL = /usr/bin/install

PREFIX    ?= /usr/local
SBINDIR    = $(DESTDIR)$(PREFIX)/sbin
LIBEXECDIR = $(DESTDIR)$(PREFIX)/libexec/kpatch
DATADIR    = $(DESTDIR)$(PREFIX)/share/kpatch

.PHONY: all install clean
.DEFAULT: all
