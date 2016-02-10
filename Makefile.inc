SHELL = /bin/sh
CC    = gcc

INSTALL = /usr/bin/install

PREFIX    ?= /usr/local
LIBDIR    ?= lib
LIBEXEC   ?= libexec
BINDIR     = $(DESTDIR)$(PREFIX)/bin
SBINDIR    = $(DESTDIR)$(PREFIX)/sbin
MODULESDIR = $(DESTDIR)$(PREFIX)/$(LIBDIR)/kpatch
LIBEXECDIR = $(DESTDIR)$(PREFIX)/$(LIBEXEC)/kpatch
DATADIR    = $(DESTDIR)$(PREFIX)/share/kpatch
MANDIR     = $(DESTDIR)$(PREFIX)/share/man/man1
SYSTEMDDIR = $(DESTDIR)$(PREFIX)/lib/systemd/system
BUILDMOD   ?= yes

.PHONY: all install clean
.DEFAULT: all
