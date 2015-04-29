SHELL = /bin/sh
CC    = gcc

INSTALL = /usr/bin/install

PREFIX    ?= /usr/local
LIBDIR    ?= lib
BINDIR     = $(DESTDIR)$(PREFIX)/bin
SBINDIR    = $(DESTDIR)$(PREFIX)/sbin
MODULESDIR = $(DESTDIR)$(PREFIX)/$(LIBDIR)/kpatch
LIBEXECDIR = $(DESTDIR)$(PREFIX)/libexec/kpatch
DATADIR    = $(DESTDIR)$(PREFIX)/share/kpatch
MANDIR     = $(DESTDIR)$(PREFIX)/share/man/man1
SYSTEMDDIR = $(DESTDIR)$(PREFIX)/lib/systemd/system
DRACUTDIR  = $(DESTDIR)/usr/$(LIBDIR)/dracut/modules.d/99kpatch

.PHONY: all install clean
.DEFAULT: all
