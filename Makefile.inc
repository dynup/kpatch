SHELL = /bin/sh
CC    = gcc

INSTALL = /usr/bin/install

ARCH       = $(shell uname -m)

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
UPSTARTDIR = $(DESTDIR)/etc/init

# The core module is only supported on x86_64
ifeq ($(ARCH),x86_64)
BUILDMOD  ?= yes
endif

.PHONY: all install clean
.DEFAULT: all
