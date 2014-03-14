include ../Makefile.inc

CFLAGS  += -I../kmod/patch -Wall -g
LDFLAGS = -lelf

TARGETS = create-diff-object add-patches-section link-vmlinux-syms


all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

install: all
	$(INSTALL) -d $(LIBEXECDIR)
	$(INSTALL) $(TARGETS) $(LIBEXECDIR)
	$(INSTALL) -d $(BINDIR)
	$(INSTALL) kpatch-build $(BINDIR)

clean:
	$(RM) $(TARGETS)
