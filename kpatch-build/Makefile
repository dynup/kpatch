include ../Makefile.inc

CFLAGS  = -I../kmod/core
LDFLAGS = -lelf

TARGETS = create-diff-object add-patches-section link-vmlinux-syms


all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

install: all
	$(INSTALL) -d $(LIBEXECDIR)
	$(INSTALL) $(TARGETS) kpatch-build $(LIBEXECDIR)

clean:
	$(RM) $(TARGETS)
