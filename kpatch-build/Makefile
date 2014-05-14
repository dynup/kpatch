include ../Makefile.inc

CFLAGS  += -I../kmod/patch -Wall -g
LDFLAGS = -lelf

TARGETS = create-diff-object

all: $(TARGETS)

%: %.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

create-diff-object: create-diff-object.c list.h lookup.c lookup.h
	$(CC) $(CFLAGS) create-diff-object.c lookup.c -o $@ $(LDFLAGS)

install: all
	$(INSTALL) -d $(LIBEXECDIR)
	$(INSTALL) $(TARGETS) $(LIBEXECDIR)
	$(INSTALL) -d $(BINDIR)
	$(INSTALL) kpatch-build $(BINDIR)

uninstall:
	$(RM) -R $(LIBEXECDIR)
	$(RM) $(BINDIR)/kpatch-build

clean:
	$(RM) $(TARGETS)
