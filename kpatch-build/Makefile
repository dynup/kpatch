include ../Makefile.inc

CFLAGS  += -I../kmod/patch -Iinsn -Wall -g
LDFLAGS = -lelf

TARGETS = create-diff-object

all: $(TARGETS)

create-diff-object: create-diff-object.c list.h lookup.c lookup.h insn/insn.c \
		    insn/inat.c insn/inat-tables.c insn/asm/inat.h \
		    insn/asm/insn.h insn/asm/inat_types.h
	$(CC) $(CFLAGS) create-diff-object.c lookup.c insn/insn.c insn/inat.c -o $@ $(LDFLAGS)

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
