include ../Makefile.inc

CFLAGS  += -I../kmod/patch -Iinsn -Wall -g -Werror
LDFLAGS = -lelf

TARGETS = create-diff-object
OBJS = create-diff-object.o lookup.o insn/insn.o insn/inat.o
SOURCES = create-diff-object.c lookup.c insn/insn.c insn/inat.c

all: $(TARGETS)

-include $(SOURCES:.c=.d)

%.o : %.c
	$(CC) -MMD -MP $(CFLAGS) -c -o $@ $<

create-diff-object: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

install: all
	$(INSTALL) -d $(LIBEXECDIR)
	$(INSTALL) $(TARGETS) kpatch-gcc $(LIBEXECDIR)
	$(INSTALL) -d $(BINDIR)
	$(INSTALL) kpatch-build $(BINDIR)

uninstall:
	$(RM) -R $(LIBEXECDIR)
	$(RM) $(BINDIR)/kpatch-build

clean:
	$(RM) $(TARGETS) $(OBJS) *.d insn/*.d
