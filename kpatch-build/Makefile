include ../Makefile.inc

CFLAGS  += -I../kmod/patch -Iinsn -Wall -g -Werror
LDFLAGS += -lelf

TARGETS = create-diff-object create-klp-module create-kpatch-module
SOURCES = create-diff-object.c kpatch-elf.c \
		  create-klp-module.c \
		  create-kpatch-module.c \
		  lookup.c insn/insn.c insn/inat.c

all: $(TARGETS)

-include $(SOURCES:.c=.d)

%.o : %.c
	$(CC) -MMD -MP $(CFLAGS) -c -o $@ $<

create-diff-object: create-diff-object.o kpatch-elf.o \
					lookup.o insn/insn.o insn/inat.o
create-klp-module: create-klp-module.o kpatch-elf.o
create-kpatch-module: create-kpatch-module.o kpatch-elf.o

$(TARGETS):
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
	$(RM) $(TARGETS) *.o *.d insn/*.d
