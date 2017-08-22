include ../Makefile.inc

CFLAGS += -MMD -MP -I../kmod/patch -Iinsn -Wall -g -Werror
LDLIBS = -lelf

TARGETS = create-diff-object create-klp-module create-kpatch-module
SOURCES = create-diff-object.c kpatch-elf.c \
		  create-klp-module.c \
		  create-kpatch-module.c \
		  create-kpatch-module.c lookup.c

ifeq ($(ARCH),x86_64)
SOURCES += insn/insn.c insn/inat.c
INSN = insn/insn.o insn/inat.o
endif


all: $(TARGETS)

-include $(SOURCES:.c=.d)

create-diff-object: create-diff-object.o kpatch-elf.o \
					lookup.o $(INSN)
create-klp-module: create-klp-module.o kpatch-elf.o
create-kpatch-module: create-kpatch-module.o kpatch-elf.o

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
