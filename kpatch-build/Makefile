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
INSN     = insn/insn.o insn/inat.o
else ifeq ($(ARCH),ppc64le)
SOURCES += gcc-plugins/ppc64le-plugin.c
PLUGIN   = gcc-plugins/ppc64le-plugin.so
TARGETS += $(PLUGIN)
GCC_PLUGINS_DIR := $(shell gcc -print-file-name=plugin)
PLUGIN_CFLAGS    = -shared $(CFLAGS) -I$(GCC_PLUGINS_DIR)/include \
		   -Igcc-plugins -fPIC -fno-rtti -O2 -Wall
endif


all: $(TARGETS)

-include $(SOURCES:.c=.d)

create-diff-object: create-diff-object.o kpatch-elf.o lookup.o $(INSN)
create-klp-module: create-klp-module.o kpatch-elf.o
create-kpatch-module: create-kpatch-module.o kpatch-elf.o

$(PLUGIN): gcc-plugins/ppc64le-plugin.c
	g++ $(PLUGIN_CFLAGS) $< -o $@

install: all
	$(INSTALL) -d $(LIBEXECDIR)
	$(INSTALL) $(TARGETS) kpatch-gcc $(PLUGIN) $(LIBEXECDIR)
	$(INSTALL) -d $(BINDIR)
	$(INSTALL) kpatch-build $(BINDIR)

uninstall:
	$(RM) -R $(LIBEXECDIR)
	$(RM) $(BINDIR)/kpatch-build

clean:
	$(RM) $(TARGETS) *.{o,d} insn/*.{o,d} gcc-plugins/*.{so,d}
