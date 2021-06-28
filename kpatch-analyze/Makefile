include ../Makefile.inc

CFLAGS += -Wp,-MP,-MMD,$(@D)/.$(@F).d -fno-strict-aliasing -Wall \
	  -Wwrite-strings -O2 -g -Wno-sign-conversion -Werror

TARGET = kpatch-sparse
SOURCES = $(wildcard *.c)
OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

GCC_BASE := $(shell $(CC) -print-file-name=)
MULTIARCH_TRIPLET := $(shell $(CC) -print-multiarch 2>/dev/null)

CFLAGS += -DGCC_BASE=\"$(GCC_BASE)\"
CFLAGS += -DMULTIARCH_TRIPLET=\"$(MULTIARCH_TRIPLET)\"

all: $(TARGET)

$(TARGET): $(OBJS)

install: all
	$(INSTALL) -d $(BINDIR)
	$(INSTALL) $(TARGET) $(LIBEXECDIR)
	$(INSTALL) kpatch-analyze $(BINDIR)

uninstall:
	$(RM) -R $(LIBEXECDIR)/$(TARGET)
	$(RM) $(BINDIR)/kpatch-analyze

clean:
	$(RM) $(TARGET) *.[oa] .*.d

-include $(OBJS:%.o=.%.o.d)
