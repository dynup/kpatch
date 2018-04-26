ARCH    = $(shell uname -m)
OBJDIR ?= objs/$(ARCH)

.PHONY: all clean

all: Makefile.include
	git submodule update --init --rebase
	$(MAKE) -C $(OBJDIR)

clean: Makefile.include
	$(MAKE) -C $(OBJDIR) clean
