ARCH    = $(shell uname -m)
OBJDIR ?= objs/$(ARCH)

.PHONY: all clean

all: Makefile.include
	@cd $(shell git rev-parse --show-toplevel) && \
		git diff-index --quiet HEAD test/unit/objs || \
		echo -e "\nWARNING: unit tests are out of date - run \"git submodule update\"\n"
	$(MAKE) -C $(OBJDIR)

clean: Makefile.include
	if [ -d $(OBJDIR) ]; then $(MAKE) -C $(OBJDIR) clean; fi
