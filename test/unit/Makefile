ARCHES ?= aarch64 ppc64le x86_64

.PHONY: all clean submodule-check

all: $(addsuffix -test,$(ARCHES))
clean: $(addsuffix -clean,$(ARCHES))

submodule-check:
	@cd $(shell git rev-parse --show-toplevel) && \
		git diff-index --quiet HEAD test/unit/objs || \
		echo -e "\nWARNING: unit tests are out of date - run \"git submodule update\"\n"

%-test: Makefile.include submodule-check
	$(MAKE) -C objs/$*

%-clean: Makefile.include
	if [ -d objs/$* ]; then $(MAKE) -C objs/$* clean; fi
