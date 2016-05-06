include ../Makefile.inc
KPATCH_BUILD ?= /lib/modules/$(shell uname -r)/build
KERNELRELEASE := $(lastword $(subst /, , $(dir $(KPATCH_BUILD))))

all: clean
ifeq ($(BUILDMOD),yes)
	$(MAKE) -C core
endif

install:
ifeq ($(BUILDMOD),yes)
	$(INSTALL) -d $(MODULESDIR)/$(KERNELRELEASE)
	$(INSTALL) -m 644 core/kpatch.ko $(MODULESDIR)/$(KERNELRELEASE)
	$(INSTALL) -m 644 core/Module.symvers $(MODULESDIR)/$(KERNELRELEASE)
endif
	$(INSTALL) -d $(DATADIR)/patch
	$(INSTALL) -m 644 patch/* $(DATADIR)/patch

uninstall:
ifeq ($(BUILDMOD),yes)
	$(RM) -R $(MODULESDIR)
endif
	$(RM) -R $(DATADIR)

clean:
ifeq ($(BUILDMOD),yes)
	$(MAKE) -C core clean
endif
