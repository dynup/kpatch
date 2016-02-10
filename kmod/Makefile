include ../Makefile.inc

all: clean
ifeq ($(BUILDMOD),yes)
	$(MAKE) -C core
endif

install:
ifeq ($(BUILDMOD),yes)
	$(INSTALL) -d $(MODULESDIR)/$(shell uname -r)
	$(INSTALL) -m 644 core/kpatch.ko $(MODULESDIR)/$(shell uname -r)
	$(INSTALL) -m 644 core/Module.symvers $(MODULESDIR)/$(shell uname -r)
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
