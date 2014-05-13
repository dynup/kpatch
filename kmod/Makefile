include ../Makefile.inc

all: clean
	$(MAKE) -C core

install:
	$(INSTALL) -d $(MODULESDIR)/$(shell uname -r)/extra/kpatch
	$(INSTALL) -m 644 core/kpatch.ko $(MODULESDIR)/$(shell uname -r)/extra/kpatch
	$(INSTALL) -m 644 core/Module.symvers $(MODULESDIR)/$(shell uname -r)/extra/kpatch
	$(INSTALL) -d $(DATADIR)/patch
	$(INSTALL) -m 644 patch/* $(DATADIR)/patch

uninstall:
	$(RM) -R $(MODULESDIR)/*/kpatch
	$(RM) -R $(DATADIR)

clean:
	$(MAKE) -C core clean
