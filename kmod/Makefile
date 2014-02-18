include ../Makefile.inc

all:
	$(MAKE) -C core

install:
	$(INSTALL) -d $(MODULESDIR)/$(shell uname -r)/kpatch
	$(INSTALL) -m 644 core/kpatch.ko $(MODULESDIR)/$(shell uname -r)/kpatch
	$(INSTALL) -d $(DATADIR)/patch
	$(INSTALL) -m 644 patch/* $(DATADIR)/patch

clean:
	$(MAKE) -C core clean
