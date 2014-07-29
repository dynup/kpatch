include ../Makefile.inc

all: clean
	$(MAKE) -C core

install:
	$(INSTALL) -d $(MODULESDIR)/$(shell uname -r)
	$(INSTALL) -m 644 core/kpatch.ko $(MODULESDIR)/$(shell uname -r)
	$(INSTALL) -m 644 core/Module.symvers $(MODULESDIR)/$(shell uname -r)
	$(INSTALL) -d $(DATADIR)/patch
	$(INSTALL) -m 644 patch/* $(DATADIR)/patch

uninstall:
	$(RM) -R $(MODULESDIR)
	$(RM) -R $(DATADIR)

clean:
	$(MAKE) -C core clean
