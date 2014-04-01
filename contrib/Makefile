include ../Makefile.inc

DRACUTDIR=/usr/lib/dracut/modules.d/99kpatch

all:

install: all
	$(INSTALL) -d $(DRACUTDIR)
	$(INSTALL) module-setup.sh kpatch-apply-all.sh $(DRACUTDIR)

uninstall:
	$(RM) $(DRACUTDIR)

clean:
