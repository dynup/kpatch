include ../Makefile.inc

all:

install: all
	$(INSTALL) -d $(DRACUTDIR)
	$(INSTALL) module-setup.sh kpatch-load-all.sh $(DRACUTDIR)

uninstall:
	$(RM) -R $(DRACUTDIR)

clean:
