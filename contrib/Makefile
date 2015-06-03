include ../Makefile.inc

all:

install: all
	$(INSTALL) -d $(SYSTEMDDIR)
	$(INSTALL) kpatch.service $(SYSTEMDDIR)
	sed -i 's~PREFIX~$(PREFIX)~' $(SYSTEMDDIR)/kpatch.service

uninstall:
	$(RM) $(SYSTEMDDIR)/kpatch.service

clean:
