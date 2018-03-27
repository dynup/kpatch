include ../Makefile.inc

all:

install: all
	$(INSTALL) -d $(SYSTEMDDIR)
	$(INSTALL) -m 0644 kpatch.service $(SYSTEMDDIR)
	sed -i 's~PREFIX~$(PREFIX)~' $(SYSTEMDDIR)/kpatch.service
	$(INSTALL) -d $(UPSTARTDIR)
	$(INSTALL) -m 0644 kpatch.conf $(UPSTARTDIR)
	sed -i 's~PREFIX~$(PREFIX)~' $(UPSTARTDIR)/kpatch.conf

uninstall:
	$(RM) $(SYSTEMDDIR)/kpatch.service
	$(RM) $(UPSTARTDIR)/kpatch.conf

clean:
