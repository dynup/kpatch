include ../Makefile.inc

all:

install: all
	$(INSTALL) -d $(SYSTEMDDIR)
	$(INSTALL) kpatch.service $(SYSTEMDDIR)

uninstall:
	$(RM) -f $(SYSTEMDDIR)/kpatch.service

clean:
