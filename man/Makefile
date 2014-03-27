include ../Makefile.inc

all:

install: all
	$(INSTALL) -d $(MANDIR)
	gzip -k -9 kpatch.1
	$(INSTALL) -m 644 kpatch.1.gz $(MANDIR)
	gzip -k -9 kpatch-build.1
	$(INSTALL) -m 644 kpatch-build.1.gz $(MANDIR)

uninstall:
	$(RM) $(MANDIR)/kpatch.1*
	$(RM) $(MANDIR)/kpatch-build.1*

clean:
