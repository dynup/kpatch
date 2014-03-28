include ../Makefile.inc

all: kpatch.1.gz kpatch-build.1.gz

kpatch.1.gz: kpatch.1
	gzip -k -9 kpatch.1

kpatch-build.1.gz: kpatch-build.1
	gzip -k -9 kpatch-build.1

install: all
	$(INSTALL) -d $(MANDIR)
	$(INSTALL) -m 644 kpatch.1.gz $(MANDIR)
	$(INSTALL) -m 644 kpatch-build.1.gz $(MANDIR)

uninstall:
	$(RM) $(MANDIR)/kpatch.1*
	$(RM) $(MANDIR)/kpatch-build.1*

clean:
	$(RM) kpatch.1.gz
	$(RM) kpatch-build.1.gz
