include Makefile.inc

SUBDIRS     = kpatch-build kpatch kmod man contrib
BUILD_DIRS   = $(SUBDIRS:%=build-%)
INSTALL_DIRS = $(SUBDIRS:%=install-%)
UNINSTALL_DIRS = $(SUBDIRS:%=uninstall-%)
CLEAN_DIRS   = $(SUBDIRS:%=clean-%)

.PHONY: $(SUBDIRS) $(BUILD_DIRS) $(INSTALL_DIRS) $(CLEAN_DIRS)


all: $(BUILD_DIRS)
$(BUILD_DIRS):
	$(MAKE) -C $(@:build-%=%)

install: $(INSTALL_DIRS)
$(INSTALL_DIRS):
	$(MAKE) -C $(@:install-%=%) install

uninstall: $(UNINSTALL_DIRS)
$(UNINSTALL_DIRS):
	$(MAKE) -C $(@:uninstall-%=%) uninstall

clean: $(CLEAN_DIRS)
$(CLEAN_DIRS):
	$(MAKE) -C $(@:clean-%=%) clean
