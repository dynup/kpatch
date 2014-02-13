include Makefile.inc

SUBDIRS     = kpatch-build kpatch kmod
BUILD_DIRS   = $(SUBDIRS:%=build-%)
INSTALL_DIRS = $(SUBDIRS:%=install-%)
CLEAN_DIRS   = $(SUBDIRS:%=clean-%)

.PHONY: $(SUBDIRS) $(BUILD_DIRS) $(INSTALL_DIRS) $(CLEAN_DIRS)


all: $(BUILD_DIRS)
$(BUILD_DIRS):
	$(MAKE) -C $(@:build-%=%)

install: $(INSTALL_DIRS)
$(INSTALL_DIRS):
	$(MAKE) -C $(@:install-%=%) install

clean: $(CLEAN_DIRS)
$(CLEAN_DIRS):
	$(MAKE) -C $(@:clean-%=%) clean
