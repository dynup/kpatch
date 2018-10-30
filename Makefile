include Makefile.inc

SUBDIRS     = kpatch-build kpatch kmod man contrib
BUILD_DIRS   = $(SUBDIRS:%=build-%)
INSTALL_DIRS = $(SUBDIRS:%=install-%)
UNINSTALL_DIRS = $(SUBDIRS:%=uninstall-%)
CLEAN_DIRS   = $(SUBDIRS:%=clean-%)

UNITTEST_DIR = test/unit
INTEGRATION_DIR = test/integration
CLEAN_DIRS  += clean-$(UNITTEST_DIR)

.PHONY: all install uninstall clean check unit
.PHONY: $(SUBDIRS) $(BUILD_DIRS) $(INSTALL_DIRS) $(CLEAN_DIRS)
.PHONY: integration integration-slow integration-quick
.PHONY: vagrant-integration-slow vagrant-integration-quick vagrant-integration


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

unit: $(UNITTEST_DIR)/Makefile build-kpatch-build
	$(MAKE) -C $(UNITTEST_DIR)

integration: integration-quick

integration-slow: $(INTEGRATION_DIR)/Makefile build-kpatch-build build-kpatch build-kmod
	$(MAKE) -C $(INTEGRATION_DIR) slow

integration-quick: $(INTEGRATION_DIR)/Makefile build-kpatch-build build-kpatch build-kmod
	$(MAKE) -C $(INTEGRATION_DIR) quick

vagrant-integration: vagrant-integration-quick

vagrant-integration-slow:
	$(MAKE) -C $(INTEGRATION_DIR) vagrant-slow

vagrant-integration-quick:
	$(MAKE) -C $(INTEGRATION_DIR) vagrant-quick

check:
	shellcheck kpatch/kpatch kpatch-build/kpatch-build kpatch-build/kpatch-gcc
