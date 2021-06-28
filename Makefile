include Makefile.inc

SUBDIRS        = kpatch-build kpatch kpatch-analyze kmod man contrib
BUILD_DIRS     = $(SUBDIRS:%=build-%)
INSTALL_DIRS   = $(SUBDIRS:%=install-%)
UNINSTALL_DIRS = $(SUBDIRS:%=uninstall-%)
CLEAN_DIRS     = $(SUBDIRS:%=clean-%)

UNITTEST_DIR = test/unit
INTEGRATION_DIR = test/integration
CLEAN_DIRS  += clean-$(UNITTEST_DIR)

.PHONY: all install uninstall clean check unit
.PHONY: $(SUBDIRS) $(BUILD_DIRS) $(INSTALL_DIRS) $(CLEAN_DIRS)
.PHONY: integration integration-slow integration-quick
.PHONY: vagrant-integration-slow vagrant-integration-quick vagrant-integration
.PHONY: vagrant-install


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

vagrant-install: $(INTEGRATION_DIR)/lib.sh
ifneq ($(shell id -u), 0)
	@echo "WARNING: This target is intended for use on freshly-installed machines/vms only." && \
	echo "Do not proceed unless you read $(INTEGRATION_DIR)/lib.sh and realise what this target does." && \
	echo "Press ctrl-c to abort, return to proceed." && \
	read
endif
	source $(INTEGRATION_DIR)/lib.sh && kpatch_check_install_vagrant

vagrant-integration: vagrant-integration-quick

vagrant-integration-slow:
	$(MAKE) -C $(INTEGRATION_DIR) vagrant-slow

vagrant-integration-quick:
	$(MAKE) -C $(INTEGRATION_DIR) vagrant-quick

check:
	shellcheck kpatch/kpatch kpatch-build/kpatch-build kpatch-build/kpatch-cc
	shellcheck test/difftree.sh test/integration/kpatch-test		\
		   test/integration/lib.sh test/integration/rebase-patches	\
		   test/integration/test-vagrant				\
		   test/integration/vm-integration-run
