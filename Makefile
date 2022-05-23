include Makefile.inc

SUBDIRS     = kpatch-build kpatch kmod man contrib
BUILD_DIRS   = $(SUBDIRS:%=build-%)
INSTALL_DIRS = $(SUBDIRS:%=install-%)
UNINSTALL_DIRS = $(SUBDIRS:%=uninstall-%)
CLEAN_DIRS   = $(SUBDIRS:%=clean-%)

UNITTEST_DIR = test/unit
INTEGRATION_DIR = test/integration
CLEAN_DIRS  += clean-$(UNITTEST_DIR)

.PHONY: all dependencies install uninstall clean check unit
.PHONY: $(SUBDIRS) $(BUILD_DIRS) $(INSTALL_DIRS) $(CLEAN_DIRS)
.PHONY: integration integration-slow integration-quick
.PHONY: vagrant-integration-slow vagrant-integration-quick vagrant-integration
.PHONY: vagrant-install
.PHONY: help


all: $(BUILD_DIRS)
$(BUILD_DIRS):
	$(MAKE) -C $(@:build-%=%)

dependencies: SHELL:=/bin/bash
dependencies:
	source test/integration/lib.sh && kpatch_dependencies

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

help:
	@echo "kpatch Makefile"
	@echo
	@echo "Targets:"
	@echo "    make dependencies                 install build dependencies [1]"
	@echo "    make all                          build entire project"
	@echo "    make install                      install programs to system [1]"
	@echo "    make uninstall                    remove programs from system [1]"
	@echo "    make clean                        clean build files"
	@echo
	@echo "Test targets:"
	@echo "    make check                        run static code analyzers"
	@echo "    make integration                  build and run integration tests [2]"
	@echo "    make integration-slow             build and run integration tests [2]"
	@echo "    make integration-quick            build and run integration tests [2]"
	@echo "    make unit                         run unit tests"
	@echo
	@echo "[1] requires admin privileges"
	@echo "[2] installs test kpatch kernel modules, run at your own risk"
	@echo
