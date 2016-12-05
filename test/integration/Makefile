include /etc/os-release

PATCH_DIR?=${ID}-${VERSION_ID}

all:
	$(error please specify local or remote)

local: slow

remote: remote_slow

slow: clean
	./kpatch-test -d $(PATCH_DIR)

quick: clean
	./kpatch-test -d $(PATCH_DIR) --quick

cached:
	./kpatch-test -d $(PATCH_DIR) --cached

clean:
	rm -f *.ko *.log COMBINED.patch

check_host:
ifndef SSH_HOST
	$(error SSH_HOST is undefined)
endif

SSH_USER ?= root

remote_setup: check_host
	ssh $(SSH_USER)@$(SSH_HOST) exit
	ssh $(SSH_USER)@$(SSH_HOST) "ls kpatch-setup &> /dev/null" || \
	(scp remote-setup $(SSH_USER)@$(SSH_HOST):kpatch-setup && \
	 ssh $(SSH_USER)@$(SSH_HOST) "./kpatch-setup")

remote_sync: remote_setup
	ssh $(SSH_USER)@$(SSH_HOST) "rm -rf kpatch-test"
	rsync -Cavz --include=core $(shell readlink -f ../../..) $(SSH_USER)@$(SSH_HOST):kpatch-test
	ssh $(SSH_USER)@$(SSH_HOST) "cd kpatch-test/kpatch && make"

remote_slow: remote_sync
	ssh $(SSH_USER)@$(SSH_HOST) "cd kpatch-test/kpatch/test/integration && make slow"
