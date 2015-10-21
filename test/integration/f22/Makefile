all:
	$(error please specify local or remote)

local: slow

remote: remote_slow

slow: clean
	../kpatch-test

quick: clean
	../kpatch-test --quick

cached:
	../kpatch-test --cached

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
	ssh $(SSH_USER)@$(SSH_HOST) "cd kpatch-test/kpatch/test/integration/f22 && make slow"
