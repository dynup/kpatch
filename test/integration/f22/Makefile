all: vagrant_slow

slow: clean
	../kpatch-test

quick: clean
	../kpatch-test --quick

cached:
	../kpatch-test --cached

clean:
	rm -f *.ko *.log COMBINED.patch

vagrant_slow:
	vagrant up
	vagrant ssh -c "cd /kpatch && make && cd /kpatch/test/integration/f22 && make slow"
