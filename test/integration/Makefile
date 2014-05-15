all:
	./kpatch-test

# Just reuse any already-built modules for the tests.  This isn't a
# reliable way to run tests if the code has changed, but it comes in
# handy when creating new tests.
quick:
	./kpatch-test -s

clean:
	rm -f *.ko *.log
