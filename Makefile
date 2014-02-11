SUBDIRS = kpatch-kmod kpatch-files tools

test: test.c
	$(CC) -g -o $@ $^ -lelf

.PHONY: clean
clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir $@; \
	done
	
