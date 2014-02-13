CFLAGS=-I../kpatch-kmod

all: create-diff-object add-patches-section link-vmlinux-syms

create-diff-object: create-diff-object.c
	$(CC) $(CFLAGS) -o $@ $^ -lelf

add-patches-section: add-patches-section.c
	$(CC) $(CFLAGS) -o $@ $^ -lelf

link-vmlinux-syms: link-vmlinux-syms.c
	$(CC) $(CFLAGS) -o $@ $^ -lelf

clean:
	$(RM) -Rf create-diff-object add-patches-section link-vmlinux-syms
