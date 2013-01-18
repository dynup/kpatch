CC=gcc
CFLAGS=-g -Wall
PROG=kpatch-diff-gen

.PHONY: all
all: $(PROG)


$(PROG): $(PROG).c
	$(CC) $(CFLAGS) -o $@ $^ -lelf -ludis86

