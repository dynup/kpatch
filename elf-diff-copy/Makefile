CC=gcc
CFLAGS=-g -Wall

.PHONY: all
all: elf-diff-copy


elf-diff-copy: elf-diff-copy.c
	$(CC) $(CFLAGS) -o $@ $^ -lelf -ludis86

