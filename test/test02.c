#include <stdio.h>

static int a = 1;

void test_func() {
	printf("%d\n",a);
}

/* this is to ensure that a isn't optimized out by the compiler */
void test_func2() {
	a = 2;
}

/*
 * This test case ensures that static data structures, normally referenced
 * by section in rela entries that reference them, are being converted to
 * symbol references, so they can later be linked to the location of the
 * data structure in the running kernel
 *
 * Verification points: test_func() bundle and 'a' symbol should be included.
 * 'a' should have GLOBAL bind and NOTYPE type.
 */
