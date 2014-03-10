#include <stdio.h>

void test_func() {
	printf("this is before\n");
}

/*
 * This test case ensures that deep inspection for rela entries
 * that reference strings is taking place.  The text and rela sections
 * for test_func() are the same between the original and patched
 * versions.  However, the tool should detect that the string referenced
 * by the printf has changed.
 *
 * Verification points: test_func bundle and the rodata.str1.8 section
 * are included.
 */
