#include <stdio.h>

void test_func() {
	printf("this is before\n");
}

/*
 * This test case introduces a new function called by an existing function
 * and ensure that the bundle for that function is included.
 *
 * Verification points: bundles for test_func() and test_func2() should be
 * included.
 */
