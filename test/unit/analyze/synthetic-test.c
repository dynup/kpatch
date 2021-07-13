#include <stdio.h>

static struct struct1 {
	int aaa;
	long bbb;
	char *ccc;
} var1;

static int catchme = 1;

static unsigned int func1(unsigned int c)
{
	int retval = 256;
	return var1.aaa;
}

void *func2(const void *src);
void *func2(const void *src)
{
	return NULL;
}

static char *func3(const char *src)
{
	return "a";
}
