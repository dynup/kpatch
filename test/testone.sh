#!/bin/bash

if [[ $# -ne 1 ]]
then
	echo "test.sh testcase"
	exit 1
fi

TESTCASE=$1
FLAGS="-fno-strict-aliasing -fno-common -fno-delete-null-pointer-checks -O2 -m64 -mpreferred-stack-boundary=4 -mtune=generic -mno-red-zone -mcmodel=kernel -funit-at-a-time -maccumulate-outgoing-args -fno-asynchronous-unwind-tables -fno-stack-protector -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-strict-overflow -fconserve-stack -ffunction-sections -fdata-sections -fno-inline"
CFLAGS="$FLAGS" make $TESTCASE.o > /dev/null 2>&1 || exit 1
mv -f $TESTCASE.o $TESTCASE.o.orig
patch $TESTCASE.c $TESTCASE.patch > /dev/null 2>&1 || exit 1
CFLAGS="$FLAGS" make $TESTCASE.o > /dev/null 2>&1 || exit 1
if [[ ! -e ../kpatch-build/create-diff-object ]]
then
	make -C ../kpatch-build create-diff-object || exit 1
fi
../kpatch-build/create-diff-object -i $TESTCASE.o.orig $TESTCASE.o output.o > /dev/null 2>&1 || exit 1
rm -f $TESTCASE.o $TESTCASE.o.orig > /dev/null 2>&1
patch -R $TESTCASE.c $TESTCASE.patch > /dev/null 2>&1 || echo "warning: unable to unpatch file $TESTCASE.c"

sort $TESTCASE.inventory > reference.inventory
sort output.o.inventory > test.inventory
rm -f output.o.inventory > /dev/null 2>&1
diff reference.inventory test.inventory
if [[ $? -ne 0 ]]
then
	echo "$TESTCASE failed" && exit 1
else
	echo "$TESTCASE passed"
fi
rm -f reference.inventory test.inventory output.o
