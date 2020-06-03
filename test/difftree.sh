#!/bin/bash

# The purpose of this test script is to determine if create-diff-object can
# properly recognize object file equivalence when passed the same file for both
# the original and patched objects.  This verifies that create-diff-object is
# correctly parsing, correlating, and comparing the different elements of the
# object file.  In practice, a situation similar to the test case occurs when a
# commonly included header file changes, causing Make to rebuild many objects
# that have no functional change.

# This script requires a built kernel object tree to be in the kpatch cache
# directory at $HOME/.kpatch/obj

#set -x

OBJDIR="$HOME/.kpatch/obj"
SCRIPTDIR="$(readlink -f $(dirname $(type -p $0)))"
TEMPDIR=$(mktemp -d)
RESULTSDIR="$TEMPDIR/results"

if [[ ! -d $OBJDIR ]]; then
	echo "please run kpatch-build to populate the object tree in $OBJDIR"
fi

cd "$OBJDIR" || exit 1
for i in $(find * -name '*.o')
do
	# copied from kpatch-build/kpatch-gcc; keep in sync
	case $i in
		*.mod.o|\
		*built-in.o|\
		*built-in.a|\
		vmlinux.o|\
		.tmp_kallsyms1.o|\
		.tmp_kallsyms2.o|\
		init/version.o|\
		arch/x86/boot/version.o|\
		arch/x86/boot/compressed/eboot.o|\
		arch/x86/boot/header.o|\
		arch/x86/boot/compressed/efi_stub_64.o|\
		arch/x86/boot/compressed/piggy.o|\
		kernel/system_certificates.o|\
		.*.o)
		continue
		;;
	esac
	# skip objects that are the linked product of more than one object file
	[[ $(readelf -s $i | awk '$4=="FILE" {n++} END {print n}') -ne 1 ]] && continue
	$SCRIPTDIR/../kpatch-build/create-diff-object $i $i /usr/lib/debug/lib/modules/$(uname -r)/vmlinux "$TEMPDIR/output.o" > "$TEMPDIR/log.txt" 2>&1
	RETCODE=$?
	# expect RETCODE to be 3 indicating no change
	[[ $RETCODE -eq 3 ]] && continue
	# otherwise record error
	mkdir -p $RESULTSDIR/$(dirname $i) || exit 1
	cp "$i" "$RESULTSDIR/$i" || exit 1
	case $RETCODE in
		139)
			echo "$i: segfault" | tee 
			if [[ ! -e core ]]; then
				echo "no corefile, run "ulimit -c unlimited" to capture corefile"
			else
				mv core "$RESULTSDIR/$i.core" || exit 1
			fi
			;;
		0)
			echo "$i: incorrectly detected change"
			mv "$TEMPDIR/log.txt" "$RESULTSDIR/$i.log" || exit 1
			;;
		1|2)
			echo "$i: error code $RETCODE"
			mv "$TEMPDIR/log.txt" "$RESULTSDIR/$i.log" || exit 1
			;;
		*)
			exit 1 # script error
			;;
	esac
done
rm -f "$TEMPDIR/log.txt" > /dev/null 2>&1

# try to group the errors together in some meaningful way
cd "$RESULTSDIR" || exit 1
echo ""
echo "Results:"
for i in $(find * -iname '*.log')
do
	echo $(cat $i | head -1 | cut -f2-3 -d':')
done | sort | uniq -c | sort -n -r | tee "$TEMPDIR/results.log"

echo "results are in $TEMPDIR"
