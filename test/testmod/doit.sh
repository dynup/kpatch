#!/bin/bash

#set -x

# If testing on a remote machine, set it here
# Probably want to use preshared keys.

unset REMOTE
#REMOTE="192.168.100.150"

cd ../../ || exit 1
make clean || exit 1
make || exit 1
cd test/testmod || exit 1
make || exit 1
../../kpatch-build/create-diff-object testmod_drv.o.orig testmod_drv.o.patched testmod.ko output.o || exit 1
cd ../../kmod/patch || exit 1
make clean || exit 1
cp ../../test/testmod/output.o . || exit 1
md5sum output.o | awk '{printf "%s\0", $1}' > checksum.tmp || exit 1
objcopy --add-section .kpatch.checksum=checksum.tmp --set-section-flags .kpatch.checksum=alloc,load,contents,readonly output.o || exit 1
rm -f checksum.tmp
KBUILD_EXTRA_SYMBOLS="$(readlink -e ../../kmod/core/Module.symvers)" make || exit 1
cd ../../test/testmod

if [[ -z "$REMOTE" ]]
then
	cp ../../kmod/core/kpatch.ko .
	cp ../../kmod/patch/kpatch-patch.ko .
	sudo ./doit-client.sh
else
	scp ../../kmod/core/kpatch.ko root@$REMOTE:~/. || exit 1
	scp ../../kmod/patch/kpatch-patch.ko root@$REMOTE:~/. || exit 1
	scp testmod.ko root@$REMOTE:~/. || exit 1
	scp doit-client.sh root@$REMOTE:~/. || exit 1
	ssh root@$REMOTE ./doit-client.sh
fi
