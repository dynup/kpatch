#!/bin/bash

#set -x

rmmod testmod 2> /dev/null
rmmod kpatch 2> /dev/null
insmod testmod.ko || exit 1
insmod kpatch.ko || exit 1
if [[ "$(cat /sys/kernel/testmod/value)" != "2" ]]
then
	exit 1
fi
insmod kpatch-patch.ko
dmesg | tail
if [[ "$(cat /sys/kernel/testmod/value)" != "3" ]]
then
	exit 1
fi
echo 0 > /sys/kernel/kpatch/patches/kpatch_patch/enabled
rmmod kpatch-patch
if [[ "$(cat /sys/kernel/testmod/value)" != "2" ]]
then
	exit 1
fi
rmmod kpatch
rmmod testmod
echo "SUCCESS"
