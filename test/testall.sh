#!/bin/bash

for i in *.c
do
	TESTCASE=${i%.*}
	./testone.sh $TESTCASE
done
