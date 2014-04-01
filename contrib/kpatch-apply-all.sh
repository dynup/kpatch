#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
#
# Licensed under the GPLv2
#
# Copyright 2014 Red Hat, Inc.
# Josh Poimboeuf <jpoimboe@redhat.com>

insmod /usr/lib/modules/$(uname -r)/kpatch/kpatch.ko
kpatch apply --all
