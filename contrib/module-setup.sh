#!/bin/bash
#
# Licensed under the GPLv2
#
# Copyright 2014 Red Hat, Inc.
# Josh Poimboeuf <jpoimboe@redhat.com>

# called by dracut
check() {
    if [[ -e /var/lib/kpatch/$kernel ]] || [[ -e /usr/lib/kpatch/$kernel ]]; then
        return 0
    else
        return 1
    fi
}

# called by dracut
install() {
    # install kpatch script
    inst_any -d /usr/sbin/kpatch /usr/local/sbin/kpatch /usr/sbin/kpatch

    # install insmod (needed by kpatch script)
    inst_symlink /usr/sbin/insmod

    # install dirname (needed by kpatch script)
    inst /usr/bin/dirname
    
    # install core module
    inst_any -d /usr/lib/modules/$kernel/extra/kpatch/kpatch.ko /usr/local/lib/modules/$kernel/extra/kpatch/kpatch.ko /usr/lib/modules/$kernel/extra/kpatch/kpatch.ko

    # install patch modules
    if [[ -e /var/lib/kpatch/$kernel ]]; then
        inst_dir /var/lib/kpatch/$kernel
        for i in /var/lib/kpatch/$kernel/*; do
            [[ -e $i ]] || continue
            inst "$i"
        done
    fi
    if [[ -e /usr/lib/kpatch/$kernel ]]; then
        inst_dir /usr/lib/kpatch/$kernel
        for i in /usr/lib/kpatch/$kernel/*; do
            [[ -e $i ]] || continue
            inst "$i"
        done
    fi

    # install hook script
    inst_hook pre-udev 00 "$moddir/kpatch-load-all.sh"
}
