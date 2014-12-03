#!/bin/bash
#
# Licensed under the GPLv2
#
# Copyright 2014 Red Hat, Inc.
# Josh Poimboeuf <jpoimboe@redhat.com>

# called by dracut
check() {
    if [[ -e /var/lib/kpatch/$kernel ]]; then
        return 0
    else
        return 1
    fi
}

# called by dracut
install() {
    # install kpatch script
    inst_any -d /usr/sbin/kpatch /usr/local/sbin/kpatch /usr/sbin/kpatch

    # install kpatch script dependencies
    inst /usr/sbin/insmod
    inst /usr/bin/dirname
    inst /usr/bin/readelf
    inst /usr/bin/awk
    
    # install core module
    inst_any -d /usr/lib/modules/$kernel/extra/kpatch/kpatch.ko /usr/local/lib/modules/$kernel/extra/kpatch/kpatch.ko /usr/lib/modules/$kernel/extra/kpatch/kpatch.ko /usr/lib/kpatch/$kernel/kpatch.ko /usr/local/lib/kpatch/$kernel/kpatch.ko

    # install patch modules
    if [[ -e /var/lib/kpatch/$kernel ]]; then
        inst_dir /var/lib/kpatch/$kernel
        for i in /var/lib/kpatch/$kernel/*; do
            [[ -e $i ]] || continue
            inst "$i"
        done
    fi

    # install hook script
    inst_hook pre-udev 00 "$moddir/kpatch-load-all.sh"
}
