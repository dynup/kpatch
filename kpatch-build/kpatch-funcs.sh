#!/bin/bash
#
# Shared helper functions for kpatch-build (and tests).
#
# Copyright (C) 2014 Seth Jennings <sjenning@redhat.com>
# Copyright (C) 2013,2014 Josh Poimboeuf <jpoimboe@redhat.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA,
# 02110-1301, USA.

# Find and move the linux source directory from an RPM BUILD tree.
# Handles both traditional flat layout (Fedora < 42, RHEL, CentOS):
#   BUILD/kernel-6.12.0/linux-6.12.0-100.fc41.x86_64/
# and nested layout (Fedora 42+):
#   BUILD/kernel-6.14.0-build/kernel-6.14/linux-6.14.0-63.fc42.x86_64/
#
# Uses: RPMTOPDIR, KERNEL_SRCDIR (must be set by caller)
find_rpm_linux_srcdir() {
	shopt -s nullglob
	local dirs=( "$RPMTOPDIR"/BUILD/kernel-*/linux-* )
	shopt -u nullglob

	if [[ ${#dirs[@]} -eq 1 ]]; then
		mv "${dirs[0]}" "$KERNEL_SRCDIR" 2>&1 | logger || die
	elif [[ ${#dirs[@]} -gt 1 ]]; then
		die "Multiple linux-* directories found in BUILD: ${dirs[*]}"
	else
		local found
		found=$(find "$RPMTOPDIR/BUILD" -maxdepth 3 -type d -name "linux-*" \
			! -path "*/configs/*")
		if [[ -z "$found" ]]; then
			die "Could not find linux source directory under $RPMTOPDIR/BUILD"
		elif [[ $(echo "$found" | wc -l) -gt 1 ]]; then
			die "Multiple linux source directories under $RPMTOPDIR/BUILD: $found"
		else
			mv "$found" "$KERNEL_SRCDIR" 2>&1 | logger || die
		fi
	fi
}
