#!/bin/bash
# Test find_rpm_linux_srcdir() from kpatch-build.
#
# Verifies source directory detection across RPM BUILD layouts:
#   Flat:   BUILD/kernel-6.12.0/linux-6.12.0-100.fc41.x86_64/         (Fedora <42, RHEL, CentOS)
#   Nested: BUILD/kernel-6.14.0-build/kernel-6.14/linux-6.14.0-63.fc42.x86_64/  (Fedora 42+)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

# Stub kpatch-build helpers so die doesn't exit and logger doesn't need a logfile.
die()    { echo "die: $*" >&2; return 1; }
logger() { cat >/dev/null; }

source "$SCRIPT_DIR/kpatch-build/kpatch-funcs.sh"

TESTDIR=$(mktemp -d)
trap 'rm -rf "$TESTDIR"' EXIT
ERRORS=0

# Create a BUILD tree, run find_rpm_linux_srcdir, check result.
#   $1 = test name
#   $2 = expected: "ok" (source moved) or "fail" (die called)
#   $3... = paths to create under BUILD/
assert_layout() {
	local name="$1" expect="$2"; shift 2
	local dir="$TESTDIR/$name"
	local rc=0

	mkdir -p "$dir/BUILD" "$dir/dest"
	for p in "$@"; do mkdir -p "$dir/BUILD/$p"; done

	RPMTOPDIR="$dir" KERNEL_SRCDIR="$dir/dest/linux" \
		find_rpm_linux_srcdir 2>/dev/null || rc=$?

	case "$expect" in
		ok)   [[ $rc -eq 0 && -d "$dir/dest/linux" ]] || { echo "FAIL  $name"; ((ERRORS++)); return; } ;;
		fail) [[ $rc -ne 0 ]] || { echo "FAIL  $name — expected error"; ((ERRORS++)); return; } ;;
	esac
	echo "ok    $name"
}

# Flat layout: Fedora 41 / RHEL / CentOS
assert_layout "flat-fc41-x86_64"   ok    "kernel-6.12.0/linux-6.12.0-100.fc41.x86_64"
assert_layout "flat-fc41-aarch64"  ok    "kernel-6.12.0/linux-6.12.0-100.fc41.aarch64"
assert_layout "flat-rhel9"         ok    "kernel-5.14.0/linux-5.14.0-362.el9.x86_64"

# Nested layout: Fedora 42+
assert_layout "nested-fc42"        ok    "kernel-6.14.0-build/kernel-6.14/linux-6.14.0-63.fc42.x86_64"
assert_layout "nested-fc42-arm"    ok    "kernel-6.14.0-build/kernel-6.14/linux-6.14.0-63.fc42.aarch64"

# configs/linux-* dirs must be ignored by the nested search
assert_layout "nested-with-configs" ok   "kernel-6.14.0-build/configs/linux-extra" \
                                         "kernel-6.14.0-build/kernel-6.14/linux-6.14.0-63.fc42.x86_64"

# Error: ambiguous (multiple matches)
assert_layout "multi-flat"         fail  "kernel-6.14.0/linux-6.14.0-aaa" \
                                         "kernel-6.14.0/linux-6.14.0-bbb"
assert_layout "multi-nested"       fail  "kernel-6.14.0-build/kernel-6.14/linux-aaa" \
                                         "kernel-6.14.0-build/kernel-6.14/linux-bbb"

# Error: nothing to find
assert_layout "empty-build"        fail
assert_layout "no-linux-dir"       fail  "kernel-6.14.0-build/kernel-6.14/sources"
assert_layout "too-deep"           fail  "a/b/c/d/linux-6.14.0"

echo ""
[[ $ERRORS -gt 0 ]] && { echo "$ERRORS test(s) failed"; exit 1; }
echo "All tests passed."
