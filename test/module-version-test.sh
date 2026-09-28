#!/bin/bash
# Fast CLI regression tests: no kernel build, Docker, or root access required.
set -euo pipefail
export LC_ALL=C

BUILD="$(dirname "$(readlink -f "$0")")/../kpatch-build/kpatch-build"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

command -v gawk >/dev/null || fail "gawk is required by kpatch-build"

# --help exits after option parsing, before source preparation or compilation.
max=$(printf '%064d' 0)
for version in "0" "1.2.3-rc1+test_2" "0123456789abcdef0123456789abcdef01234567" "$max"; do
	"$BUILD" --module-version "$version" --help >"$TMP/out" 2>"$TMP/err" ||
		fail "valid version rejected: $version"
done

for version in "" "${max}0" "-1" "a b" 'a"b' 'a\b' $'a\nb' $'a\rb' \
		"a/b" "a;exit" "\$(false)" $'\xc3\xa9'; do
	if "$BUILD" --module-version "$version" --help >"$TMP/out" 2>"$TMP/err"; then
		fail "invalid version accepted: $version"
	fi
	grep -q "Invalid module version" "$TMP/err" ||
		fail "unexpected failure for invalid version: $version"
done

if "$BUILD" --module-version >"$TMP/out" 2>"$TMP/err"; then
	fail "missing argument accepted"
fi
grep -q "requires an argument" "$TMP/err" || fail "missing-argument diagnostic not found"

# The new option must not conflict with the existing tool-version option.
"$BUILD" --version >"$TMP/out" 2>"$TMP/err" || fail "--version failed"
grep -q "Version :" "$TMP/out" || fail "tool version missing"
"$BUILD" --help >"$TMP/out" 2>"$TMP/err" || fail "--help failed"
grep -q -- "--module-version" "$TMP/err" || fail "option missing from help"

echo "module-version CLI tests: PASS"
