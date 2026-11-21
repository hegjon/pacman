#!/bin/bash
# Tests for lib/libalpm/btrpkg.c through test/btrpkg/btrdump.
#   run.sh BTRDUMP FIXTURES
# Fixtures come from btrpkg (https://github.com/hegjon/btrpkg): a real index and its signature,
# its `btrpkg dump` output, the public key, and indexes from bench/craft_indexes.py (valid hashes,
# bad contents) with the verdict btrpkg's reader gives each.
set -u
D=$1; F=$2; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
n=0; failed=0
ok() { n=$((n+1)); echo "ok $n - $1"; }
no() { n=$((n+1)); failed=$((failed+1)); echo "not ok $n - $1"; }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else no "$what"; fi; }
refuse() { local what=$1; shift; if "$@" >/dev/null 2>&1; then no "$what"; else ok "$what"; fi; }

IDX=$F/owe-lockfeed.btrpkg
"$D" "$IDX" > "$T/dump" 2>&1
check "dump matches btrpkg's" cmp -s "$T/dump" "$F/owe-lockfeed.dump"
id=$(awk '$1=="id"{print $2}' "$F/owe-lockfeed.dump")
check "expected id accepted" "$D" --id "$id" "$IDX"
refuse "other id refused" "$D" --id "$(echo "$id" | tr 0-9a-f 1-9a-f0)" "$IDX"
check "every bit flip and cut refused" "$D" --mutate "$IDX"

check "good signature" "$D" --verify "$IDX.sig" "$F/keys" "$IDX"
cp "$IDX" "$T/t.btrpkg"; printf '\001' | dd of="$T/t.btrpkg" bs=1 seek=200 conv=notrunc 2>/dev/null
refuse "signature over a changed header refused" "$D" --verify "$IDX.sig" "$F/keys" "$T/t.btrpkg"
mkdir "$T/none"
refuse "unknown key refused" "$D" --verify "$IDX.sig" "$T/none" "$IDX"
mkdir "$T/rev"; cp "$F"/keys/*.pub "$T/rev/"
kn=$(sed -n 2p "$F"/keys/*.pub | base64 -d | od -An -tx1 -j2 -N8 | tr -d ' \n')
echo "$kn  # revoked for the test" > "$T/rev/revoked"
refuse "revoked key refused" "$D" --verify "$IDX.sig" "$T/rev" "$IDX"
echo "not-a-key-number" > "$T/rev/revoked"
refuse "malformed revoked file refused" "$D" --verify "$IDX.sig" "$T/rev" "$IDX"
head -c 40 "$IDX.sig" > "$T/short.sig"
refuse "truncated signature refused" "$D" --verify "$T/short.sig" "$F/keys" "$IDX"

while read -r name expect; do
	if "$D" "$F/crafted/$name.btrpkg" >/dev/null 2>&1; then got=accept; else got=reject; fi
	if [[ $got == "$expect" ]]; then ok "crafted $name: $expect"; else no "crafted $name: expected $expect, got $got"; fi
done < "$F/crafted/cases.txt"

echo "1..$n"
exit $(( failed > 0 ))
