#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
make_cmd=$1 repo=$2 build=$3
header=$repo/include/cdk2/ata_atapi_pass_thru.h
tmp=$(mktemp -d)
touch -r "$header" "$tmp/header.timestamp"
trap 'touch -r "$tmp/header.timestamp" "$header"; rm -rf "$tmp"' EXIT HUP INT TERM
for dep in "$build"/native/ata-atapi-*.d; do
	test -s "$dep"
	grep -Fq 'include/cdk2/ata_atapi_pass_thru.h' "$dep"
done
printf '%s\n' 'ata dependency depfiles: PASS'
sleep 1
touch "$header"
if MAKEFLAGS= MAKEOVERRIDES= "$make_cmd" -q -C "$repo" -f "$repo/Makefile" \
	CDK2_CONFIG_READY=1 CDK2_BUILD_DIR="$build" native-ata-atapi-package; then
	exit 1
fi
printf '%s\n' 'ata dependency header touch: PASS'
sentinel=$tmp/predecessor.fv
output=$(MAKEFLAGS= MAKEOVERRIDES= "$make_cmd" -n -C "$repo" \
	CDK2_CONFIG_READY=0 CDK2_BUILD_DIR="$build" \
	CDK2_NATIVE_PRE_ATA_ATAPI_FV="$sentinel" \
	native-ata-atapi-fv-exact 2>&1 || true)
case "$output" in
*"CDK2_NATIVE_PRE_ATA_ATAPI_FV=\"$sentinel\""*) ;;
*) exit 1 ;;
esac
printf '%s\n' 'ata dependency FV forwarding: PASS'
