#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
make_cmd=$1 repo=$2 build=$3
header=$repo/include/cdk2/ata_bus.h
tmp=$(mktemp -d)
touch -r "$header" "$tmp/header.timestamp"
trap 'touch -r "$tmp/header.timestamp" "$header"; rm -rf "$tmp"' EXIT HUP INT TERM
for dep in "$build"/native/ata-bus-*.d; do
	test -s "$dep"
	grep -Fq 'include/cdk2/ata_bus.h' "$dep"
done
printf '%s\n' 'ata bus dependency depfiles: PASS'
sleep 1
touch "$header"
if MAKEFLAGS= MAKEOVERRIDES= "$make_cmd" -q -C "$repo" -f "$repo/Makefile" \
	CDK2_CONFIG_READY=1 CDK2_BUILD_DIR="$build" native-ata-bus-package; then
	exit 1
fi
printf '%s\n' 'ata bus dependency header touch: PASS'
