#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu
make_cmd=$1 repo=$2 build=$3
header=$repo/include/cdk2/scsi_bus_binding.h
tmp=$(mktemp -d)
touch -r "$header" "$tmp/header.timestamp"
trap 'touch -r "$tmp/header.timestamp" "$header"; rm -rf "$tmp"' EXIT HUP INT TERM
for dep in "$build"/native/scsi-bus-model.d \
	"$build"/native/scsi-bus-binding.d "$build"/native/scsi-bus-entry.d; do
	test -s "$dep"
	grep -Eq 'include/cdk2/scsi_bus(_binding)?\.h' "$dep"
done
printf '%s\n' 'scsi bus dependency depfiles: PASS'
sleep 1
touch "$header"
if MAKEFLAGS= MAKEOVERRIDES= "$make_cmd" -q -C "$repo" -f "$repo/Makefile" \
	CDK2_CONFIG_READY=1 CDK2_BUILD_DIR="$build" native-scsi-bus-package; then
	exit 1
fi
printf '%s\n' 'scsi bus dependency header touch: PASS'
