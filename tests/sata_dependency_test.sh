#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu

make_cmd=$1
repo=$2
build=$3
header=$repo/include/cdk2/sata_controller.h
tmp=$(mktemp -d)
touch -r "$header" "$tmp/header.timestamp"
trap 'touch -r "$tmp/header.timestamp" "$header"; rm -rf "$tmp"' EXIT HUP INT TERM

test -s "$build/native/sata-model.d"
test -s "$build/native/sata-entry.d"
grep -Fq 'include/cdk2/sata_controller.h' "$build/native/sata-model.d"
grep -Fq 'include/cdk2/sata_controller.h' "$build/native/sata-entry.d"
sleep 1
touch "$header"
if MAKEFLAGS= MAKEOVERRIDES= "$make_cmd" -q -C "$repo" -f "$repo/Makefile" \
	CDK2_CONFIG_READY=1 CDK2_BUILD_DIR="$build" native-sata-controller-package; then
	exit 1
fi
