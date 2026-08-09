#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu

make_cmd=$1
repo=$2
build=$3
tmp=$(mktemp -d)
header=$repo/include/guid/graphics_info_hob.h
touch -r "$header" "$tmp/header.timestamp"
trap 'touch -r "$tmp/header.timestamp" "$header"; rm -rf "$tmp"' EXIT HUP INT TERM

touch "$header"
if MAKEFLAGS= MAKEOVERRIDES= "$make_cmd" -q -C "$repo" \
	CDK2_CONFIG_READY= CDK2_BUILD_DIR="$build" native-bl-support-package; then
	exit 1
fi
touch -r "$tmp/header.timestamp" "$header"

sed 's/^CONFIG_CDK2_NATIVE_BL_SUPPORT=y$/# CONFIG_CDK2_NATIVE_BL_SUPPORT is not set/' \
	"$repo/defconfig" >"$tmp/defconfig"
MAKEFLAGS= MAKEOVERRIDES= "$make_cmd" -s -C "$repo" CDK2_BUILD_DIR="$tmp/build" \
	CDK2_CONFIG_READY= CDK2_CONFIG="$tmp/build/.config" CDK2_DEFCONFIG="$tmp/defconfig" \
		native-bl-support-test native-bl-support-package native-bl-support-oracle \
		>"$tmp/disabled.out"
	test "$(grep -xc 'native BlSupportDxe: disabled by Kconfig' "$tmp/disabled.out")" -eq 3
test ! -e "$tmp/build/native/BlSupportDxe.ffs"

if MAKEFLAGS= MAKEOVERRIDES= "$make_cmd" -s -C "$repo" \
	CDK2_CONFIG_READY= CDK2_BUILD_DIR="$build" CDK2_PAYLOAD_FV= \
	native-bl-support-fv >"$tmp/no-payload.out" 2>&1; then
	exit 1
fi
grep -q 'native-bl-support-fv requires CDK2_PAYLOAD_FV=' "$tmp/no-payload.out"
