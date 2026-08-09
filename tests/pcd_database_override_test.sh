#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu

make_cmd=$1
makefile=$2
source_dir=$3
build_dir=$4
database=$5
predecessor=$6
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
external="$work/external.database"
cp "$database" "$external"
before=$(sha256sum "$external")
touch "$predecessor"
"$make_cmd" -f "$makefile" CDK2_DIR="$source_dir" CDK2_BUILD_DIR="$build_dir" \
	CDK2_NATIVE_PCD_DATABASE="$external" native-pcd-package >/dev/null
after=$(sha256sum "$external")
test "$before" = "$after"
printf '%s\n' 'pcd external database override: PASS'
