#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only

set -eu

make_command=$1
makefile=$2
root=$3
build_dir=$4
native_build_dir=$5
config_header=$6
compiler=$7
header=$8
object=$9
object_stamp="${object}.dependency-object.$$"
header_stamp="${object}.dependency-header.$$"

cleanup()
{
	if test -e "$header_stamp"; then
		touch -r "$header_stamp" "$header"
	fi
	rm -f "$object_stamp" "$header_stamp"
}
trap cleanup EXIT HUP INT TERM

cp -p "$object" "$object_stamp"
touch -r "$header" "$header_stamp"
touch "$header"
"$make_command" -f "$makefile" CDK2_DIR="$root" CDK2_BUILD_DIR="$build_dir" \
	CDK2_NATIVE_BUILD_DIR="$native_build_dir" CDK2_CONFIG_HEADER="$config_header" \
	CDK2_NATIVE_CC="$compiler" "$object"
test "$object" -nt "$object_stamp"
