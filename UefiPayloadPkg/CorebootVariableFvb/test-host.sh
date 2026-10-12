#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause-Patent
set -eu

cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

"${CC:-cc}" -m32 -malign-double -std=gnu11 -fshort-wchar -DEFI32 \
	-fno-pie -no-pie -ffunction-sections -fdata-sections -Wl,--gc-sections \
	-Wall -Werror -I. -IMdePkg/Include -IMdePkg/Include/Ia32 \
	-IMdeModulePkg/Include -IUefiPayloadPkg/Include -IStandaloneMmPkg/Include \
	UefiPayloadPkg/CorebootVariableFvb/CorebootVariableFvbTest.c -o "$test_dir/fvb-test"
"$test_dir/fvb-test"
