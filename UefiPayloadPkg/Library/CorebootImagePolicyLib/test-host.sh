#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause-Patent
set -eu
cd "$(dirname "$0")/../../.."
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
"${CC:-cc}" -m32 -malign-double -std=gnu11 -fshort-wchar -DEFI32 \
  -fno-pie -no-pie -Wall -Werror -IMdePkg/Include -IMdePkg/Include/Ia32 \
  -IMdeModulePkg/Include \
  UefiPayloadPkg/Library/CorebootImagePolicyLib/CorebootImagePolicyTest.c \
  -o "$test_dir/image-policy-test"
"$test_dir/image-policy-test"
