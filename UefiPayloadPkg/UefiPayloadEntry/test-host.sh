#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause-Patent
set -eu
cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
for arch in X64 Ia32; do
  flags=
  if [ "$arch" = Ia32 ]; then
    flags='-m32 -malign-double -DEFI32 -fno-pie -no-pie'
  fi
  for source in UefiPayloadPkg/UefiPayloadEntry/AcpiTableTest.c \
    MdeModulePkg/Universal/SecurityStubDxe/SecurityStubTest.c \
    SecurityPkg/Tcg/Tcg2Dxe/Tcg2EventLogTest.c \
    UefiPayloadPkg/Tpm2AcpiTableDxe/Tpm2AcpiTableTest.c; do
    echo "Required measurement: $arch $source"
    "${CC:-cc}" $flags -std=gnu11 -fshort-wchar -fno-strict-aliasing -ffunction-sections -fdata-sections \
      -Wl,--gc-sections -Wall -Werror -O2 -IMdePkg/Include -I"MdePkg/Include/$arch" \
      -IMdeModulePkg/Include -ISecurityPkg/Include -IUefiPayloadPkg/Include \
      -IUefiCpuPkg/Include -ICryptoPkg/Include \
      "$source" -o "$test_dir/test"
    "$test_dir/test"
  done
done
