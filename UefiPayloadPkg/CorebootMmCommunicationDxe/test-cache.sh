#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause-Patent
set -eu
cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
for arch in X64 Ia32; do
  archflags=
  safe=64
  if [ "$arch" = Ia32 ]; then archflags='-m32 -malign-double'; safe=32; fi
  "${CC:-cc}" ${CFLAGS:-} $archflags -std=gnu11 -fshort-wchar -fno-pie -no-pie \
    -ffunction-sections -fdata-sections -Wl,--gc-sections -Wall -Werror \
    -I. -IMdePkg/Include -IMdePkg/Include/"$arch" -IMdeModulePkg/Include \
    -IUefiPayloadPkg/Include \
    UefiPayloadPkg/CorebootMmCommunicationDxe/CacheTest.c \
    MdePkg/Library/BaseSafeIntLib/SafeIntLib.c \
    MdePkg/Library/BaseSafeIntLib/SafeIntLib"$safe".c \
    MdePkg/Library/BaseDebugLibNull/DebugLib.c -o "$test_dir/transport-$arch"
  "$test_dir/transport-$arch"
done
"${CC:-cc}" ${CFLAGS:-} -m32 -malign-double -std=gnu11 -fshort-wchar -fno-pie -no-pie \
  -ffunction-sections -fdata-sections -Wl,--gc-sections -Wall -Werror \
  -I. -IMdePkg/Include -IMdePkg/Include/Ia32 -IMdeModulePkg/Include \
  -IUefiPayloadPkg/Include -ISecurityPkg/Include -IStandaloneMmPkg/Include \
  MdeModulePkg/Universal/Variable/RuntimeDxe/RuntimeCacheTest.c \
  MdePkg/Library/BaseDebugLibNull/DebugLib.c -o "$test_dir/mm-cache"
"$test_dir/mm-cache"
