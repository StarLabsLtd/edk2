#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause-Patent
set -eu
cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
python3 - "$test_dir/content" <<'PY'
import sys, struct
with open(sys.argv[1], 'wb') as f:
    image = bytearray(bytes(range(256)) * 512)
    fmap = struct.pack('<8sBBQI32sH', b'__FMAP__', 1, 1, 0, len(image), b'Fixture', 4)
    fmap += struct.pack('<II32sH', 128, 4096, b'FMAP', 0)
    fmap += struct.pack('<II32sH', 4096, 57344, b'COREBOOT', 0)
    fmap += struct.pack('<II32sH', 65536, 65536, b'SMMSTORE', 0)
    fmap += struct.pack('<II32sH', 61440, 4096, b'EC', 0)
    image[128:128+len(fmap)] = fmap
    f.write(struct.pack('<4sIII', b'MSS1', 16, 42, 10) + image + b'COREBOOT'.ljust(16, b'\0') + b'EC'.ljust(16, b'\0') + struct.pack('<4sHH', b'RMAP', 1, 2) + bytes(8))
PY
openssl req -x509 -newkey rsa:2048 -noenc -subj /CN=CapsuleTest/ -days 1 \
  -keyout "$test_dir/key.pem" -out "$test_dir/cert.pem" >/dev/null 2>&1
openssl x509 -in "$test_dir/cert.pem" -outform DER -out "$test_dir/root.der"
openssl cms -sign -binary -noattr -in "$test_dir/content" \
  -signer "$test_dir/cert.pem" -inkey "$test_dir/key.pem" -outform DER \
  -out "$test_dir/signature.der"
"${CC:-cc}" -std=c11 -fshort-wchar -Wall -Wextra -Werror -O2 \
  -I. -ICryptoPkg/Include -IMdePkg/Include -IMdePkg/Include/X64 \
  UefiPayloadPkg/CorebootCapsuleMm/VerifyTest.c \
  CryptoPkg/Library/CapsuleVerifyLib/CapsuleVerifyLib.c -lcrypto -o "$test_dir/test"
"$test_dir/test" "$test_dir/content" "$test_dir/signature.der" "$test_dir/root.der" 16 131072

"${CC:-cc}" -std=c11 -fshort-wchar -Wall -Wextra -Werror -O2 \
  -I. -ICryptoPkg/Include -IMdePkg/Include -IMdePkg/Include/X64 \
  UefiPayloadPkg/CorebootCapsuleMm/OwnerTest.c \
  UefiPayloadPkg/CorebootCapsuleMm/Owner.c \
  UefiPayloadPkg/Library/FmpDeviceSmmLib/FmpDeviceSmmManifest.c \
  UefiPayloadPkg/Library/FmpDeviceSmmLib/FmpDeviceSmmFmap.c \
  CryptoPkg/Library/CapsuleVerifyLib/CapsuleVerifyLib.c -lcrypto -o "$test_dir/owner-test"
"$test_dir/owner-test" "$test_dir/content" "$test_dir/signature.der" "$test_dir/root.der"

"${CC:-cc}" -m32 -malign-double -std=gnu11 -fshort-wchar -DEFI32 \
  -fno-pie -no-pie -Wall -Wextra -Werror -IMdePkg/Include -IMdePkg/Include/Ia32 \
  -IMdeModulePkg/Include -IStandaloneMmPkg/Include -IUefiPayloadPkg/Include \
  UefiPayloadPkg/CorebootCapsuleMm/SourceTest.c -o "$test_dir/source-test"
"$test_dir/source-test"

"${CC:-cc}" -m32 -malign-double -std=gnu11 -fshort-wchar -DEFI32 \
  -fno-pie -no-pie -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -Wall -Wextra -Werror -Wno-unused-parameter -Wno-missing-field-initializers \
  -IMdePkg/Include -IMdePkg/Include/Ia32 -IMdeModulePkg/Include \
  -IStandaloneMmPkg/Include -IUefiPayloadPkg/Include -ICryptoPkg/Include -IFmpDevicePkg/Include \
  UefiPayloadPkg/CorebootCapsuleMm/DispatchTest.c -o "$test_dir/dispatch-test"
"$test_dir/dispatch-test"
