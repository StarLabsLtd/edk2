#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause-Patent
set -eu
cd "$(dirname "$0")/../.."
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
python3 - "$test_dir/content" <<'PY'
import sys, struct, uuid
sys.path.insert(0, 'BaseTools/Source/Python')
from Common.Edk2.Capsule.FmpPayloadHeader import FmpPayloadHeaderClass
with open(sys.argv[1], 'wb') as f:
    image = bytearray(bytes(range(256)) * 512)
    fmap = struct.pack('<8sBBQI32sH', b'__FMAP__', 1, 1, 0, len(image), b'Fixture', 4)
    fmap += struct.pack('<II32sH', 128, 4096, b'FMAP', 0)
    fmap += struct.pack('<II32sH', 4096, 57344, b'COREBOOT', 0)
    fmap += struct.pack('<II32sH', 65536, 65536, b'SMMSTORE', 0)
    fmap += struct.pack('<II32sH', 61440, 4096, b'EC', 0)
    image[128:128+len(fmap)] = fmap
    header = FmpPayloadHeaderClass()
    header.FwVersion = 42
    header.LowestSupportedVersion = 10
    header.TargetGuid = uuid.UUID('00112233-4455-6677-8899-aabbccddeeff')
    header.Payload = image + b'COREBOOT'.ljust(16, b'\0') + b'EC'.ljust(16, b'\0') + struct.pack('<4sHH', b'RMAP', 1, 2) + bytes(8)
    f.write(header.Encode())
    header.TargetGuid = None
    with open(sys.argv[1] + '.legacy', 'wb') as legacy:
        legacy.write(header.Encode())
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
"$test_dir/test" "$test_dir/content" "$test_dir/signature.der" "$test_dir/root.der" 32 131072

"${CC:-cc}" -std=c11 -fshort-wchar -Wall -Wextra -Werror -O2 \
  -I. -ICryptoPkg/Include -IMdePkg/Include -IMdePkg/Include/X64 \
  UefiPayloadPkg/CorebootCapsuleMm/OwnerTest.c \
  UefiPayloadPkg/CorebootCapsuleMm/Owner.c \
  UefiPayloadPkg/Library/FmpDeviceSmmLib/FmpDeviceSmmManifest.c \
  UefiPayloadPkg/Library/FmpDeviceSmmLib/FmpDeviceSmmFmap.c \
  CryptoPkg/Library/CapsuleVerifyLib/CapsuleVerifyLib.c -lcrypto -o "$test_dir/owner-test"
"$test_dir/owner-test" "$test_dir/content" "$test_dir/signature.der" "$test_dir/root.der"
# A valid signature cannot authorize legacy metadata without a target identity.
openssl cms -sign -binary -noattr -in "$test_dir/content.legacy" \
  -signer "$test_dir/cert.pem" -inkey "$test_dir/key.pem" -outform DER \
  -out "$test_dir/legacy.der"
"$test_dir/owner-test" "$test_dir/content.legacy" "$test_dir/legacy.der" "$test_dir/root.der" 16
# Sign another target, then relabel the public FMP wrapper to this board.
python3 - "$test_dir/content" "$test_dir/wrong-target" <<'PYTEST'
from pathlib import Path
import sys
content = bytearray(Path(sys.argv[1]).read_bytes())
content[16] ^= 1
Path(sys.argv[2]).write_bytes(content)
PYTEST
openssl cms -sign -binary -noattr -in "$test_dir/wrong-target" \
  -signer "$test_dir/cert.pem" -inkey "$test_dir/key.pem" -outform DER \
  -out "$test_dir/wrong-target.der"
python3 - "$test_dir" <<'PYTEST'
from pathlib import Path
import sys, uuid, struct
sys.path.insert(0, 'BaseTools/Source/Python')
from Common.Uefi.Capsule.FmpAuthHeader import FmpAuthHeaderClass
from Common.Uefi.Capsule.FmpCapsuleHeader import FmpCapsuleHeaderClass
root = Path(sys.argv[1])
auth = FmpAuthHeaderClass()
auth.CertData = (root/'wrong-target.der').read_bytes()
auth.Payload = (root/'wrong-target').read_bytes()[:-8]
wrapper = FmpCapsuleHeaderClass()
expected = uuid.UUID('00112233-4455-6677-8899-aabbccddeeff')
wrapper.AddPayload(expected, auth.Encode(), CapsuleSupport=1)
wrapper.Decode(wrapper.Encode())
routed = wrapper.GetFmpCapsuleImageHeader(0)
assert routed.UpdateImageTypeId == expected
extracted = FmpAuthHeaderClass()
extracted.Decode(routed.Payload)
(root/'relabelled').write_bytes(extracted.Payload + struct.pack('<Q', extracted.MonotonicCount))
(root/'relabelled.der').write_bytes(extracted.CertData)
PYTEST
"$test_dir/owner-test" "$test_dir/relabelled" "$test_dir/relabelled.der" "$test_dir/root.der" 32
# Mutating the target without re-signing must also fail.
python3 - "$test_dir/content" "$test_dir/tampered" <<'PYTEST'
from pathlib import Path
import sys
content = bytearray(Path(sys.argv[1]).read_bytes())
content[16] ^= 1
Path(sys.argv[2]).write_bytes(content)
PYTEST
"$test_dir/owner-test" "$test_dir/tampered" "$test_dir/signature.der" "$test_dir/root.der" 32
# An authentic but structurally invalid target header must also fail.
python3 - "$test_dir/content" "$test_dir/malformed" <<'PYTEST'
from pathlib import Path
import sys, struct
content = bytearray(Path(sys.argv[1]).read_bytes())
struct.pack_into('<I', content, 4, 31)
Path(sys.argv[2]).write_bytes(content)
PYTEST
openssl cms -sign -binary -noattr -in "$test_dir/malformed" \
  -signer "$test_dir/cert.pem" -inkey "$test_dir/key.pem" -outform DER \
  -out "$test_dir/malformed.der"
"$test_dir/owner-test" "$test_dir/malformed" "$test_dir/malformed.der" "$test_dir/root.der" 32

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

"${CC:-cc}" -m32 -malign-double -std=gnu11 -fshort-wchar -DEFI32 \
  -fno-pie -no-pie -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -Wall -Wextra -Werror -IMdePkg/Include -IMdePkg/Include/Ia32 \
  -IUefiPayloadPkg/Include \
  UefiPayloadPkg/Library/CorebootCapsuleLib/ClientTest.c -o "$test_dir/client-test"
"$test_dir/client-test"

"${CC:-cc}" -m32 -malign-double -std=gnu11 -fshort-wchar -DEFI32 \
  -fno-pie -no-pie -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -Wall -Werror -IMdePkg/Include -IMdePkg/Include/Ia32 \
  -IMdeModulePkg/Include -IUefiPayloadPkg/Include \
  UefiPayloadPkg/CorebootMmBridge/BridgeTest.c -o "$test_dir/bridge-test"
"$test_dir/bridge-test"

"${CC:-cc}" -std=gnu11 -fshort-wchar -ffunction-sections -fdata-sections \
  -Wl,--gc-sections -Wall -Werror -D_PCD_GET_MODE_32_PcdMaximumDevicePathNodeCount=1000 \
  -IMdePkg/Include -IMdePkg/Include/X64 -IMdeModulePkg/Include -ISecurityPkg/Include \
  UefiPayloadPkg/Library/LockBoxLibApmsmi/HandoffTest.c \
  MdePkg/Library/UefiDevicePathLib/DevicePathUtilities.c \
  MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.c -o "$test_dir/handoff-test"
"$test_dir/handoff-test"
