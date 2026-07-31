## SPDX-License-Identifier: BSD-2-Clause-Patent

# cdk2 coreboot-quality profile

This profile is the local review gate for the cdk2 native payload while it
still lives inside the EDK II tree. It deliberately separates EDK II repository
requirements from the stricter rules that apply when the native code is
projected into coreboot.

Required local checks:

- `git diff --check <range>`
- `python3 BaseTools/Scripts/PatchCheck.py <range>`
- `make -f UefiPayloadPkg/cdk2/Makefile check native-check`
- `make -f UefiPayloadPkg/cdk2/Makefile olddefconfig`
- `python3 UefiPayloadPkg/cdk2/tools/coreboot_lint_profile.py --range <range>`

Coreboot-projection checks:

- native source lives under `UefiPayloadPkg/cdk2/src`
- shared native headers live under `UefiPayloadPkg/cdk2/include/cdk2`
- native make fragments use `Makefile.mk`, not `Makefile.inc`
- native source includes cdk2-owned headers through `<cdk2/...>`
- module selection is driven by the resolved Kconfig/override state
- coreboot wrapper options remain opt-in for `EDK2_CDK2`
- legacy `EDK2_UEFIPAYLOAD` behavior is not changed by CDK2-only code

When checking a coreboot worktree, run the matching coreboot lints against the
wrapper files:

- `util/lint/lint-stable-008-kconfig payloads/external/edk2/Kconfig`
- `util/lint/lint-stable-003-whitespace payloads/external/edk2/Kconfig payloads/external/edk2/Makefile`
- `util/lint/lint-stable-030-makefile-inc payloads/external/edk2/Makefile`
- `git diff --check`

The cdk2 tree keeps CRLF line endings for EDK II PatchCheck. A future coreboot
projection must normalize the projected native files to LF before applying
coreboot's line-ending lint.
