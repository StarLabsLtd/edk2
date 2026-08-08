# Obsolete retained-FV modules

This records why modules classified as `remove` in `retained-fv.tsv` are not
part of the native payload contract. Removal is admitted only after the exact
baseline FV has been pruned by file GUID and the resulting image has passed the
QEMU boot gate.

## EBC interpreter

`EbcDxe` has file GUID `13ac6dd0-73d0-11d4-b06b-00aa00bd6de7` and `TRUE`
DEPEX. It produces the EBC interpreter, debug-support, and PE/COFF emulator
protocols. CDK2 targets native x86-64 payload and driver images and does not
admit EFI Byte Code as an executable format. No retained module has an EBC
machine type.

## Platform driver override sample

`PlatformDriOverrideDxe` has file GUID
`35034ce2-a6e5-4fb4-babe-a0156e9b2549`. Its source describes it as a sample
implementation for test purposes. It depends on the form-browser and HII
configuration-routing protocols and provides a UI for persistent manual
controller-to-driver mappings. That policy is not part of CDK2's coreboot
payload contract.

## Dynamic PCD driver

`PcdDxe`, file GUID `80cf7257-87ab-47f9-a3fe-d50b76d89541`, remains retained.
Although its DEPEX is `TRUE`, removing it from the current baseline stops the
payload before DXE logging and BDS. The retained binaries therefore still have
an implicit runtime dependency on the dynamic-PCD protocols or database. It
must not be removed until those consumers are identified and migrated.

## TPM 1.2 driver

`TcgDxe`, file GUID `a5683620-7998-4bb2-a377-1c1e31e1e215`, implements the
legacy TPM 1.2 measured-boot protocol. CDK2's platform contract supports TPM
2.0 only; the unused `CDK2_TPM12` configuration switch has therefore been
removed rather than retaining an untestable second security policy. The TPM
2.0 driver remains present until its native replacement passes both FIFO/TIS
and CRB QEMU gates.

## QEMU evidence

The admitted candidate was derived from baseline FV SHA-256
`ca1ebfd0ff6c7c82935a4302c1ddc4cc418ed177756c678260dfb09527e1f50e`.
Only the EBC and platform-driver-override FFS files were replaced with valid,
same-size pad files; every subsequent file retained its original offset. The
candidate reached BDS, booted the USB UEFI shell, completed `startup.nsh`
through `CDK2_NATIVE_DONE`, and invoked shutdown. Neither removed driver's load
name appears in the serial log.

The three-module negative candidate, which also removed `PcdDxe`, stopped
immediately after coreboot transferred control to the payload. This is the
reason the retained count decreases by two, not three.

The later TPM-1.2-free candidate replaced `TcgDxe` with a valid pad while
leaving `Tcg2Dxe` at its admitted offset. On the paired coreboot local-APIC
handoff, exact IA32 and x86-64 Q35 carriers both reached the UEFI shell, ran
`startup.nsh` through `CDK2_NATIVE_DONE`, and invoked reset without an
exception or assertion.

The deterministic candidate command is:

```text
cdk2-fvpack --prune-dxe-fv --dxe-fv BASELINE.fv --output CANDIDATE.fv \
  --remove-guid 13ac6dd0-73d0-11d4-b06b-00aa00bd6de7 \
  --remove-guid 35034ce2-a6e5-4fb4-babe-a0156e9b2549 \
  --remove-guid a5683620-7998-4bb2-a377-1c1e31e1e215
```
