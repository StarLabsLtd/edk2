# cdk2 payload build

`Kconfig` and `defconfig` describe the retained coreboot payload contract.
`Makefile` is the reproducible entry point used to build it. It selects the
`edk2` backend by default through `CDK2_BACKEND`. The `native` backend provides
the coreboot-facing handoff when a flat payload FV has already been produced:
`CDK2_BACKEND=native CDK2_PAYLOAD_FV=/path/to/payload.fv` validates that FV
with the native C checker and embeds it in the native coreboot image without
invoking Python, BaseTools, a DSC, or an FDF. The old `native-fv` name remains
as a compatibility alias. Both backends implement the same versioned
interface.
dispatcher validates that the selected backend provides the build, image
assembly, validation, cleanup, manifest, and module-list operations before it
runs. It runs the host
Kconfig solver, writes `Build/cdk2/.config` and `Build/cdk2/include/cdk2/config.h`,
translates the resolved symbols into EDK II build defines, and records the
resolved late-link map. The EDK II backend writes its complete build output
under `Build/cdk2/edk2/`, keeping cdk2 builds separate from the ordinary
`Build/UefiPayloadPkgX64` output. `modules.mk` is the reviewable inventory of C-backed
EDK II modules that the payload keeps; the build checks that every retained
module exists, that every selected module is referenced by the backend, and
writes a selected manifest beside the payload. The backend also emits
`cdk2-module-metadata.json` and `cdk2-module-guids.txt` from the selected INF
set, making the module/library/source/PCD/DEPEX inventory cdk2-owned instead
of deriving it from an EDK II build report. The default build also emits a
freestanding native stage and its linker map under `Build/cdk2/native/`.
The x86 backend builds X64 only. The native `entry32.S` file is the small
coreboot-to-long-mode bootstrap and is not an IA32 payload build. The flat cdk2
EDK II bridge rejects IA32 and AArch64 when `CDK2_FLAT_DXE_FV` is enabled.

The `edk2` backend still compiles the PE/COFF modules and emits the FFS inputs used as the
DXE firmware-volume reference. The native cdk2 host packer assembles the
retained DXE files from those inputs, then owns the final outer `PLDFV`
assembly: it places the payload-entry PE32 image, applies the fixed-address
relocations required by coreboot's load address, places the DXE files directly
in the outer FV, and writes the result to the configured payload path. The
entry path correspondingly loads DXE core from the outer FV without a nested
FV-image wrapper. EDK II remains the source of PE/COFF and FFS content; the
native packer owns volume layout and the cdk2 flat-FV contract. The generic
makefile asks the selected backend for a completed payload; the EDK II backend
keeps EDK II source compilation, generated PCD/DEPEX content, FFS discovery,
and flat-FV assembly behind that contract. The EDK II
entry implementation is split into the entry flow, HOB construction and
service adapters (`cdk2/backend/edk2/Cdk2EfiHobs.c` and
`cdk2/backend/edk2/Cdk2EfiServices.c`) behind explicit backend headers.

The cdk2 layer owns feature dependencies, selected module composition, and the
late-link alignment policy. `Cdk2PlatformLib` provides a weak late hook so
board-specific payload policy can override the common entry path without
editing shared entry code. The native stage compiles that same weak library
implementation with the generated config header and links it with
`native/cdk2.ld`; `native-check` verifies static ELF output, section layout,
program-header permissions, weak-to-strong board override resolution, and the
linker-collected native module table. The native ELF contract keeps the image
fixed at 1 MiB with separate RX text, read-only metadata/FV, and RW state
segments; the final coreboot image check also requires the embedded FV section
and its `__cdk2_fv_*` symbols to agree. The final FV file check rejects
legacy nested-FV output and requires the compact flat DXE-core layout before
embedding. Registered modules receive a shared
context with explicit HOB construction, image loading, and DXE handoff service
slots, and return an
`EFI_STATUS` so the stage can stop on a failed module. Those service
implementations now provide a bounded PHIT/end-HOB builder, payload-range
image validation, and a no-jump handoff validator. The real UEFI entry installs
and consumes the same service table as the freestanding stage; the host service
test exercises that path and rejects invalid image names and entry ranges. The
architecture-specific transfer is isolated in
`cdk2/backend/edk2/Cdk2EfiBackend.c`, leaving the
native service contract independent of the EDK II handoff implementation. The
cdk2-only API headers live under `cdk2/include/Library`; the package declaration
exports that directory as a cdk2-owned include root instead of placing the
headers in the package-wide `UefiPayloadPkg/Include` tree.
When `CDK2_NATIVE_STAGE=n`, the native ELF and linker checks are omitted while
the host service test and FV packer remain part of the EDK II backend build.
When `CDK2_CAPSULE=y`, `CDK2_CAPSULE_MAIN_FW_GUID` must name the system
firmware FMP GUID forwarded to `CAPSULE_MAIN_FW_GUID`.
Unless the caller sets `SOURCE_DATE_EPOCH`, the cdk2 wrapper exports the most
recent cdk2 bridge commit time so BaseTools does not stamp outputs with wall
clock time.

Useful targets:

```text
make -f UefiPayloadPkg/cdk2/Makefile olddefconfig
make -f UefiPayloadPkg/cdk2/Makefile menuconfig
make -f UefiPayloadPkg/cdk2/Makefile check
make -f UefiPayloadPkg/cdk2/Makefile metadata
make -f UefiPayloadPkg/cdk2/Makefile native-check
make -f UefiPayloadPkg/cdk2/Makefile build

# Embed an FV produced by a separate EDK II build through the native backend.
make -f UefiPayloadPkg/cdk2/Makefile \
  CDK2_BACKEND=native CDK2_PAYLOAD_FV=/path/to/UEFIPAYLOAD.fd build-image
```
