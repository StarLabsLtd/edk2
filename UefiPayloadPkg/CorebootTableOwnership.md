# coreboot table ownership and cdk2 ABI boundary

This note records the cdk2/coreboot-table ownership decision for the
EDK2-26.08 based product branch.  It is written against cdk2 PR #38 fixed
head `4d4deeec700e26f98d66f6a56017979e37ca6bff`.
The cdk2 PR #47 document commit
`80d8d094b65ff4676379c9aa0f73449bf64b56e7` was inspected as prior art only.

Decision: no runtime deletion is correct yet.  The current coreboot table is a
validated, length-delimited discovery table, but it does not carry the
authoritative EFI memory attribute, x86 paging/PAT, PCI assignment, UEFI boot
target, or SMM lifetime contracts that would let cdk2 delete the corresponding
payload-owned work.  cdk2 already avoids the largest duplicate MTRR write by
building the coreboot payload with
`gUefiCpuPkgTokenSpaceGuid.PcdCpuDisableMtrrProgramming|TRUE`; removing
`MtrrLib`, page-table setup, PCI host-bridge fallback, BootNext/BootOrder, or
SMM memory-attribute logic needs a new ABI.

Concrete branch result: cdk2 now defines and host-tests a parser-only candidate
`CB_TAG_PAYLOAD_RESOURCE_HANDOFF` record.  The record is versioned,
length-delimited, CRC-protected, and made only from 4-byte-safe fields.  It is
optional evidence: absent, unsupported, or malformed records leave the current
coreboot table parser successful and force cdk2 to keep existing fallback
ownership.  No runtime deletion is claimed by this parser-only step.

## Completion audit, 2026-08-02

Final step-5 conclusion: no additional runtime payload operation is deleted in
this branch.  The only safe ownership movement is parser-side: cdk2 validates
and republishes a candidate PRH record as optional evidence, while every current
duplicate lane remains behind the existing fallback owner until a producer
contract exists in coreboot and the consumer has compatibility tests.

The remaining duplicate operations were audited as follows:

* MTRR/GCD/PAT: keep `MtrrLib`, `CpuPageTableLib`, `CpuDxe` readback/GCD
  refresh, and page-attribute handling.  The existing
  `PcdCpuDisableMtrrProgramming|TRUE` avoids duplicate MTRR programming, but
  cdk2 still owns EFI cache/protection validation, GCD refresh, AP sync, and S3
  proof.
* PCI windows: keep PCI root-bridge/BAR fallback.  Current coreboot records do
  not publish complete typed I/O, MMIO32, MMIO64, prefetchable windows, and
  per-BAR ownership.
* ACPI/SMBIOS: keep these as table-to-HOB/config-table publications only.
  Existing tags identify table pointers; they do not transfer ownership of
  installed EFI table lifetime, memory attributes, PCI resources, or runtime
  policy.
* CFR/S3/SMM lifetime state: keep CFR HII/runtime variable policy, SMMSTORE
  runtime validation, SMM communication, SMRAM/SMM page attributes, and S3
  resume handling.  Runtime and boot-intent PRH section types remain reserved
  until their semantic contracts exist.
* Depthcharge: keep treating it as a Linux/E820 handoff reference only.  It is
  not evidence for deleting UEFI GCD, PAT/page-table, PCI host-bridge, boot
  manager, ACPI/SMBIOS, CFR, S3, or SMM ownership.

Host evidence added in this completion pass extends
`UefiPayloadPkg/cdk2/native/coreboot_test.c` so malformed or unsupported PRH
data disables only the candidate ABI and keeps the legacy coreboot table path
successful.  The added fixtures cover unsupported PRH revision/flags/lifetime
bits, unsupported EFI memory bits, invalid GCD type, ambiguous cache
attributes, S3 cache state without S3 lifetime, S3 lifetime without generation
or S3 cache proof, S3 handoffs without a current-generation comparator, cache
coverage gaps, PAT/MTRR cache-policy mismatches, GCD/EFI type conflicts,
entry-authoritative non-authoritative memory sections, framebuffer mask and
backing-resource failures, overlapping PCI root windows, invalid 64-bit BAR
slot combinations, duplicate/zero PCI assignments, excessive assignment
counts, MMIO32 above 4 GiB, I/O attributes, oversized PRH GUID-HOB publication,
and reserved runtime-policy sections.

## Sources inspected

Line ranges below refer to the source trees and hashes named in this section.

cdk2 fixed base:

* `UefiPayloadPkg/Library/CbParseLib/CbParseLib.c`
  * Lines 168-199: `IsValidCbTable()` checks the coreboot header and table
    checksums.
  * Lines 210-280: `GetCbTableFromFdt()` bounds an FDT-carried table to the
    advertised CBMEM range.
  * Lines 381-410: `FindCbTag()` iterates the existing length-delimited
    records.
  * Lines 552-582: `ParseMemoryInfo()` converts only `CB_TAG_MEMORY` to
    E820-style ranges.
  * Lines 594-624: `ParseBootMode()` consumes only normal and flash-update
    modes.
  * Lines 814-925: `ParseMiscInfo()` validates CFR version, size, and CRC before
    building HOBs.
* `UefiPayloadPkg/cdk2/native/coreboot.c`,
  `UefiPayloadPkg/cdk2/native/coreboot.h`, and
  `UefiPayloadPkg/cdk2/native/coreboot_hobs.c`
  * `coreboot.c` lines 46-181: the native parser validates table shape,
    checksums, bounded records, forwarding, and memory ranges.
  * `coreboot.c` lines 194-233: forwarding is bounded by
    `CDK2_COREBOOT_MAX_FORWARD_DEPTH`.
  * `coreboot.h` lines 15-52: the handoff limits and stored state cover only
    table metadata, memory ranges, largest usable RAM, and forward address.
  * `coreboot_hobs.c` lines 13-20: resource HOBs use broad cacheability
    capabilities; they are not authoritative current cacheability or
    page-protection state.
  * `coreboot_hobs.c` lines 176-210, 284-328, and 757-826: cdk2 validates
    non-overlapping memory ranges, maps coarse range types into EFI resource and
    allocation types, and resolves only capsule/flash-update boot mode.
* `UefiPayloadPkg/UefiPayloadPkg.dsc`
  * Lines 457-465: the coreboot build selects `CbParseLib`.
  * Lines 545 and 555: `MtrrLib` and `CpuPageTableLib` remain linked.
  * Lines 908-910: `PcdCpuDisableMtrrProgramming` is `TRUE` and
    `PcdCpuRefreshGcdMemoryAttributes` is controlled by the CPU option.
  * Line 1094: `PcdPciDisableBusEnumeration` is `TRUE`, while lines 1367-1372
    still include the PCI host bridge and PCI bus drivers.
  * Lines 1471-1479 and 1562: SMM components and `CpuDxe` are still part of the
    x64 build.
* `UefiCpuPkg/CpuDxe/CpuDxe.c` and `UefiCpuPkg/CpuDxe/CpuPageTable.c`
  * `CpuDxe.c` lines 22-86: MTRR-derived ranges are decoded to verify cache
    attributes.
  * `CpuDxe.c` lines 373-502: `CpuSetMemoryAttributes()` splits cacheability
    from protection bits; with MTRR programming disabled, cacheability requests
    are checked against current MTRR-derived state rather than blindly accepted.
  * `CpuDxe.c` lines 668-764: GCD attributes are refreshed from MTRRs and
    paging.
  * `CpuDxe.c` lines 934-1007: MMIO gaps are added to GCD by payload CPU code.
  * `CpuPageTable.c` lines 27-38, 101-143, 911-924, and 990-1085:
    page-table/PAT/protection bits are represented and refreshed separately
    from MTRRs, and SMM page tables are treated as distinct from DXE page
    tables.
* `UefiPayloadPkg/Library/PciHostBridgeLib/PciHostBridgeLib.c` and
  `UefiPayloadPkg/Library/PciHostBridgeLib/PciHostBridgeSupport.c`
  * `PciHostBridgeLib.c` lines 189-218: a Universal Payload PCI root-bridge HOB
    is used if present, otherwise the payload scans for root bridges.
  * `PciHostBridgeLib.c` lines 263-275: the coreboot path should not enumerate
    new PCI resources.
  * `PciHostBridgeSupport.c` lines 117-150: the fallback path parses assigned
    BAR resources.
* `UefiPayloadPkg/Library/PlatformBootManagerLib/PlatformBootManager.c`
  * Lines 1160-1236 and 1254-1323: UEFI `BootNext`, `BootOrder`, generated
    fallback device paths, storage boot, and removable boot policy remain
    payload-owned.
  * Lines 1480-1493 and 1568-1579: capsule boot policy is keyed from
    `BOOT_ON_FLASH_UPDATE`, but capsule processing remains payload-owned.
* `UefiPayloadPkg/CfrSetupMenuDxe/SetupMenu.c` and
  `UefiPayloadPkg/CfrSetupMenuDxe/SetupMenuCfr.c`
  * `SetupMenu.c` lines 30-64: cdk2 publishes HII data and inserts runtime
    components from CFR.
  * `SetupMenuCfr.c` lines 651-672, 840-892, and 1050-1180: cdk2 validates
    runtime apply records, publishes fwupd settings, creates variables, updates
    attributes, and locks read-only CFR variables.

coreboot producer tree:

* coreboot repository `https://review.coreboot.org/coreboot` at
  `92587b97bd2aaa6cd8feeb74b592f22b17dce662`.
* `src/commonlib/include/commonlib/coreboot_tables.h`
  * Lines 36-103: current tags include memory, framebuffer, SMMSTOREv2, TPM
    PPI, ACPI RSDP, PCIe ECAM info, EFI firmware info, capsule ranges, CFR
    root, root-bridge-info CBMEM reference, panel poweroff, non-PCI SDHCI, and
    boot mode.
  * Lines 119-137: the table container is length-delimited with
    `struct lb_record { tag, size }`.
  * Lines 139-162: `struct lb_memory_range` has only base, size, and a coarse
    memory type.
  * Lines 353-358: `LB_TAG_X86_ROM_MTRR` only names the variable MTRR index
    covering ROM; it is not a complete cacheability ABI.
  * Lines 555-571, 618-631, and 642-674: SMMSTOREv2, EFI firmware info, CFR,
    and boot mode carry useful state but not complete EFI ownership policy.
* `src/lib/coreboot_table.c`
  * Lines 74-87: `lb_new_record()` appends length-delimited records.
  * Lines 129-160: PCIe base info and framebuffer records are emitted.
  * Lines 300-340: CBMEM references include root-bridge-info by address only.
  * Lines 511-519: boot mode is emitted.
  * Lines 534-642: `write_coreboot_table()` emits CFR, bootmem memory ranges,
    framebuffer, PCIe base info, CBMEM references, SMMSTOREv2, EFI firmware
    info, capsules, boot media parameters, board config, TPM PPI, architecture
    records, and all CBMEM entries.
* `src/lib/bootmem.c`
  * Lines 174-195: `bootmem_write_memory_table()` serializes `bootmem_os`
    ranges into `LB_MEM_*` classes.
* `src/drivers/option/cfr.c`
  * Lines 418-445: CFR root records carry version and CRC.
* `src/drivers/efi/capsules.c`
  * Lines 776-801: capsule publication sets flash-update boot mode and emits
    capsule ranges.
* `src/drivers/smmstore/ramstage.c`
  * Lines 11-39: SMMSTOREv2 publishes block geometry, MMIO read address, SMM
    communication buffer, and APM command.
    Current upstream coreboot fills both the deprecated 32-bit MMIO address and
    the length-gated 64-bit MMIO address; this cdk2 base still consumes the
    32-bit field and rejects SMMSTORE ranges at or above 4 GiB in the UPL FDT
    bridge.  That is a compatibility/test item, not a deletion proof.

Depthcharge reference:

* coreboot wrapper `payloads/external/depthcharge/Makefile` pins stable
  Depthcharge to `c48613a71c1ee29295b184c51fe5dadf71b543c4`; `Kconfig`
  points at
  `https://chromium.googlesource.com/chromiumos/platform/depthcharge`.
* At that commit, `src/arch/x86/boot.c` converts coreboot memory ranges to
  Linux E820 entries at lines 35-55 and 76-92, clears the top write-protected
  ROM MTRR at handoff when it matches the expected type at lines 125-158, and
  finalizes coreboot through SMI commands at lines 160-185.
* Current Depthcharge main commit `de480220c2aff9cd22d595574d597e1513e7eb5e`
  keeps the same ownership shape in `src/arch/x86/boot.c`: memory ranges become
  Linux E820 entries, ROM MTRR cleanup is opportunistic, and coreboot finalize
  remains a handoff cleanup action.

Depthcharge is therefore not a UEFI ownership precedent.  It does not maintain
EFI GCD memory space descriptors, implement
`EFI_CPU_ARCH_PROTOCOL.SetMemoryAttributes()`, merge MTRR-derived cacheability
with page-table protection bits, manage SMM page tables or SMM memory attribute
protocols, publish UEFI Boot#### device paths, or expose PCI host-bridge
resource allocation protocols.  Its coreboot-table usage proves that the memory
map is sufficient for Linux E820 handoff; it does not prove that cdk2 can delete
UEFI memory-attribute, PCI, boot-manager, or SMM work.

## Current ownership matrix

| State | coreboot-owned today | cdk2 payload-owned today | Deletion status |
| --- | --- | --- | --- |
| DRAM and reserved topology | `LB_TAG_MEMORY` from `bootmem_os`; base, size, coarse `LB_MEM_*` type | Conversion to EFI resource HOBs, allocation HOBs, GCD memory spaces, MMIO gap handling | Keep payload work; table lacks EFI attributes and full GCD policy |
| MTRR programming | coreboot/FSP programs initial MTRRs before payload entry | cdk2 links `MtrrLib` to decode, validate, refresh GCD, and synchronize AP/SMM paths; programming is disabled for coreboot builds | No further deletion until a versioned cacheability/MTRR handoff exists |
| EFI cache attributes | Not published as an EFI contract | `CpuDxe` derives GCD cacheability from current MTRRs and rejects incompatible cache requests when programming is disabled | ABI-dependent future work |
| PAT and page protection | Not published | `CpuPageTable` applies and refreshes RO/RP/XP attributes; DXE and SMM page tables are distinct | ABI-dependent future work |
| PCIe ECAM/root bridge topology | `LB_TAG_PCIE` and optional root-bridge-info CBMEM reference | UPL PCI HOB if present; otherwise payload scans root bridges and assigned BARs; PCI enumeration remains disabled | Root-bridge scanning can only be removed after typed assigned-resource ABI |
| Boot reason | `LB_TAG_BOOT_MODE` plus capsule ranges; cdk2 consumes normal and flash-update | UEFI BootNext, BootOrder, generated fallback device paths, storage/removable policy, capsule boot flow | Only broad flash-update intent is shared; device path ownership remains payload |
| CFR setup description | CFR root with version and CRC | cdk2 validates CFR, builds HII/setup variables, locks policy, and handles runtime apply | Keep payload runtime/HII ownership; future ABI can reduce copying, not policy |
| SMMSTORE and SMM communication | SMMSTOREv2 geometry, MMIO read address, comm buffer, APM command | SMM access/control/runtime, SMM CPU, SMRAM, SMM page attributes, comm-buffer validation | SMM lifetime and memory policy still payload-owned |
| ACPI and SMBIOS tables | ACPI RSDP and SMBIOS table pointers/CBMEM references | UPL HOB publication, EFI configuration-table exposure, table lifetime checks | Keep table publication; current tags are not an ownership or lifetime contract |
| Power/runtime state | Some boot mode values, panel poweroff commands, board/config CBMEM refs | UEFI variables, runtime services, ACPI/SMBIOS exposure, shutdown/reset policy | ABI-dependent future work |

## Actionable consumer inventory

This inventory names the cdk2 consumers that are candidates for replacement by
existing coreboot records or by one section of the proposed versioned handoff.
Entries marked "current tag" are already safe table consumers; entries marked
"extension" are explicit no-go items until the named ABI section is complete and
authoritative.

* Memory topology, HOB placement, GCD resources, and MTRR/GCD refresh:
  `UefiPayloadEntry.c` calls `ParseMemoryInfo()` for TOLUD, resource HOBs, MMIO
  HOBs, and HOB placement at lines 369, 380, 483, and 585; the edk2 backend
  repeats that at `Cdk2EfiHobs.c` lines 377, 388, and 528, and
  `Cdk2EfiServices.c` line 175; the native backend parses `CB_TAG_MEMORY` in
  `coreboot.c` lines 967-1005 and builds EFI resource/allocation HOBs in
  `coreboot_hobs.c` lines 936-980.  Current tag: `CB_TAG_MEMORY` is enough only
  for topology and fallback HOB construction.  Extension: `MEMORY_POLICY` plus
  `X86_CACHE_STATE`.  Deletion opportunity after that ABI: delete or fence
  TOLUD-derived MMIO synthesis and broad cacheability synthesis in the payload
  memory callbacks and `Cdk2CorebootAppendResource()`, and remove
  `CpuDxe` MTRR-derived GCD refresh/readback only when the record supplies the
  full EFI cache/protection/GCD contract.  No-go now: `CpuSetMemoryAttributes()`
  still validates cache requests against MTRRs when programming is disabled, and
  `RefreshGcdMemoryAttributes()` still merges MTRR and paging state.
* PCI root bridges and assigned device windows:
  `PciHostBridgeGetRootBridges()` consumes a Universal Payload PCI root-bridge
  HOB if present and otherwise calls `ScanForRootBridges()` at
  `PciHostBridgeLib.c` lines 191-218; `PciHostBridgeSupport.c` parses assigned
  BARs at lines 144-291, scans buses at lines 302-617, and toggles
  `PcdPciDisableBusEnumeration` from HOB ownership at lines 630-691.  Current
  tags: upstream `LB_TAG_PCIE` and root-bridge-info CBMEM references are not
  typed assigned-resource ownership.  Extension: `PCI_ROOT_BRIDGES` plus
  `PCI_ASSIGNMENTS`.  Deletion opportunity after that ABI: replace the scan/BAR
  fallback with direct UPL PCI root-bridge HOB construction for authoritative
  bridges, while keeping the UEFI host-bridge and PCI I/O protocols.  No-go now:
  the current producer does not publish complete I/O/MMIO/prefetchable windows
  or per-BAR ownership.
* Framebuffer and GOP lifetime:
  legacy and edk2 paths consume `ParseGfxInfo()` at `UefiPayloadEntry.c`
  line 388 and `Cdk2EfiHobs.c` line 396; the native backend consumes
  `CB_TAG_FRAMEBUFFER` at `coreboot_backend.c` lines 1767-1822; GOP still
  matches a PCI display device, checks BAR resources, enables PCI attributes,
  and configures blit state in `GraphicsOutput.c` lines 1467-1582 and
  1705-1747.  Current tag: `CB_TAG_FRAMEBUFFER` is enough for the graphics-info
  HOB geometry.  Extension: `FRAMEBUFFER` tied to authoritative
  `PCI_ASSIGNMENTS` and `MEMORY_POLICY`.  Deletion opportunity after that ABI:
  remove BAR-size matching and redundant geometry fallback for authoritative
  devices.  No-go now: the framebuffer tag lacks BAR ownership, GCD/cache
  policy, and lifetime.
* Boot mode, capsules, BootNext, BootOrder, and removable fallback:
  `ParseBootMode()`, `ParseCapsules()`, and `ParseIsDiskCapsulesBoot()` are used
  by `UefiPayloadEntry.c` lines 429 and 508, `Cdk2EfiHobs.c` lines 453 and 553,
  and `Cdk2EfiServices.c` line 121; the native backend resolves only
  capsule/flash-update boot mode in `coreboot_hobs.c` lines 809-880 and appends
  capsule HOBs in `coreboot_backend.c` lines 917-964.  The actual UEFI boot
  manager owns BootNext, BootOrder, generated storage paths, targeted removable
  discovery, connect-all fallback, and capsule processing in
  `PlatformBootManager.c` lines 1166-1323, 1348-1415, 1480-1493, and
  1543-1587.  Current tags: `CB_TAG_BOOT_MODE`, `CB_TAG_BOOT_INFO`, and
  `CB_TAG_CAPSULE` are enough for flash-update/capsule reason only.  Extension:
  `BOOT_INTENT`.  Deletion opportunity after that ABI: skip selected fallback
  discovery paths only when the record carries an EFI device path or exact
  translatable target plus BootNext/BootOrder precedence.  No-go now: current
  tags do not name a UEFI boot option.
* CFR setup forms and runtime policy:
  `ParseMiscInfo()` is used by `UefiPayloadEntry.c` line 491 and
  `Cdk2EfiHobs.c` line 536; the native backend validates and republishes CFR
  forms in `coreboot_backend.c` lines 979-1344; `SetupMenu.c` publishes HII and
  creates runtime components at lines 30-64; `SetupMenuHii.c` serves HII config
  routing and variables at lines 233-414; `SetupMenuCfr.c` builds runtime
  components from CFR HOBs at lines 1848-2002.  Current tag: `CB_TAG_CFR_ROOT`
  is enough for versioned/CRC-checked setup description.  Extension:
  `RUNTIME_POLICY`.  Deletion opportunity after that ABI: reduce duplicate CFR
  copying or runtime apply validation only when the producer defines variable
  namespace, apply method, reboot requirement, and SMM lifetime.  No-go now: CFR
  records describe forms, not UEFI runtime ownership.
* SMMSTORE, SMM communication, S3, and SMM lifetime:
  `ParseSmmStoreInfo()` feeds `UefiPayloadEntry.c` line 407,
  `FitUniversalPayloadEntry.c` line 72, and `Cdk2EfiHobs.c` line 423; the native
  backend emits the SMMSTORE HOB from `CB_TAG_SMMSTOREV2` at
  `coreboot_backend.c` lines 1837-1855; `SmmStoreLib` copies the HOB to runtime
  memory, validates comm/MMIO ranges, probes the backend, and marks GCD runtime
  ranges at `SmmStore.c` lines 520-677.  Current tag: `CB_TAG_SMMSTOREV2` is
  enough for geometry and command parameters, and upstream coreboot now includes
  a length-gated 64-bit MMIO address.  Extension: `RUNTIME_POLICY` plus
  `MEMORY_POLICY`.  Deletion opportunity after that ABI: remove payload-added
  GCD runtime marking and backend lifetime assumptions only when the record
  covers comm-buffer lifetime, SMMSTORE MMIO ownership, S3 validity, and SMRAM
  copy/validation.  No-go now: SMM and runtime memory policy remain payload
  responsibilities.
* ACPI, SMBIOS, serial, firmware info, and TPM PPI:
  `ParseAcpiTableInfo()`, `ParseSmbiosTable()`, `ParseSerialInfo()`,
  `ParseFirmwareInfo()`, and `ParseTPMPPIInfo()` are used by the legacy and edk2
  paths at `UefiPayloadEntry.c` lines 418, 438, 449, 468, and 599, and by the
  native backend at `coreboot_backend.c` lines 748-912, 1712-1755, 1865-1925,
  and 1935-1955.  Current tags and CBMEM references are sufficient for these
  narrow HOB publications.  Deletion opportunity: none beyond keeping these as
  table-to-HOB translations; they do not prove ownership for memory attributes,
  PCI windows, boot targets, or SMM lifetime.

## Safe immediate deletions

None in runtime code for the fixed `4d4deeec700e26f98d66f6a56017979e37ca6bff`
base.

The duplicate MTRR programming concern is already addressed by
`PcdCpuDisableMtrrProgramming|TRUE` in the coreboot payload build.  The
remaining MTRR, page-table, PCI, boot-manager, CFR, and SMM code is not merely
duplicated initialization; it is currently the only place where cdk2 derives or
enforces UEFI-visible policy from partial coreboot state.  Deleting it now would
replace checked fallback behavior with an implicit trust boundary that the
coreboot table does not express.

## Hot spots and performance implications

The high-value duplicate-work target is not the record parser itself.  Parsing a
validated table record and checking a CRC is cheap compared with PCI
configuration-space walks, BAR probing, removable-device discovery, SMMSTORE SMI
round trips, and full GCD attribute refresh.

* MTRR/GCD: coreboot builds already avoid the riskiest duplicate work through
  `PcdCpuDisableMtrrProgramming|TRUE`.  The remaining `MtrrLib` users are
  readback, verification, and synchronization paths.  Deleting them would save
  MTRR range walks during `CpuSetMemoryAttributes()` and GCD refresh, but only
  after coreboot publishes an authoritative cacheability and AP/S3 lifetime
  contract.
* PCI: `ScanForRootBridges()` and BAR probing are real boot-time hot spots on
  systems without a complete UPL PCI root-bridge HOB.  A complete PCI assignment
  section is the most plausible performance win because cdk2 could avoid
  config-space probing while still publishing the UEFI PCI I/O protocols.
* Framebuffer: the framebuffer tag saves mode discovery, but GOP startup still
  matches a PCI display device, validates the BAR, enables PCI attributes, and
  configures blit state.  A richer table can reduce that work only when it is
  tied to the authoritative PCI assignment section.
* SMMSTORE: table parsing is not the hot path.  Runtime variable operations are
  SMI round trips plus communication-buffer copies.  The current table does not
  let cdk2 skip runtime buffer allocation, backend probing, or GCD/runtime
  memory marking.
* Boot targets: removable-media discovery and connect-all fallback can be slow.
  They can only be skipped when boot intent carries a selected UEFI device path,
  or an exact translatable coreboot target, plus BootNext/BootOrder and fallback
  precedence.

## ABI-dependent future work

The future ABI should be one length-delimited coreboot record with a versioned
header and optional, independently validated sections.  One record keeps the
handoff atomic while allowing cdk2 to delete one ownership lane at a time only
when the relevant section is present, complete, and authoritative.

Suggested record name:

```c
#define LB_TAG_PAYLOAD_RESOURCE_HANDOFF  0x004b /* value to allocate upstream */

struct lb_payload_resource_handoff {
  uint32_t tag;
  uint32_t size;
  uint16_t revision;
  uint16_t header_length;
  uint16_t section_header_length;
  uint16_t flags;
  uint32_t crc32;
  uint32_t section_count;
  uint32_t producer_stage;
  lb_uint64_t producer_generation;
  lb_uint64_t lifetime_flags;
  /* struct lb_payload_resource_section sections[]; */
};

struct lb_payload_resource_section {
  uint16_t type;
  uint16_t flags;
  uint16_t header_length;
  uint16_t entry_size;
  uint32_t entry_count;
  uint32_t offset;
  uint32_t length;
};
```

Required generic rules:

* `tag` and `size` use the normal coreboot table record framing.
* `revision` starts at 1.  Revision 2 adds the cache-state
  `physical_address_bits` field.  Unknown major revisions are ignored.
* `header_length` and every section `header_length` allow forward extension.
* `crc32` covers the complete record with the `crc32` field treated as zero.
  The algorithm is the non-reflected, MSB-first CRC-32 polynomial
  `0x04c11db7`, with `init=0`, `refin=false`, `refout=false`, and `xorout=0`.
  Bytes are processed in record order and the stored value is the raw register
  value; a producer must not substitute the reflected Ethernet CRC-32
  parameters.
* `section_count`, `offset`, `length`, `entry_size`, and `entry_count` must not
  overflow, overlap incorrectly, or point outside `size`.
* Unknown section types are skipped unless their section flags mark them
  mandatory.
* All integer fields are little endian and naturally aligned to the existing
  4-byte coreboot record rule.  Any 64-bit field uses coreboot's `lb_uint64_t`
  wire type, or an equivalent pair of little-endian 32-bit words, not native
  `uint64_t`.
* cdk2 ignores the whole record and uses current fallback paths if generic
  validation fails.

Suggested section types:

```c
enum lb_payload_resource_section_type {
  LB_PRH_SECTION_MEMORY_POLICY      = 1,
  LB_PRH_SECTION_X86_CACHE_STATE    = 2,
  LB_PRH_SECTION_PCI_ROOT_BRIDGES   = 3,
  LB_PRH_SECTION_PCI_ASSIGNMENTS    = 4,
  LB_PRH_SECTION_BOOT_INTENT        = 5,
  LB_PRH_SECTION_RUNTIME_POLICY     = 6,
  LB_PRH_SECTION_FRAMEBUFFER        = 7,
};
```

### Memory policy section

The memory policy section is the minimum gate for deleting MTRR/GCD/page-table
duplicate work.  It must contain sorted, non-overlapping entries:

```c
struct lb_prh_memory_policy_entry {
  lb_uint64_t base;
  lb_uint64_t length;
  lb_uint64_t capabilities;
  lb_uint64_t attributes;
  uint32_t gcd_type;
  uint32_t efi_memory_type;
  uint32_t owner_flags;
  uint32_t reserved;
};
```

The `capabilities` and `attributes` fields use EFI memory capability and
attribute bits, including exactly one EFI cacheability attribute when cache is
authoritative and any RO/RP/XP bits when protection is authoritative.
`gcd_type` identifies system memory, memory-mapped I/O, reserved, persistent,
or non-existent space.  `efi_memory_type` is meaningful for ranges that become
allocation or memory map entries.

Validation requirements:

* Reject zero length, address wraparound, overlap, unsupported EFI bits, and
  sub-4 KiB protection ranges.
* Reject cache-authoritative entries that do not cover all ranges cdk2 would
  otherwise expose through GCD.
* Reject protection-authoritative entries unless paging is enabled and the
  record states whether the attributes apply to DXE page tables, SMM page
  tables, or both.
* Reject memory policy deletion unless every range needed by the current
  `CB_TAG_MEMORY`, ACPI, framebuffer, SMMSTORE, capsule, PCI MMIO, SMRAM, and
  runtime-service flows is either present or intentionally delegated back to the
  payload through an owner flag.

### x86 cache state section

If cdk2 is expected to delete `MtrrLib` readback/decoding rather than only avoid
MTRR programming, coreboot must publish the x86 PAT/MTRR cacheability state that
backs the memory policy:

```c
struct lb_prh_x86_cache_state {
  lb_uint64_t mtrr_default_type_msr;
  lb_uint64_t pat_msr;
  lb_uint64_t fixed_mtrr_crc64;
  uint32_t variable_count;
  uint32_t physical_address_bits;
  uint32_t flags;
  uint32_t reserved;
  /* struct lb_prh_x86_variable_mtrr variable[]; */
};

struct lb_prh_x86_variable_mtrr {
  lb_uint64_t phys_base_msr;
  lb_uint64_t phys_mask_msr;
};
```

`physical_address_bits` is the producer CPU physical-address width used when
encoding the raw variable MTRR mask/base MSRs. Consumers must use it to derive
the valid MTRR address mask before decoding variable MTRR lengths.

This section is not a request for the payload to program MTRRs.  It is the
producer-owned proof that the normalized EFI cacheability policy corresponds to
the PAT/MTRR hardware state coreboot left behind.  Deleting cdk2 MTRR decoding
is only correct if the section also asserts BSP/AP synchronization and the S3
resume contract.  If cdk2 still has to read, decode, or synchronize PAT/MTRRs
to prove the state, then `MtrrLib` remains required.

### PCI assignments section

The PCI section gates removal of payload root-bridge/BAR scanning.  It must
describe each root bridge window and every assigned I/O, MMIO32, MMIO64, and
prefetchable BAR.  The parser-only branch splits those into root-bridge and
assignment sections so cdk2 can validate host-bridge windows independently from
device BARs:

```c
struct lb_prh_pci_root_bridge_entry {
  uint16_t segment;
  uint8_t bus_start;
  uint8_t bus_end;
  uint32_t flags;
  lb_uint64_t io_base;
  lb_uint64_t io_length;
  lb_uint64_t mem32_base;
  lb_uint64_t mem32_length;
  lb_uint64_t mem64_base;
  lb_uint64_t mem64_length;
  lb_uint64_t pref_mem32_base;
  lb_uint64_t pref_mem32_length;
  lb_uint64_t pref_mem64_base;
  lb_uint64_t pref_mem64_length;
};
```

```c
struct lb_prh_pci_assignment_entry {
  uint16_t segment;
  uint8_t bus;
  uint8_t device;
  uint8_t function;
  uint8_t bar;
  uint8_t resource_type;
  uint8_t flags;
  lb_uint64_t base;
  lb_uint64_t length;
  lb_uint64_t attributes;
};
```

If a root bridge is authoritative, the record must be complete for that
segment/bus range.  cdk2 may then build the UPL PCI root-bridge HOB directly
and skip `ScanForRootBridges()`.  Missing or malformed PCI sections keep the
current scan/parse fallback.

### Framebuffer section

The framebuffer section is intentionally tied to PCI/resource ownership.  It can
prove linear framebuffer geometry and the backing memory range, but cdk2 cannot
delete GOP/framebuffer policy unless the PCI assignment section proves the
display BAR and the memory policy section proves the corresponding cache/GCD
attributes:

```c
struct lb_prh_framebuffer_entry {
  lb_uint64_t physical_address;
  lb_uint64_t size;
  uint32_t x_resolution;
  uint32_t y_resolution;
  uint32_t bytes_per_line;
  uint8_t bits_per_pixel;
  uint8_t red_mask_pos;
  uint8_t red_mask_size;
  uint8_t green_mask_pos;
  uint8_t green_mask_size;
  uint8_t blue_mask_pos;
  uint8_t blue_mask_size;
  uint8_t reserved_mask_pos;
  uint8_t reserved_mask_size;
  uint8_t reserved[3];
  uint32_t owner_flags;
};
```

Malformed masks, zero dimensions, size underruns, unknown owner flags, or an
authoritative section without authoritative geometry keep the current GOP and
framebuffer fallback.

### Boot intent section

The boot intent section gates any future deletion of UEFI boot-manager fallback
logic.  `LB_TAG_BOOT_MODE` is not enough: it is a broad reason, not a selected
UEFI boot option.  A complete boot intent needs at least:

* boot reason and security flags;
* selected boot target class;
* an EFI device path blob, or a versioned coreboot device path with exact cdk2
  translation rules;
* whether UEFI `BootNext` must override coreboot intent;
* whether removable media fallback is allowed;
* capsule/update restrictions for flash-update mode.

Without those fields, cdk2 must keep `BootNext`, `BootOrder`, generated device
paths, storage/removable fallback, and capsule boot policy.

### Runtime policy section

The runtime policy section gates reductions in CFR/power/SMMSTORE duplication.
It must define which runtime state is coreboot-owned, which state becomes UEFI
variable state, and which updates are mediated by SMM.  It should include:

* SMM communication buffer range and lifetime;
* SMMSTORE read/write block ownership;
* CFR variable namespace, apply method, and reboot requirement;
* panel/power/runtime commands that remain valid after ExitBootServices;
* whether the record was copied into SMRAM before lock, if SMM consumes it.

Existing CFR records already provide version and CRC for setup description.
They do not replace UEFI HII/runtime variable policy by themselves.

## Lifetime semantics

Cold boot:

* The record is valid from payload entry only after full table checksum and
  record checksum validation.
* The record must state whether it is valid until EndOfDxe, ExitBootServices,
  or runtime.
* Payload fallback remains mandatory for absent, unsupported, partial, or
  malformed records.

S3 resume:

* The record must be regenerated on resume or marked S3-valid with a producer
  generation that cdk2 can compare with the current resume flow.
* MTRR/AP, paging, SMMSTORE, and PCI assignment sections are not S3-valid unless
  their section flags explicitly say so.
* Missing or stale S3 records fall back to the current cdk2 resume ownership.

SMM:

* DXE page-table policy does not imply SMM page-table policy.
* SMM consumers need either a copy of the validated record inside SMRAM before
  SMM lock, or an SMM-owned validation path.
* SMRAM, SMRR/PRMRR, SMM communication buffers, SMMSTORE ranges, and SMM memory
  attributes must be represented explicitly before cdk2 can delete SMM-side
  memory-attribute logic.

## Test plan for the future ABI

Parser host tests:

* absent record keeps current fallback;
* valid revision 1 record with memory policy, x86 cache state, PCI root bridge,
  PCI assignment, and unknown skippable section;
* bad coreboot table checksum falls back or rejects as today;
* bad record CRC rejects the new ABI only;
* short header, short section, section overflow, count overflow, and record
  overlap reject;
* memory range wraparound, zero length, overlap, unsupported EFI attribute bits,
  and sub-page protection reject;
* cache-authoritative memory policy without matching MTRR/AP lifetime rejects;
* PCI authoritative section missing a root bridge or assigned BAR rejects;
* boot intent with malformed EFI device path rejects;
* S3/SMM deletion is disabled unless the relevant lifetime bits are present.

QEMU evidence for an implementation PR:

* boot a coreboot+cdk2 image with no new record and show identical fallback
  behavior;
* boot with a valid record and show the parser creates the expected HOB/policy
  data while runtime deletion remains off;
* boot with malformed CRC and malformed range fixtures and show cdk2 ignores the
  new ABI and reaches the current fallback path;
* for any later deletion PR, add QEMU coverage for cold boot, S3 resume where
  available, and SMM-enabled builds before removing code.

## Reviewable next step

This branch is now a parser-only code PR.  The remaining upstream sequence is:

1. get the candidate tag and wire structure accepted in coreboot or renumber the
   cdk2 consumer to the accepted tag;
2. add a coreboot producer and QEMU fixtures for absent, valid, and malformed
   records;
3. consume the GUID HOB only after the producer contract is stable and the
   relevant section is complete and authoritative;
4. add QEMU evidence that fallback is unchanged;
5. keep `MtrrLib`, `CpuPageTableLib`, PCI host-bridge scanning, UEFI boot
   manager policy, CFR runtime handling, and SMM memory-attribute logic in place.

Only after the parser-only PR is merged and coreboot producers populate a
complete, versioned, lifetime-qualified record should cdk2 remove the matching
payload-owned work one ownership lane at a time.

## Deletion checklist

Before removing `MtrrLib` readback or EFI attribute refresh:

* memory policy covers every GCD-visible range, including MMIO gaps, ACPI,
  framebuffer, capsule, runtime, SMRAM/SMM communication, PCI MMIO, and CBMEM
  table ranges;
* cache-authoritative entries contain exactly one EFI cache attribute;
* protection-authoritative entries state whether they apply to DXE page tables,
  SMM page tables, or both;
* x86 cache state includes IA32_PAT, MTRR default type, fixed-MTRR proof,
  variable MTRRs, BSP/AP synchronization, and S3 validity.

Before removing PCI/root-bridge fallback:

* root bridge windows are complete for every segment/bus range;
* every assigned BAR is represented with type, base, length, and attributes;
* producer states whether cdk2 may skip probing, or whether incomplete bridges
  are delegated back to payload scanning.

Before removing BDS/boot fallback:

* boot intent carries a selected EFI device path or exact translatable coreboot
  target, BootNext/BootOrder precedence, removable fallback policy, and
  flash-update/capsule restrictions.

Before removing CFR/S3/SMM lifetime work:

* CFR runtime namespace, apply method, and reboot requirements are explicit;
* SMMSTORE and communication buffers include range, ownership, and runtime
  lifetime;
* S3-valid records are regenerated or generation-checked on resume;
* SMM consumers validate or receive a locked SMRAM copy before SMM lock.
