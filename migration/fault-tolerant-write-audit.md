# FaultTolerantWriteDxe admission audit

The baseline retained FV admits `FaultTolerantWriteDxe` as FFS GUID
`fe5cea76-4f72-49e8-986f-2cd899dffe5d`, offset `0x103048`, size `0x8096`,
file type `0x07` (`EFI_FV_FILETYPE_DRIVER`), and UI name
`FaultTolerantWriteDxe`.

Its exact 58-byte DXE DEPEX section has a four-byte section header followed by:

1. `PUSH 8f644fa9-e850-4db1-9ce2-0b44698e8da4`
   (`EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL`);
2. `PUSH b7dfb4e1-052f-449f-87be-9818fc91b733`
   (`EFI_RUNTIME_ARCH_PROTOCOL`);
3. `PUSH 13a3f0f6-264a-3ef0-f2e0-dec512342f34` (dynamic PCD protocol);
4. `AND; AND; END`.

The third dependency is injected by the dynamic PCD library and is present in
the admitted bytes even though the module INF names only FVB and RuntimeArch in
its explicit DEPEX expression.

This source lane is inventory-neutral: it does not replace the admitted FFS,
change either retained-inventory TSV, or alter FV composition.

## PI working-space compatibility

The persistent journal uses the PI/EDK II byte layout rather than a private
on-flash structure.  The 32-byte `EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER`
uses working-block signature `9e58292b-7c68-497d-a0ce-6500fd9f1b95`, the
standard CRC32 calculated with the CRC and state bytes erased, and the
erase-polarity-one valid/invalid transition.  The variable queue uses the
40-byte `EFI_FAULT_TOLERANT_WRITE_HEADER` followed by 40-byte
`EFI_FAULT_TOLERANT_WRITE_RECORD` entries and per-record private data.

The codec scans past completed batches, preserves the last admitted pending
batch across reclaim, records the signed target-to-spare `RelativeOffset`, and
only permits flash-compatible one-to-zero updates between erases.  Host tests
pin the complete 32-byte header for the admitted `0x10000` working-space size,
recover a spare-complete record, reject torn headers and illegal zero-to-one
updates, exhaust the queue to exercise reclaim, and run every core write crash
boundary through the PI codec.

## Native DXE envelope

The source-owned DXE entry locates the authoritative SMMSTORE GUID HOB from
the UEFI HOB-list configuration table, validates the derived geometry, and
enumerates FVB handles by the PI FVB protocol.  It matches the FVB physical
range containing the exact working and spare regions, uses FVB reads, writes,
and erases for both the journal and transaction adapter, and publishes the PI
fault-tolerant-write protocol only after RuntimeArch is present and pending PI
journal recovery succeeds.  If the admitted FVB has not arrived, it registers
a protocol notification; event, pool, and failed-publication paths roll back
their owned resources.

The inventory-neutral build emits a relocatable EFI boot-service-driver PE and
an exact `0x8096`-byte FFS with GUID
`fe5cea76-4f72-49e8-986f-2cd899dffe5d`, file type `0x07`, UI name
`FaultTolerantWriteDxe`, and the admitted 58-byte triple dependency expression
documented above.  Native checks execute the DXE entry fault matrix, validate
the PE relocation contract, and pin the final FFS size.  No FV replacement or
retained-inventory transition is wired in this source commit.

## Admitted Q35 geometry

The admitted Q35 trace reports `NvStorageBase:0xFF800000,
NvStorageSize:0x80000`; its coreboot configuration has an SMMSTORE block size
of `0x10000` and total size `0x80000` (eight blocks). `SmmStoreFvbRuntime`
derives the layout directly from the authoritative SMMSTORE HOB as three
variable blocks, one working block, and four spare blocks. Therefore the exact
admitted values are variable `0xff800000+0x30000`, working
`0xff830000+0x10000`, and spare `0xff840000+0x40000`.

The native contract consumes the existing `SMMSTORE_INFO` HOB and repeats that
derivation with overflow, parity, alignment, and minimum-size validation. It
has no Q35 default and fails closed when the HOB is absent or malformed.
