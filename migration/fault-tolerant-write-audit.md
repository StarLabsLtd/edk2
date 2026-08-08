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
