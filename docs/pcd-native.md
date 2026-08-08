# Native PCD service boundary

The admitted `PcdDxe` file is `80cf7257-87ab-47f9-a3fe-d50b76d89541`, at
offset `0x441d0`, with an `0x945a` byte FFS envelope and DXE file type `0x07`.
Its first section is the generated `0x414` byte version-seven DXE PCD database,
followed by the six-byte `TRUE; END` DXE DEPEX. The PE32 section begins at file
offset `0x434` and its image begins at `0x438`.

The native model consumes the build-generated database rather than compiling
platform PCD values into service code. It validates the signature, service
version, lengths, all table spans and every directly addressable datum before
exposing native and DynamicEx lookup. It preserves mutable data in place,
including pointer/string current-size rules, callback-before-write ordering,
one-shot SKU selection and token iteration.

The inventory-neutral `native-pcd-package` target requires the extracted RAW
payload through `CDK2_NATIVE_PCD_DATABASE`. It emits the admitted GUID, type,
`0x945a` size, RAW/DEPEX/PE32 ordering, subsystem 11 and fixed PE32 section
envelope without changing the retained FV or configuration.
