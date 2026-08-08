# Native PCD service boundary

The admitted `PcdDxe` file is `80cf7257-87ab-47f9-a3fe-d50b76d89541`, at
offset `0x441d0`, with an `0x945a` byte FFS envelope and DXE file type `0x07`.
Its first section is the generated `0x414` byte version-seven DXE PCD database;
the PE32 section begins at file offset `0x438`. There is no DEPEX section.

The native model consumes the build-generated database rather than compiling
platform PCD values into service code. It validates the signature, service
version, lengths, all table spans and every directly addressable datum before
exposing native and DynamicEx lookup. It preserves mutable data in place,
including pointer/string current-size rules, callback-before-write ordering,
one-shot SKU selection and token iteration.

This source slice is deliberately inventory-neutral. Packaging and protocol
publication must carry this admitted database as the leading RAW section; they
are not enabled until the serial integration base is selected.
