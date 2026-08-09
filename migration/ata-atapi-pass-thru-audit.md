# Native ATA/ATAPI pass-through migration audit

The admitted `AtaAtapiPassThruDxe` FFS has GUID
`5e523cb4-d397-4986-87bd-a6dd8b22f455`, offset `0x31d598`, exact envelope
`0xe056`, file type `0x07`, and no DEPEX section.

The implementation owns IDE and AHCI controllers through Driver Binding and
publishes canonical ATA Pass Thru and Extended SCSI Pass Thru protocols.  Its
engines preserve controller state transactionally, negotiate IDE modes, own
AHCI DMA structures, enumerate devices and expose synchronous pass-through,
reset, enumeration and device-path operations.  It is composed directly after
native SATA Controller and reduces the retained inventory to 35.
