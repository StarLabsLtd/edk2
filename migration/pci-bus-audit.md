# Native PCI Bus migration audit

The admitted `PciBusDxe` FFS has GUID
`93b80004-9fb3-11d4-9a3a-0090273fc14d`, offset `0x28c0c0`, exact envelope
`0x18042`, file type `0x07`, and no DEPEX section.

The implementation follows the `edk2-stable202302` PCI bus lifecycle: global
host-bridge resource allocation, recursive multifunction and bridge discovery,
transactional BAR sizing/programming, per-function Device Path and PCI I/O
publication, DMA/IOMMU handling, option-ROM ownership, and hot-plug rollback.
It is composed after native Fat and reduces the retained inventory to 37.
