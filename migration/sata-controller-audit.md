# Native SATA controller migration audit

The admitted `SataController` FFS has GUID
`820c59bb-274c-43b2-83ea-dac673035a59`, offset `0x30e500`, exact envelope
`0x604e`, file type `0x07`, and no DEPEX section.

The implementation publishes the IDE Controller Init protocol only for an
owned PCI IDE or AHCI controller.  It preserves PCI attributes across
Start/Stop, derives the admitted channel geometry, retains submitted identify
data and independent PIO/UDMA disqualifications, and returns caller-owned
collective modes.  ComponentName uses `eng` and ComponentName2 uses `en`
exactly.  It is composed after native PciBus and reduces the retained inventory
to 36.
