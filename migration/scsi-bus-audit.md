# Native SCSI bus admission

The native SCSI bus driver replaces FFS
`0167ccc4-d0f7-4f21-a3ef-9e64b7cdce8b` at offset `0x32b5f0` while preserving
the exact `0x703e` envelope. Its sections are PE32 (`0x7004`), UI (`ScsiBus`),
and version (`1.0`), with no DEPEX section.

The driver consumes Extended SCSI Pass Thru, validates targets with aligned
INQUIRY commands, publishes DevicePath plus SCSI I/O children transactionally,
and preserves controller and child ownership for Stop or Unload retry. Native
admission reduces the retained inventory to 33.

The exact composition target also refreshes the native ATA/ATAPI producer in
the accepted ATA bus predecessor. That bounded repair preserves the producer's
existing envelope while setting the AHCI PACKET DMA feature required for real
ExtScsi INQUIRY commands; the SCSI replacement is then applied to its own slot.
