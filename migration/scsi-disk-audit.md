# Native SCSI disk admission

The native SCSI disk driver replaces FFS
`0a66e322-3740-4cce-ad62-bd172cecca35` at offset `0x332630` while preserving
the exact `0xf042` envelope. Its sections are PE32 (`0xf004`), UI
(`ScsiDisk`), and version (`1.0`), with no DEPEX section.

The driver consumes SCSI I/O, validates direct-access disks, caches INQUIRY
and capacity data, and atomically publishes Block I/O, genuine event-backed
Block I/O 2, Disk Info, Driver Binding, and Component Name protocols. Its
controller scheduler serializes synchronous and asynchronous commands and
retains accepted tokens through reset or Stop cancellation. Native admission
reduces the retained inventory to 32.
