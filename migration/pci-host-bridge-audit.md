# Native PCI host bridge audit

The admitted `PciHostBridgeDxe` file is GUID
`128fb770-5e79-4176-9e51-9bb268a17dd1`, offset `0x2a4108`, size
`0x1108e`, file type `0x07`, in the exact retained FV at DevicePath head
`366f2e7f810e5d7ac8eb4e89b4c325f2f8f247f2`.

Its `0x3a`-byte DXE DEPEX section requires, in order, CPU I/O2 protocol
`ad61f191-ae5f-4c0e-b9fa-e869d288c64f`, CPU Architecture protocol
`26baccb1-6f42-11d4-bce7-0080c73c8881`, and EFI PCD protocol
`13a3f0f6-264a-3ef0-f2e0-dec512342f34`, combined by two AND opcodes and
terminated by END. The executable section begins at file-relative `0x54`; the
UI and version sections retain `PciHostBridgeDxe` and `1.0`.

The first inventory-neutral slice validates and imports the exact Universal
Payload PCI Root Bridges HOB consumed by the stable driver. It preserves every
bridge aperture and policy field while rejecting truncated arrays, invalid bus
windows, and malformed boolean fields. It deliberately does not yet publish a
host-bridge or root-bridge-I/O protocol, so the retained inventory remains
unchanged until the allocation state machine and CPU I/O-backed protocol ABI
are complete.
