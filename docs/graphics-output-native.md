# Native graphics output boundary

The admitted `GraphicsOutputDxe` file is
`0b04b2ed-861c-42cd-a22f-c3aafaccb896` at FV offset `0x2ee3c8`. It is a DXE
driver (`0x07`) with a fixed `0x9052` byte FFS envelope and no DEPEX. The PE32
section starts at file offset `0x18`, and its image begins at `0x1c`.

The native binding validates the graphics-info HOB, matches the framebuffer to
a PCI BAR resource descriptor, and publishes one ACPI ADR child with GOP. GOP
supports direct RGB/BGR and checked contiguous bit masks, all four BLT
operations, centered aspect capping, and a software HiDPI mode. ReadyToBoot
returns GOP to the physical mode and exposes the real framebuffer for OS
handoff. Start and stop release child opens, protocol publication, event, and
parent ownership in reverse order.

`native-graphics-output-package` emits the admitted GUID, type, envelope,
no-DEPEX ordering, and subsystem 11 without modifying retained inventory.
