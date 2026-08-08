# Native TPM2 ACPI table service

The admitted FFS is GUID `c442a847-892a-4f94-ad6f-60317c317be7`, offset
`0x003a18c8`, size `0x0000409e`, and type `0x07`. Its exact 76-byte DXE DEPEX
requires the ACPI table, ACPI SDT, TCG2, and dynamic-configuration protocols.

This inventory-neutral layer only implements checked table construction and
replacement. Final integration needs an authoritative handoff for TPM
interface, OEM identity, base address, and event-log address/length, plus a
TCG2-capable QEMU run. It must not decrement the retained inventory before
those inputs and the exact carrier have been validated.
