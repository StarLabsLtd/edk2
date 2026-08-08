# Native TPM2 ACPI table service

The admitted FFS is GUID `c442a847-892a-4f94-ad6f-60317c317be7`, offset
`0x003a18c8`, size `0x0000409e`, and type `0x07`. Its exact 76-byte DXE DEPEX
requires the ACPI table, ACPI SDT, TCG2, and dynamic-configuration protocols.

The DXE adapter takes TPM interface, base address, and event-log range from the
immutable native TCG2 service export. It requires an existing platform TPM2
table and ACPI SDT metadata rather than inventing OEM or platform defaults.
The layer remains inventory-neutral until it has run after native TCG2 on the
exact swtpm TIS and CRB carriers.
