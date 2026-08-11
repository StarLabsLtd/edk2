# Native ACPI table admission

The native owner publishes ACPI 1.0/2.0 roots and the ACPI Table protocol,
maintaining checksums, keys, root identity inherited from FADT, replacement,
uninstall, allocation rollback, and below-4G ownership.

The retained file at `0x3f3b58` keeps GUID
`9622e42c-8e38-4a08-9e8f-54f784652f6b`, size `0xb062`, its exact protocol
DEPEX, PE32/UI/version sections, and adjacent FV bytes.
