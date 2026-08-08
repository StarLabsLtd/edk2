# Native PCH software-SMI dispatcher

The admitted FFS is GUID `60f343e3-2ae2-4aa7-b01e-bf9bd5c04a3b`, offset
`0x000f5f30`, size `0x0000509e`, and type `0x0a`. Its PE image begins at
`0x000f5f98` and declares subsystem 11; the native relocation gate enforces
that same subsystem.

Its exact 76-byte MM DEPEX requires, in order, the SMM CPU, dynamic
configuration, SMM Base2, and SMM Access2 protocols, followed by three `AND`
opcodes and `END`. This artifact dependency is authoritative over the source
metadata.

The native FV composition reproduces that wrapper exactly.
