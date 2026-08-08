# Native PCH software-SMI dispatcher

The admitted FFS is GUID `60f343e3-2ae2-4aa7-b01e-bf9bd5c04a3b`, offset
`0x000f5f30`, size `0x0000509e`, and type `0x0a`.

Its exact 76-byte MM DEPEX requires, in order, the SMM CPU, PI PCD, SMM Base2,
and SMM Access2 protocols, followed by three `AND` opcodes and `END`. This is
the artifact dependency and is authoritative over the source INF.

This source layer deliberately does not change the retained inventory or FV
composition. The final integration must reproduce that wrapper exactly.
