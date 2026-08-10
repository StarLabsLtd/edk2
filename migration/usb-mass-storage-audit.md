# Native USB mass-storage admission

The native replacement occupies GUID `9fb4b4a7-42c0-4bcd-8540-9bcc6711f83e`
at FV offset `0x3e3ab8`, exact size `0x9052`, type `0x07`, with PE32
`0x9004`, UI `UsbMassStorageDxe`, version `1.0`, and no DEPEX.

It consumes native USB I/O, executes bulk-only transport with reset recovery,
discovers logical units and capacity, and publishes Block I/O children with
transactional parent/child ownership.
