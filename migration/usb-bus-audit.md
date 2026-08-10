# Native USB Bus admission

The native replacement occupies the retained USB Bus envelope at FV offset
`0x3cda28`, GUID `240612b7-a063-11d4-9a3a-0090273fc14d`, size `0xd042`,
type `0x07`, with PE32 `0xd004`, UI `UsbBusDxe`, version `1.0`, and no DEPEX.

It consumes the native USB2 Host Controller protocol, enumerates configured
root-port interfaces, publishes exact USB I/O and appended USB DevicePath
children, and owns parent/child opens transactionally.
