# Native terminal driver boundary

The admitted `TerminalDxe` file is
`9e863906-a40f-4875-977f-5b93ff237fc6` at FV offset `0x2e3380`. It is a DXE
driver (`0x07`) with an `0xb046` byte FFS envelope and no DEPEX. Its PE32
section starts at file offset `0x18`, with the image at `0x1c`.

The native driver binds Serial I/O controllers and publishes a child device
path plus Simple Text Input, Simple Text Input Ex, and Simple Text Output. The
four standard terminal vendor GUIDs cover PC ANSI, VT100, VT100+, and VT-UTF8.
Wait events poll Serial I/O into a bounded decoder; stop and every failed start
release events, child publications, child opens, and parent ownership in
reverse order.

`native-terminal-package` emits the admitted GUID, file type, size, no-DEPEX
section ordering, and subsystem 11 without modifying the retained FV or native
inventory.
