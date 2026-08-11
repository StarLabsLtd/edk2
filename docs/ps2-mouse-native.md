# Native PS/2 mouse boundary

The admitted `Ps2MouseDxe` file is
`08464531-4c99-4c4c-a887-8d8ba4bbb063` at FV offset `0x2c1240`. It is a DXE
driver (`0x07`) with a fixed `0x7046` byte envelope and no DEPEX. Its PE32
section starts at file offset `0x18`, and its image starts at `0x1c`.

The native driver accepts the standard PNP0F03/PNP0F13 mouse paths and UID 1
of PNP0303. It owns SIO by-driver, performs bounded 8042 self-test and AUX
negotiation with ACK/RESEND handling, publishes SimplePointer, and polls using
a periodic event. Packet framing resynchronizes on bit 3 and supports signed
motion, overflow saturation, buttons, and four-byte wheel packets. Every start
failure and stop releases timers, events, controller state, and SIO ownership
in reverse order.

`native-ps2-mouse-package` emits the admitted GUID, type, size, no-DEPEX
ordering, and subsystem 11 without changing retained inventory.
