# Native Console Splitter admission

The native console splitter replaces retained `ConSplitterDxe` at GUID
`408edcec-cf6d-477c-a5a8-b4844e3de281`, FV offset `0x2cf2d8`, using the exact
`0xb04e` type-7 envelope. Its only sections are PE32, UI `ConSplitterDxe`, and
version `1.0`; it intentionally has no DEPEX.

The implementation owns five physical DriverBinding relationships and publishes
virtual text input, extended input, relative/absolute pointer, text output, and
GOP aggregation protocols. Start and Stop update aggregate state transactionally;
pointer resets fan out to physical devices, ComponentName languages are exact,
and the SystemTable console handles, pointers, and header CRC are updated together.

Executable fixtures cover aggregation, hot removal, wait-event forwarding,
physical ownership rollback, exact protocol languages and ABI calls, GOP mode
intersection, the full package envelope, and header dependency rebuilds.
