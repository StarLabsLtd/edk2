# Native USB mouse audit

The native driver replaces retained `UsbMouseDxe` at `0x3ecb10`, GUID
`2d2e62aa-9ecf-43b7-8219-94e7fc713dfe`, using the exact `0x7046` envelope.

It validates HID boot-mouse interfaces, parses bounded HID report descriptors,
owns asynchronous interrupt and recovery-event lifecycles, accumulates signed
relative movement and button state, and publishes the canonical Simple Pointer
protocol through transactional DriverBinding Start, Stop, and Unload paths.

The exact package contains PE32, `UsbMouseDxe` UI, and version `1.0` sections
with no DEPEX.
