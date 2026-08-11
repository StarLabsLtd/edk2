# Native USB keyboard audit

The native driver replaces retained `UsbKbDxe` at `0x3daa70` using GUID
`2d2e62cf-9ecf-43b7-8219-94e7fc713dfe` and the exact `0x9042` envelope.

The implementation validates HID boot-keyboard interfaces, owns protocol and
interrupt-transfer lifecycles transactionally, decodes boot reports into EFI
scan/Unicode keys, publishes shared Simple Text Input and Extended Input state,
supports WaitForKey events, toggle state, and bounded key notifications.

The package contains PE32, `UsbKbDxe` UI, and version `1.0` sections with no
DEPEX. Focused host fixtures cover report transitions, modifiers/toggles,
transport tuples, protocol ABI, notifications, controller rollback, and entry
offsets.
