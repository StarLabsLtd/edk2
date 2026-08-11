# Native PS/2 mouse admission

The native driver replaces the retained `Ps2MouseDxe` file at `0x2c1240`.
It binds the ACPI auxiliary-controller child published by native SioBus,
initializes and polls the 8042 auxiliary channel, publishes Simple Pointer, and
reverses timer/event/protocol ownership on failure and Stop.

The package preserves GUID `08464531-4c99-4c4c-a887-8d8ba4bbb063`, envelope
`0x7046`, PE32/UI/version sections, and the admitted absence of DEPEX.
