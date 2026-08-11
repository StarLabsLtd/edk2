# Native SMMSTORE FVB admission

The native runtime driver validates the SMMSTORE HOB, provides bounded raw
transport, formats and verifies authenticated variable stores, publishes FVB,
and converts runtime pointers on virtual-address change.  Failure paths reverse
protocol and event ownership.

The retained slot at `0xfafd0` keeps GUID
`a0402fca-6b25-4cea-b7dd-c08f99714b29`, size `0x8072`, exact DEPEX,
PE32/UI/version sections, and adjacent bytes.
