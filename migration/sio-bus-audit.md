# Native SIO bus admission

The native driver replaces the retained `SioBusDxe` envelope at `0x2bb1f8`
without moving adjacent firmware files.  It owns the ISA bridge through PCI I/O,
publishes the three fixed ACPI resource children transactionally, restores PCI
attributes on rollback and Stop, and emits the admitted package exactly: GUID
`864e1ca8-85eb-4d63-9dcc-6e0fc90ffd55`, size `0x6042`, PE32/UI/version only,
with no DEPEX.

Host fixtures cover supported bridge discovery, fixed resource rejection,
multi-child publication, ownership reversal, injected Start failures, exact
entry ABI calls, and the complete package envelope.
