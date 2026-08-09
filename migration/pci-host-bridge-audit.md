# Native PCI host bridge audit

The admitted `PciHostBridgeDxe` file is GUID
`128fb770-5e79-4176-9e51-9bb268a17dd1`, offset `0x2a4108`, size
`0x1108e`, file type `0x07`, in the exact retained FV at DevicePath head
`366f2e7f810e5d7ac8eb4e89b4c325f2f8f247f2`.

Its `0x3a`-byte DXE DEPEX section requires, in order, CPU I/O2 protocol
`ad61f191-ae5f-4c0e-b9fa-e869d288c64f`, CPU Architecture protocol
`26baccb1-6f42-11d4-bce7-0080c73c8881`, and EFI PCD protocol
`13a3f0f6-264a-3ef0-f2e0-dec512342f34`, combined by two AND opcodes and
terminated by END. The executable section begins at file-relative `0x54`; the
UI and version sections retain `PciHostBridgeDxe` and `1.0`.

The first inventory-neutral slice validates and imports the exact Universal
Payload PCI Root Bridges HOB consumed by the stable driver. It preserves every
bridge aperture and policy field while rejecting truncated arrays, invalid bus
windows, and malformed boolean fields. It deliberately does not yet publish a
host-bridge or root-bridge-I/O protocol, so the retained inventory remains
unchanged until the allocation state machine and CPU I/O-backed protocol ABI
are complete.

The second inventory-neutral slice adds the restart/resource-submission model,
alignment-ordered aperture allocation checks, a concrete DXE entry that imports
the handoff from the configuration-table HOB list, and publication of the first
three exact Host Bridge Resource Allocation protocol methods. The standalone
package preserves GUID, `0x1108e` envelope, UI/version strings, file type, and
the admitted DEPEX byte-for-byte.

The subsequent inventory-neutral slices implement the ACPI resource methods,
GCD allocation and rollback, and a real handle for every root. Each root handle
publishes an ACPI HID DevicePath and `EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL` together.
Memory and I/O operations are CPU I/O2-backed; PCI configuration follows the
admitted range below. DMA delegates to the optional IOMMU protocol and otherwise
uses identity mappings or stable-compatible below-4-GiB bounce mappings with
directional copies. Root publication is atomic: failure removes previously
installed roots in reverse order and then removes the host protocol. The
stable202302 host-bridge DXE is not a Driver Binding driver and has no Stop or
Unload lifecycle; therefore no unsupported teardown protocol is advertised.
No FV replacement or inventory wiring is provided by this lane.

## Admitted PCI configuration range

The retained dependency envelope has no PCI-segment protocol and the Universal
Payload root-bridge record has no per-segment ECAM base.  Consequently the
native driver admits only segment zero.  A root marked `no_extended_config`
uses CPU I/O2 CF8/CFC cycles for its conventional 256-byte configuration space.
A root permitting extended configuration requires the generated native PCD
named `PcdPciExpressBaseAddress` (the token-space-qualified form is accepted)
to contain a nonzero 64-bit segment-zero ECAM base.  Entry prevalidates every
root and returns `EFI_UNSUPPORTED` before publishing anything if a nonzero
segment or an extended-config root without that PCD is present.  This preserves
the exact admitted DEPEX instead of silently advertising inaccessible PCI
configuration space.
