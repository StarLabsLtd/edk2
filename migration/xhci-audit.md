# Native XHCI admission

The native replacement occupies the retained XHCI envelope at FV offset
`0x3bc9e8`: GUID `b7f50e91-a759-412c-ade4-dcd03e7f7c28`, FFS size
`0x1103e`, type `0x07`, PE32 section `0x11004`, UI `XhciDxe`, version
`1.0`, and no DEPEX section.

The implementation owns PCI decode and DMA mappings, controller and event
rings, root-port state, device slots and contexts, and the USB2 Host Controller
protocol. Exact package and predecessor byte-comparison gates protect the
admitted envelope.
