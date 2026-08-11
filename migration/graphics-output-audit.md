# Native graphics-output admission

The native driver validates the Universal Payload framebuffer handoff, exposes
the GOP mode and BLT surface transactionally, and preserves PCI attributes and
child ownership on failure and Stop.  Missing or malformed framebuffer HOBs
fail closed.

The exact retained slot at `0x2ee3c8` keeps GUID
`0b04b2ed-861c-42cd-a22f-c3aafaccb896`, size `0x9052`, PE32/UI/version only,
and no DEPEX.
