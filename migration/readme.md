# Retained firmware-volume migration

This directory records the modules still supplied by the temporary external
firmware volume. It is migration evidence, not a build input. The production
build must reach zero retained modules before the external FV interface can be
removed.

`retained-fv.tsv` is tied to SHA-256
`ca1ebfd0ff6c7c82935a4302c1ddc4cc418ed177756c678260dfb09527e1f50e`.
The module names were recovered from the debug paths embedded in that exact
FV. Every listed module must be replaced by native source or deliberately
removed; an opaque replacement binary does not count as migration.

The table is sorted by module path. Its status column accepts:

- `retain`: still supplied by the external FV;
- `native`: replaced by source built in this repository;
- `remove`: proven unnecessary and removed from the image.

`make retained-fv-check` rejects malformed entries, duplicate paths, an
increase above the admitted baseline, or a mismatch between the declared and
actual retained counts.

Removal decisions and their QEMU evidence are recorded in
`obsolete-modules.md`. `cdk2-fvpack --prune-dxe-fv` creates deterministic test
candidates by replacing selected FFS GUIDs with same-size pad files. This keeps
the remaining binary layout stable while proving that a module is unnecessary.

`retained-readiness.tsv` classifies every remaining opaque module and is
checked against this inventory by `make retained-fv-check`. See
`hardware-readiness.md` for the closure and hardware handoff criteria.

Build the native inventory tool and inspect an FV without EDK2 or BaseTools:

```
make native-fvinfo
build/cdk2/native/cdk2-fvinfo path/to/payload.fv
```

The tab-separated output records each top-level FFS GUID, byte offset, byte
size, file type, and its UI section name when present. The parser rejects
truncated or inconsistent FV, FFS, extended-size, and section boundaries.

## Deferred platform inputs

`LocalApicTimerDxe` cannot be replaced safely until the coreboot handoff gives
the payload an explicit local-APIC timer frequency. The retained driver obtains
`PcdFSBClock` dynamically; substituting a QEMU-specific constant would make
firmware event timing silently platform-dependent. Its admitted FFS is GUID
`52fe8196-f9de-4d07-b22f-51f77a0e7c41`, offset `0x80880`, size `0x607a`, and
has a CPU-architecture plus PCD-protocol DEPEX.
