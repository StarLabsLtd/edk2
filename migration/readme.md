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
