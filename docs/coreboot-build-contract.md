# coreboot build contract

cdk2 is built as an external coreboot payload. coreboot owns board policy,
the resolved Kconfig file, the toolchain, and the outer build directory. cdk2
owns its source selection, compilation, linking, validation, and final payload
artifact.

The integration entry point is:

```text
make coreboot-stage \
  COREBOOT_CONFIG=/path/to/coreboot/build/.config \
  COREBOOT_OUTPUT_DIR=/path/to/coreboot/build/cdk2 \
  HOSTCC=... CC=... OBJCOPY=... NM=...
```

The current transition target emits
`COREBOOT_OUTPUT_DIR/native/cdk2-coreboot-stage.elf`. It deliberately does not
claim to be the complete payload while retained firmware-volume modules remain.
The same interface will emit the final payload once the retained-module count
reaches zero.

## Ownership

coreboot supplies:

- a resolved configuration containing the `CONFIG_CDK2_*` namespace;
- host and target toolchain commands;
- an output directory outside the cdk2 source tree;
- the coreboot table pointer at runtime.

cdk2 copies only `CONFIG_CDK2_*` values into its private output configuration.
It never modifies coreboot's resolved `.config`.

cdk2 supplies:

- all payload source and private headers;
- generated cdk2 configuration headers under its output directory;
- the native entry point and linker script;
- host validation tools and tests;
- a deterministic payload artifact.

The integration must not copy generated files into the source tree, invoke an
external package build, or accept a prebuilt payload module as native closure.

## Stable interface

`COREBOOT_CONFIG` and `COREBOOT_OUTPUT_DIR` are the only required integration
paths. Optional compiler overrides use the conventional `HOSTCC`, `CC`,
`OBJCOPY`, and `NM` variables. Internal `CDK2_*` variables are not part of the
coreboot wrapper contract.
