# cdk2 native payload work

This tree is the native cdk2 source boundary intended to be movable into
coreboot-style directories. The active build is Kconfig-driven and uses C,
assembly, linker scripts, and host utilities only.

The native build currently covers:

- coreboot table parsing
- UPL HOB construction helpers
- PE/COFF and FV validation helpers
- x86 entry/linker output
- host tests for the native parser, services, PE, FV, module table, and ELF
  layout checks

The active build deliberately does not produce a bootable payload image. The
retained UEFI payload modules still need to be ported to native C/Make/Kconfig
before image production can be re-enabled without relying on external package
metadata or a prebuilt firmware volume.

Useful targets:

```text
make olddefconfig
make lint-stable
make lint
make check
make native-check
make native-stage
make native-coreboot-stage
make manifest
make what-jenkins-does
```

`make build-image` exits with an error until the retained payload modules are
native sources in this tree.

`make what-jenkins-does` is the current cdk2 analogue of the coreboot Jenkins
path: it runs the copied coreboot lint harness, native checks, source manifest
generation, and verifies that image production still fails closed at the native
source boundary.
