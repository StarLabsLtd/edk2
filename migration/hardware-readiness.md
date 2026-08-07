# Hardware-readiness boundary

The SMBIOS migration head is suitable for host tests, controlled QEMU
experiments, and transition-carrier hardware smoke testing after final coreboot
integration. It is **not ready for hardware validation as a complete native
cdk2 payload**. Of the admitted baseline's 72 modules, 12 are source-built here,
two were removed with QEMU evidence, and 58 are still opaque files supplied by
the transition firmware volume. Consequently, `make build-image` deliberately
fails and `coreboot-stage` emits only the transition stage.

`retained-readiness.tsv` classifies every remaining opaque module exactly once:

- `intentional-dependency`: retained binaries currently consume its protocol;
  removal is known to stop the payload or requires coordinated consumers;
- `hardware-gated`: correctness depends on chipset, controller, interrupt,
  timer, SMM, TPM, or other platform behaviour that QEMU cannot close out;
- `subsystem-sized`: it belongs to a coupled boot, console, storage, update, UI,
  or variable-services migration and should not be treated as a leaf port;
- `unsafe-standalone`: it is a core dispatcher, execution environment, or
  handoff component whose replacement changes the payload architecture.

These are migration-planning classes, not claims that the retained files are
native. The integrated transition carrier may be smoke-tested on hardware to
validate the coreboot handoff and expose platform gaps. Complete native-payload
hardware validation begins only after all `retain` entries reach `native` or
`remove`, `build-image` succeeds from repository source, and coreboot consumes
that artifact without an external FV input.

## Evidence required before that handoff

Each migration change must pass the repository's host tests and native image
checks. Its committed candidate and an unchanged control must then boot through
the same coreboot/QEMU path, reach the UEFI shell, complete `startup.nsh`, emit
`CDK2_NATIVE_DONE`, and shut down. The candidate must be proven to contain the
newly built FFS bytes; a successful baseline carrier is not candidate evidence.

QEMU is a regression gate, not hardware evidence. Transition-carrier smoke
testing should first establish entry, console output, shell completion, and a
controlled shutdown without claiming native closure. After native closure, the
complete-payload campaign must separately exercise storage and USB controllers,
console and graphics, reset and RTC runtime paths, ACPI and SMBIOS publication,
TPM measurement, variable persistence, and SMM-backed services on each target
board. No hardware execution is claimed by this repository state.

The source-owned tree is independently guarded by
`lint-stable-025-native-boundary`: package build metadata, Python sources,
legacy package names, and package-style include paths are rejected. Historical
module paths are permitted only in the migration evidence directory and are
never build inputs.
