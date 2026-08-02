#!/usr/bin/env python3
## SPDX-License-Identifier: BSD-2-Clause-Patent

"""Host tests for cdk2 EDK II backend make-time validation."""

from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


CDK2_DIR = Path(__file__).resolve().parent
GOOD_GUID = "11111111-2222-3333-4444-555555555555"
ENTRY_GUID = "2119BBD7-9432-4F47-B5E2-5C4EA31B6BDC"
APRIORI_GUID = "FC510EE7-FFDC-11D4-BD41-0080C73C8881"
PAD_GUID = "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
LOW_BATTERY_LOGO_GUID = "BE6E1243-682C-4186-8151-448D48AFE341"
UNEXPECTED_GUID = "99999999-8888-7777-6666-555555555555"
GOOD_MODULE = "Pkg/GoodDxe.inf"
FMP_DXE_MODULE = "FmpDevicePkg/FmpDxe/FmpDxe.inf"
CAPSULE_GUID = "22222222-3333-4444-5555-666666666666"
OVERRIDE_CAPSULE_GUID = "33333333-4444-5555-6666-777777777777"


class Edk2BackendDiscoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, relpath: str, text: str) -> Path:
        path = self.workspace / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def _write_ffs(self, guid: str) -> None:
        path = (
            self.workspace
            / "root/out/RELEASE_TEST/FV/Ffs"
            / f"{guid}Fixture"
            / f"{guid}.ffs"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture")

    def _run_discover(self, dxe_fv_guids: list[str]) -> subprocess.CompletedProcess[str]:
        root = self.workspace / "root"
        build = self.workspace / "build"
        fv_text = root / "out/RELEASE_TEST/FV/DXEFV.Fv.txt"
        module_guids = build / "cdk2-module-guids.txt"

        self._write(
            str(module_guids.relative_to(self.workspace)),
            f"{GOOD_GUID} {GOOD_MODULE}\n"
            f"{ENTRY_GUID} UefiPayloadPkg/cdk2/backend/edk2/entry/UefiPayloadEntry.inf\n",
        )
        self._write(
            str(fv_text.relative_to(self.workspace)),
            "\n".join(
                ["EFI_FV_TOTAL_SIZE = 0x1000", "EFI_FV_TAKEN_SIZE = 0x400"]
                + [
                    f"0x{index * 0x40 + 0x78:08X} {guid}"
                    for index, guid in enumerate(dxe_fv_guids)
                ]
            )
            + "\n",
        )

        for guid in dxe_fv_guids:
            self._write_ffs(guid)

        makefile = self._write(
            "Makefile",
            textwrap.dedent(
                f"""\
                SHELL := /bin/bash
                override CDK2_ROOT := {root}
                override CDK2_DIR := {CDK2_DIR}
                override CDK2_BUILD_DIR := {build}
                override CDK2_TARGET := RELEASE
                override CDK2_BACKEND_TOOLCHAIN := TEST
                override CDK2_BACKEND_OUTPUT_DIRECTORY := out
                include $(CDK2_DIR)/edk2-backend.mk
                CDK2_SELECTED_MODULES := {GOOD_MODULE} $(CDK2_BACKEND_ENTRY_MODULE)

                .PHONY: discover
                discover:
                \t$(CDK2_BACKEND_DISCOVER)
                """
            ),
        )

        return subprocess.run(
            ["make", "--no-print-directory", "-f", str(makefile), "discover"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _run_manifest(
        self,
        *,
        capsule: bool,
        capsule_guid: str = CAPSULE_GUID,
        extra_defines: str = "",
    ) -> subprocess.CompletedProcess[str]:
        root = self.workspace / "root"
        build = self.workspace / "build"
        config = build / ".config"

        self._write(
            str(config.relative_to(self.workspace)),
            "CONFIG_CDK2_PAYLOAD=y\n",
        )
        makefile = self._write(
            "Makefile",
            textwrap.dedent(
                f"""\
                SHELL := /bin/bash
                CONFIG_CDK2_CAPSULE := {"y" if capsule else "n"}
                CONFIG_CDK2_CAPSULE_MAIN_FW_GUID := "{capsule_guid}"
                CDK2_ROOT := {root}
                CDK2_DIR := {CDK2_DIR}
                CDK2_BUILD_DIR := {build}
                CDK2_CONFIG := {config}
                CDK2_MANIFEST := $(CDK2_BUILD_DIR)/cdk2-modules.txt
                CDK2_EXTRA_DEFINES := {extra_defines}
                include $(CDK2_DIR)/edk2-backend.mk
                CDK2_SELECTED_MODULES := {GOOD_MODULE} {FMP_DXE_MODULE}

                $(CDK2_MANIFEST): $(CDK2_BACKEND_INPUTS)
                \t$(CDK2_BACKEND_WRITE_MANIFEST)

                .PHONY: manifest
                manifest: $(CDK2_MANIFEST)
                """
            ),
        )

        return subprocess.run(
            ["make", "--no-print-directory", "-f", str(makefile), "manifest"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_discover_accepts_cdk2_owned_non_module_dxe_guids(self) -> None:
        result = self._run_discover(
            [APRIORI_GUID, ENTRY_GUID, GOOD_GUID, LOW_BATTERY_LOGO_GUID, PAD_GUID]
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        ffs_list = self.workspace / "build/cdk2-dxe-ffs.txt"
        packed_ffs = ffs_list.read_text(encoding="utf-8")
        self.assertEqual(len(packed_ffs.splitlines()), 3)
        self.assertNotIn(ENTRY_GUID, packed_ffs)
        self.assertNotIn(PAD_GUID, packed_ffs)

    def test_discover_rejects_unexpected_extra_dxe_guid(self) -> None:
        result = self._run_discover(
            [APRIORI_GUID, GOOD_GUID, LOW_BATTERY_LOGO_GUID, UNEXPECTED_GUID]
        )

        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn(
            f"unexpected DXE FV GUID selected for cdk2 packing: {UNEXPECTED_GUID}",
            output,
        )
        self.assertIn(
            "cdk2 EDK2 DXE FV contains GUIDs outside the cdk2 selected map",
            output,
        )

    def test_manifest_records_capsule_fmp_guid_override(self) -> None:
        result = self._run_manifest(capsule=True)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = (self.workspace / "build/cdk2-modules.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"{FMP_DXE_MODULE} FILE_GUID={CAPSULE_GUID}\n", manifest)

    def test_manifest_keeps_normal_fmp_module_unannotated(self) -> None:
        result = self._run_manifest(capsule=False)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest_lines = (
            self.workspace / "build/cdk2-modules.txt"
        ).read_text(encoding="utf-8").splitlines()
        self.assertIn(FMP_DXE_MODULE, manifest_lines)
        self.assertNotIn(f"{FMP_DXE_MODULE} FILE_GUID={CAPSULE_GUID}", manifest_lines)

    def test_manifest_uses_capsule_extra_define_override(self) -> None:
        result = self._run_manifest(
            capsule=True,
            extra_defines=f"-D CAPSULE_MAIN_FW_GUID={OVERRIDE_CAPSULE_GUID}",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = (self.workspace / "build/cdk2-modules.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f"{FMP_DXE_MODULE} FILE_GUID={OVERRIDE_CAPSULE_GUID}\n",
            manifest,
        )
        self.assertNotIn(f"{FMP_DXE_MODULE} FILE_GUID={CAPSULE_GUID}\n", manifest)

    def test_manifest_uses_capsule_define_equals_override(self) -> None:
        result = self._run_manifest(
            capsule=True,
            extra_defines=f"--define=CAPSULE_MAIN_FW_GUID={OVERRIDE_CAPSULE_GUID}",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = (self.workspace / "build/cdk2-modules.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f"{FMP_DXE_MODULE} FILE_GUID={OVERRIDE_CAPSULE_GUID}\n",
            manifest,
        )
        self.assertNotIn(f"{FMP_DXE_MODULE} FILE_GUID={CAPSULE_GUID}\n", manifest)

    def test_manifest_uses_quoted_capsule_define_override(self) -> None:
        result = self._run_manifest(
            capsule=True,
            extra_defines=f'-D "CAPSULE_MAIN_FW_GUID={OVERRIDE_CAPSULE_GUID}"',
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = (self.workspace / "build/cdk2-modules.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f"{FMP_DXE_MODULE} FILE_GUID={OVERRIDE_CAPSULE_GUID}\n",
            manifest,
        )
        self.assertNotIn(f"{FMP_DXE_MODULE} FILE_GUID={CAPSULE_GUID}\n", manifest)

    def test_manifest_rebuilds_when_capsule_extra_define_changes(self) -> None:
        first_guid = "44444444-5555-6666-7777-888888888888"
        second_guid = "55555555-6666-7777-8888-999999999999"
        result = self._run_manifest(
            capsule=True,
            extra_defines=f"-D CAPSULE_MAIN_FW_GUID={first_guid}",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        makefile = self.workspace / "Makefile"
        result = subprocess.run(
            [
                "make",
                "--no-print-directory",
                "-f",
                str(makefile),
                "manifest",
                f"CDK2_EXTRA_DEFINES=-D CAPSULE_MAIN_FW_GUID={second_guid}",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        manifest = (self.workspace / "build/cdk2-modules.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"{FMP_DXE_MODULE} FILE_GUID={second_guid}\n", manifest)
        self.assertNotIn(f"{FMP_DXE_MODULE} FILE_GUID={first_guid}\n", manifest)


class Edk2BackendPs2KeyboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _run_inspect(
        self, config: str, *, extra_defines: str = ""
    ) -> subprocess.CompletedProcess[str]:
        makefile = self.workspace / "Makefile"
        makefile.write_text(
            "\n".join(
                [
                    "SHELL := /bin/bash",
                    f"override CDK2_ROOT := {CDK2_DIR.parents[1]}",
                    f"override CDK2_DIR := {CDK2_DIR}",
                    f"override CDK2_BUILD_DIR := {self.workspace / 'build'}",
                    f"CDK2_EXTRA_DEFINES := {extra_defines}",
                    "CONFIG_CDK2_PAYLOAD := y",
                    "CONFIG_CDK2_CONSOLE := y",
                    "CONFIG_CDK2_BOOT_TIMEOUT := 0",
                    *config.splitlines(),
                    "include $(CDK2_DIR)/edk2-backend.mk",
                    "",
                    ".PHONY: inspect",
                    "inspect:",
                    "\t@printf '%s\\n' 'MODULES'",
                    "\t@printf '%s\\n' $(CDK2_SELECTED_MODULES)",
                    "\t@printf '%s\\n' 'DEFINES'",
                    "\t@printf '%s\\n' '$(CDK2_DEFINES)'",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        return subprocess.run(
            ["make", "--no-print-directory", "-f", str(makefile), "inspect"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_ps2_keyboard_disabled_keeps_keyboard_and_sio_bus_out(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_SIO_BUS := n",
                    "CONFIG_CDK2_PS2_KEYBOARD := n",
                    "CONFIG_CDK2_PS2_MOUSE := n",
                ]
            )
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("OvmfPkg/SioBusDxe/SioBusDxe.inf", result.stdout)
        self.assertNotIn(
            "MdeModulePkg/Bus/Isa/Ps2KeyboardDxe/Ps2KeyboardDxe.inf",
            result.stdout,
        )
        self.assertIn("-D SIO_BUS_ENABLE=FALSE", result.stdout)
        self.assertIn("-D PS2_KEYBOARD_ENABLE=FALSE", result.stdout)

    def test_ps2_keyboard_enabled_implies_sio_bus_path(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_SIO_BUS := n",
                    "CONFIG_CDK2_PS2_KEYBOARD := y",
                    "CONFIG_CDK2_PS2_MOUSE := n",
                ]
            )
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OvmfPkg/SioBusDxe/SioBusDxe.inf", result.stdout)
        self.assertIn(
            "MdeModulePkg/Bus/Isa/Ps2KeyboardDxe/Ps2KeyboardDxe.inf",
            result.stdout,
        )
        self.assertIn("-D SIO_BUS_ENABLE=TRUE", result.stdout)
        self.assertIn("-D PS2_KEYBOARD_ENABLE=TRUE", result.stdout)

    def test_extra_defines_drive_selected_module_set(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_TPM12 := y",
                    "CONFIG_CDK2_TPM2 := y",
                    "CONFIG_CDK2_TPM_CONFIG := y",
                    "CONFIG_CDK2_SECURE_BOOT := n",
                    "CONFIG_CDK2_SECURE_BOOT_CONFIG := n",
                ]
            ),
            extra_defines="-D MEMORY_TEST=NONE -D TPM1_ENABLE=FALSE "
            "-D SECURE_BOOT_ENABLE=TRUE -D OPAL_PASSWORD_ENABLE=TRUE",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(
            "MdeModulePkg/Universal/MemoryTest/NullMemoryTestDxe/NullMemoryTestDxe.inf",
            result.stdout,
        )
        self.assertNotIn("SecurityPkg/Tcg/TcgDxe/TcgDxe.inf", result.stdout)
        self.assertNotIn("SecurityPkg/Tcg/TcgConfigDxe/TcgConfigDxe.inf", result.stdout)
        self.assertIn("SecurityPkg/Tcg/Tcg2Dxe/Tcg2Dxe.inf", result.stdout)
        self.assertIn("SecurityPkg/Tcg/Tcg2Config/Tcg2ConfigDxe.inf", result.stdout)
        self.assertIn("UefiPayloadPkg/EnrollDefaultKeys/EnrollDefaultKeys.inf", result.stdout)
        self.assertIn("SecurityPkg/Tcg/Opal/OpalPassword/OpalPasswordDxe.inf", result.stdout)
        self.assertIn("-D MEMORY_TEST=NONE", result.stdout)
        self.assertIn("-D TPM1_ENABLE=FALSE", result.stdout)
        self.assertIn("-D SECURE_BOOT_ENABLE=TRUE", result.stdout)



class Edk2BackendCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, relpath: str, text: str) -> Path:
        path = self.workspace / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def _run_check(self, *, secure_boot: bool) -> subprocess.CompletedProcess[str]:
        root = self.workspace / "root"
        build = self.workspace / "build"
        config = self._write("build/.config", "CONFIG_CDK2_PAYLOAD=y\n")
        self._write(f"root/{GOOD_MODULE}", "")
        self._write("root/UefiPayloadPkg/UefiPayloadPkg.dsc", f"{GOOD_MODULE}\n")

        makefile = self._write(
            "Makefile",
            textwrap.dedent(
                f"""\
                SHELL := /bin/bash
                CONFIG_CDK2_CAPSULE := n
                CONFIG_CDK2_SECURE_BOOT := {"y" if secure_boot else "n"}
                CDK2_ROOT := {root}
                CDK2_DIR := {CDK2_DIR}
                CDK2_BUILD_DIR := {build}
                CDK2_CONFIG := {config}
                include $(CDK2_DIR)/edk2-backend.mk
                CDK2_RETAINED_MODULES :=
                CDK2_PAYLOAD_LIBRARIES :=
                CDK2_SELECTED_MODULES := {GOOD_MODULE}

                .PHONY: check
                check:
                \t$(CDK2_BACKEND_CHECK)
                """
            ),
        )

        return subprocess.run(
            ["make", "--no-print-directory", "-f", str(makefile), "check"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_secure_boot_check_warns_when_object_submodule_is_missing(self) -> None:
        result = self._run_check(secure_boot=True)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "WARNING: Microsoft secure-boot objects submodule is missing",
            result.stderr,
        )

    def test_secure_boot_check_is_skipped_when_secure_boot_is_disabled(self) -> None:
        result = self._run_check(secure_boot=False)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("secure-boot objects", result.stderr)

if __name__ == "__main__":
    unittest.main()
