#!/usr/bin/env python3
## SPDX-License-Identifier: BSD-2-Clause-Patent

"""Host tests for cdk2 EDK II backend make-time validation."""

from __future__ import annotations

import subprocess
import tempfile
import textwrap
import time
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


class Edk2BackendDscTests(unittest.TestCase):
    def test_cpu_timer_library_is_available_to_cdk2_flat_fv(self) -> None:
        dsc = (CDK2_DIR.parent / "UefiPayloadPkg.dsc").read_text(encoding="utf-8")
        condition = (
            "!if $(CPU_TIMER_LIB_ENABLE) == TRUE && "
            "($(UNIVERSAL_PAYLOAD) == TRUE || $(CDK2_FLAT_DXE_FV) == TRUE)"
        )

        self.assertIn(condition, dsc)
        self.assertIn(
            "TimerLib|UefiCpuPkg/Library/CpuTimerLib/BaseCpuTimerLib.inf",
            dsc,
        )


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

    def _write_ffs(self, guid: str, suffix: str = "Fixture") -> Path:
        path = (
            self.workspace
            / "root/out/RELEASE_TEST/FV/Ffs"
            / f"{guid}{suffix}"
            / f"{guid}.ffs"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture")
        return path

    def _run_discover(
        self,
        dxe_fv_guids: list[str],
        stale_ffs_guids: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        root = self.workspace / "root"
        build = self.workspace / "build"
        fv_text = root / "out/RELEASE_TEST/FV/DXEFV.Fv.txt"
        fv_inf = root / "out/RELEASE_TEST/FV/DXEFV.inf"
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

        ffs_paths = [self._write_ffs(guid) for guid in dxe_fv_guids]
        for guid in stale_ffs_guids or []:
            self._write_ffs(guid, suffix="Stale")
        self._write(
            str(fv_inf.relative_to(self.workspace)),
            "".join(f"EFI_FILE_NAME = {path}\n" for path in ffs_paths),
        )

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
                CONFIG_CDK2_ESRT := y
                CONFIG_CDK2_PCI := y
                CONFIG_CDK2_CONSOLE := y
                CONFIG_CDK2_GRAPHICS := y
                CONFIG_CDK2_SMM := y
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

    def _run_check_secure_boot(self) -> subprocess.CompletedProcess[str]:
        root = self.workspace / "root"
        build = self.workspace / "build"
        config = build / ".config"

        root.mkdir(parents=True, exist_ok=True)
        self._write(
            str(config.relative_to(self.workspace)),
            "CONFIG_CDK2_PAYLOAD=y\n",
        )
        makefile = self._write(
            "Makefile",
            textwrap.dedent(
                f"""\
                SHELL := /bin/bash
                CONFIG_CDK2_PAYLOAD := y
                CONFIG_CDK2_PCI := y
                CONFIG_CDK2_CONSOLE := y
                CONFIG_CDK2_GRAPHICS := y
                CONFIG_CDK2_SECURE_BOOT := y
                CONFIG_CDK2_BOOT_TIMEOUT := 0
                CDK2_ROOT := {root}
                CDK2_DIR := {CDK2_DIR}
                CDK2_BUILD_DIR := {build}
                CDK2_CONFIG := {config}
                include $(CDK2_DIR)/edk2-backend.mk
                CDK2_BACKEND_REQUIRED_SUBMODULES :=
                CDK2_BACKEND_REQUIRED_SUBMODULE_FILES :=
                CDK2_RETAINED_MODULES :=
                CDK2_SELECTED_MODULES :=
                CDK2_PAYLOAD_LIBRARIES :=

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

    def _run_check_missing_submodule_file(self) -> subprocess.CompletedProcess[str]:
        root = self.workspace / "root"
        build = self.workspace / "build"
        config = build / ".config"

        root.mkdir(parents=True, exist_ok=True)
        self._write(
            str(config.relative_to(self.workspace)),
            "CONFIG_CDK2_PAYLOAD=y\n",
        )
        makefile = self._write(
            "Makefile",
            textwrap.dedent(
                f"""\
                SHELL := /bin/bash
                PYTHON := python3
                CONFIG_CDK2_PAYLOAD := y
                CONFIG_CDK2_BOOT_TIMEOUT := 0
                CDK2_ROOT := {root}
                CDK2_DIR := {CDK2_DIR}
                CDK2_BUILD_DIR := {build}
                CDK2_CONFIG := {config}
                include $(CDK2_DIR)/edk2-backend.mk
                CDK2_BACKEND_REQUIRED_SUBMODULES :=
                CDK2_RETAINED_MODULES :=
                CDK2_SELECTED_MODULES :=
                CDK2_PAYLOAD_LIBRARIES :=

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

    def _run_check_lvgl(self) -> subprocess.CompletedProcess[str]:
        root = self.workspace / "root"
        build = self.workspace / "build"
        config = build / ".config"

        root.mkdir(parents=True, exist_ok=True)
        self._write(
            str(config.relative_to(self.workspace)),
            "CONFIG_CDK2_PAYLOAD=y\n",
        )
        makefile = self._write(
            "Makefile",
            textwrap.dedent(
                f"""\
                SHELL := /bin/bash
                CONFIG_CDK2_PAYLOAD := y
                CONFIG_CDK2_PCI := y
                CONFIG_CDK2_CONSOLE := y
                CONFIG_CDK2_GRAPHICS := y
                CONFIG_CDK2_USB := y
                CONFIG_CDK2_SETUP_UI := y
                CONFIG_CDK2_BOOT_TIMEOUT := 0
                CDK2_EXTRA_DEFINES := -D LVGL_ENABLE=TRUE
                CDK2_ROOT := {root}
                CDK2_DIR := {CDK2_DIR}
                CDK2_BUILD_DIR := {build}
                CDK2_CONFIG := {config}
                include $(CDK2_DIR)/edk2-backend.mk
                CDK2_BACKEND_REQUIRED_SUBMODULES :=
                CDK2_BACKEND_REQUIRED_SUBMODULE_FILES :=
                CDK2_RETAINED_MODULES :=
                CDK2_SELECTED_MODULES :=
                CDK2_PAYLOAD_LIBRARIES :=

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

    def _run_parallel_metadata_with_missing_lvgl(self) -> subprocess.CompletedProcess[str]:
        root = self.workspace / "root"
        build = self.workspace / "build"
        config = build / ".config"

        root.mkdir(parents=True, exist_ok=True)
        self._write(
            str(config.relative_to(self.workspace)),
            "CONFIG_CDK2_PAYLOAD=y\n",
        )
        makefile = self._write(
            "Makefile",
            textwrap.dedent(
                f"""\
                SHELL := /bin/bash
                CONFIG_CDK2_PAYLOAD := y
                CONFIG_CDK2_PCI := y
                CONFIG_CDK2_CONSOLE := y
                CONFIG_CDK2_GRAPHICS := y
                CONFIG_CDK2_USB := y
                CONFIG_CDK2_SETUP_UI := y
                CONFIG_CDK2_BOOT_TIMEOUT := 0
                CDK2_EXTRA_DEFINES := -D LVGL_ENABLE=TRUE
                CDK2_ROOT := {root}
                CDK2_DIR := {CDK2_DIR}
                CDK2_BUILD_DIR := {build}
                CDK2_CONFIG := {config}
                CDK2_MANIFEST := $(CDK2_BUILD_DIR)/cdk2-modules.txt
                include $(CDK2_DIR)/edk2-backend.mk
                CDK2_BACKEND_REQUIRED_SUBMODULES :=
                CDK2_BACKEND_REQUIRED_SUBMODULE_FILES :=
                CDK2_RETAINED_MODULES :=
                CDK2_PAYLOAD_LIBRARIES :=

                $(CDK2_MANIFEST): $(CDK2_BACKEND_MANIFEST_DEPS)
                \t$(CDK2_BACKEND_CHECK)
                \t$(CDK2_BACKEND_WRITE_MANIFEST)

                .PHONY: build
                build: $(CDK2_BACKEND_METADATA)
                """
            ),
        )

        return subprocess.run(
            ["make", "--no-print-directory", "-j8", "-f", str(makefile), "build"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _run_metadata_with_stale_missing_selected_module(
        self,
    ) -> subprocess.CompletedProcess[str]:
        root = self.workspace / "root"
        build = self.workspace / "build"
        config = build / ".config"
        manifest = build / "cdk2-modules.txt"
        metadata = build / "cdk2-module-metadata.json"

        root.mkdir(parents=True, exist_ok=True)
        self._write(
            str(config.relative_to(self.workspace)),
            "CONFIG_CDK2_PAYLOAD=y\n",
        )
        self._write(str(manifest.relative_to(self.workspace)), f"{GOOD_MODULE}\n")
        self._write(str(metadata.relative_to(self.workspace)), "{}\n")
        makefile = self._write(
            "Makefile",
            textwrap.dedent(
                f"""\
                SHELL := /bin/bash
                PYTHON := python3
                CONFIG_CDK2_PAYLOAD := y
                CONFIG_CDK2_BOOT_TIMEOUT := 0
                CDK2_ROOT := {root}
                CDK2_DIR := {CDK2_DIR}
                CDK2_BUILD_DIR := {build}
                CDK2_CONFIG := {config}
                CDK2_MANIFEST := {manifest}
                include $(CDK2_DIR)/edk2-backend.mk
                CDK2_BACKEND_REQUIRED_SUBMODULES :=
                CDK2_BACKEND_REQUIRED_SUBMODULE_FILES :=
                CDK2_RETAINED_MODULES :=
                CDK2_SELECTED_MODULES := {GOOD_MODULE}
                CDK2_PAYLOAD_LIBRARIES :=

                .PHONY: metadata
                metadata: $(CDK2_BACKEND_METADATA)
                """
            ),
        )

        return subprocess.run(
            ["make", "--no-print-directory", "-f", str(makefile), "metadata"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _run_noop_metadata(self):
        root = self.workspace / "root"
        build = self.workspace / "build"
        config = build / ".config"
        manifest = build / "cdk2-modules.txt"
        metadata = build / "cdk2-module-metadata.json"
        dsc = root / "UefiPayloadPkg/UefiPayloadPkg.dsc"

        self._write(
            str(root.joinpath(GOOD_MODULE).relative_to(self.workspace)),
            f"""\
[Defines]
  INF_VERSION = 1.30
  BASE_NAME = GoodDxe
  FILE_GUID = {GOOD_GUID}
  MODULE_TYPE = DXE_DRIVER
  ENTRY_POINT = GoodEntry

[Sources]
  Good.c
""",
        )
        self._write(str(dsc.relative_to(self.workspace)), f"{GOOD_MODULE}\n")
        self._write(
            str(config.relative_to(self.workspace)),
            "CONFIG_CDK2_PAYLOAD=y\n",
        )
        self._write(str(manifest.relative_to(self.workspace)), f"{GOOD_MODULE}\n")
        makefile = self._write(
            "Makefile",
            textwrap.dedent(
                f"""\
                SHELL := /bin/bash
                PYTHON := python3
                CONFIG_CDK2_PAYLOAD := y
                CONFIG_CDK2_BOOT_TIMEOUT := 0
                CDK2_ROOT := {root}
                CDK2_DIR := {CDK2_DIR}
                CDK2_BUILD_DIR := {build}
                CDK2_CONFIG := {config}
                CDK2_MANIFEST := {manifest}
                include $(CDK2_DIR)/edk2-backend.mk

                .PHONY: metadata
                metadata: $(CDK2_BACKEND_METADATA)
                """
            ),
        )
        command = [
            "make",
            "--no-print-directory",
            "-f",
            str(makefile),
            "metadata",
            f"CDK2_SELECTED_MODULES={GOOD_MODULE}",
            "CDK2_PAYLOAD_LIBRARIES=",
            "CDK2_RETAINED_MODULES=",
            "CDK2_BACKEND_REQUIRED_SUBMODULES=",
            "CDK2_BACKEND_REQUIRED_SUBMODULE_FILES=",
        ]
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            return result, None

        metadata_mtime = metadata.stat().st_mtime_ns
        time.sleep(1.1)

        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result, metadata_mtime

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

    def test_discover_ignores_stale_unreferenced_matching_guid_ffs(self) -> None:
        result = self._run_discover(
            [APRIORI_GUID, ENTRY_GUID, GOOD_GUID, LOW_BATTERY_LOGO_GUID, PAD_GUID],
            stale_ffs_guids=[GOOD_GUID],
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        packed_ffs = (self.workspace / "build/cdk2-dxe-ffs.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn(f"{GOOD_GUID}Fixture/{GOOD_GUID}.ffs", packed_ffs)
        self.assertNotIn(f"{GOOD_GUID}Stale/{GOOD_GUID}.ffs", packed_ffs)

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

    def test_check_rejects_missing_required_edk2_submodule_file(self) -> None:
        result = self._run_check_missing_submodule_file()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "missing required cdk2 EDK2 submodule file: "
            "CryptoPkg/Library/OpensslLib/openssl/crypto/aes/aes_core.c",
            result.stderr,
        )
        self.assertIn("git submodule update --init --checkout", result.stderr)

    def test_check_rejects_missing_lvgl_files_when_enabled(self) -> None:
        result = self._run_check_lvgl()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "missing LVGL module file: 3rdparty/LvglPkg/LvglPkg.dec",
            result.stderr,
        )
        self.assertIn(
            "git submodule update --init --checkout --recursive 3rdparty/LvglPkg",
            result.stderr,
        )

    def test_parallel_metadata_reports_missing_lvgl_guard(self) -> None:
        result = self._run_parallel_metadata_with_missing_lvgl()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "missing LVGL module file: 3rdparty/LvglPkg/LvglPkg.dec",
            result.stderr,
        )
        self.assertNotIn("No rule to make target", result.stderr)

    def test_metadata_rejects_stale_missing_selected_module(self) -> None:
        result = self._run_metadata_with_stale_missing_selected_module()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"missing selected backend module: {GOOD_MODULE}", result.stderr)

    def test_metadata_noop_preserves_output_mtime(self) -> None:
        result, metadata_mtime = self._run_noop_metadata()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIsNotNone(metadata_mtime)
        metadata = self.workspace / "build/cdk2-module-metadata.json"
        self.assertEqual(metadata_mtime, metadata.stat().st_mtime_ns)

    def test_check_rejects_missing_secure_boot_default_key_objects(self) -> None:
        result = self._run_check_secure_boot()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "missing Secure Boot default-key object: "
            "3rdparty/secureboot_objects/PostSignedObjects/DBX/amd64/DBXUpdate.bin",
            result.stderr,
        )
        self.assertIn(
            "git submodule update --init --checkout 3rdparty/secureboot_objects",
            result.stderr,
        )


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

    def test_setup_ui_disabled_keeps_browser_modules_out(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_SETUP_UI := n",
                ]
            )
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf", result.stdout)
        self.assertNotIn("UefiPayloadPkg/CfrSetupMenuDxe/CfrSetupMenuDxe.inf", result.stdout)
        self.assertNotIn("MdeModulePkg/Application/UiApp/UiApp.inf", result.stdout)
        self.assertNotIn(
            "MdeModulePkg/Application/BootManagerMenuApp/BootManagerMenuApp.inf",
            result.stdout,
        )
        self.assertNotIn(
            "MdeModulePkg/Universal/SetupBrowserDxe/SetupBrowserDxe.inf",
            result.stdout,
        )
        self.assertNotIn(
            "MdeModulePkg/Universal/PlatformDriOverrideDxe/PlatformDriOverrideDxe.inf",
            result.stdout,
        )
        self.assertNotIn(
            "UefiPayloadPkg/UserAuthPkg/UserAuthenticationDxe/UserAuthenticationDxe.inf",
            result.stdout,
        )
        self.assertNotIn(
            "MdeModulePkg/Universal/DisplayEngineDxe/DisplayEngineDxe.inf",
            result.stdout,
        )
        self.assertNotIn("3rdparty/LvglPkg/LvglSetupDxe/LvglSetupDxe.inf", result.stdout)
        self.assertIn("-D SETUP_UI_ENABLE=FALSE", result.stdout)

    def test_setup_ui_enabled_selects_browser_modules(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_SETUP_UI := y",
                ]
            )
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("UefiPayloadPkg/CfrSetupMenuDxe/CfrSetupMenuDxe.inf", result.stdout)
        self.assertIn("MdeModulePkg/Application/UiApp/UiApp.inf", result.stdout)
        self.assertIn(
            "MdeModulePkg/Universal/SetupBrowserDxe/SetupBrowserDxe.inf",
            result.stdout,
        )
        self.assertIn(
            "MdeModulePkg/Universal/PlatformDriOverrideDxe/PlatformDriOverrideDxe.inf",
            result.stdout,
        )
        self.assertIn(
            "MdeModulePkg/Universal/DisplayEngineDxe/DisplayEngineDxe.inf",
            result.stdout,
        )
        self.assertIn("-D SETUP_UI_ENABLE=TRUE", result.stdout)

    def test_lvgl_override_uses_compact_modules_without_setup_ui(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_GRAPHICS := y",
                    "CONFIG_CDK2_USB := y",
                    "CONFIG_CDK2_PS2_MOUSE := n",
                    "CONFIG_CDK2_SETUP_UI := n",
                ]
            ),
            extra_defines="-D LVGL_ENABLE=TRUE",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf", result.stdout)
        self.assertIn(
            "3rdparty/LvglPkg/LvglDisplayEngineDxe/LvglDisplayEngineDxe.inf",
            result.stdout,
        )
        self.assertIn("3rdparty/LvglPkg/LvglSetupDxe/LvglSetupDxe.inf", result.stdout)
        self.assertIn("MdeModulePkg/Bus/Usb/UsbKbDxe/UsbKbDxe.inf", result.stdout)
        self.assertIn(
            "MdeModulePkg/Bus/Usb/UsbMouseAbsolutePointerDxe/UsbMouseAbsolutePointerDxe.inf",
            result.stdout,
        )
        self.assertNotIn("UefiPayloadPkg/CfrSetupMenuDxe/CfrSetupMenuDxe.inf", result.stdout)
        self.assertNotIn("MdeModulePkg/Application/UiApp/UiApp.inf", result.stdout)
        self.assertNotIn(
            "MdeModulePkg/Application/BootManagerMenuApp/BootManagerMenuApp.inf",
            result.stdout,
        )
        self.assertNotIn(
            "MdeModulePkg/Universal/SetupBrowserDxe/SetupBrowserDxe.inf",
            result.stdout,
        )
        self.assertNotIn(
            "MdeModulePkg/Universal/PlatformDriOverrideDxe/PlatformDriOverrideDxe.inf",
            result.stdout,
        )
        self.assertNotIn(
            "UefiPayloadPkg/UserAuthPkg/UserAuthenticationDxe/UserAuthenticationDxe.inf",
            result.stdout,
        )
        self.assertNotIn(
            "MdeModulePkg/Universal/DisplayEngineDxe/DisplayEngineDxe.inf",
            result.stdout,
        )
        self.assertNotIn("MdeModulePkg/Bus/Usb/UsbMouseDxe/UsbMouseDxe.inf", result.stdout)
        self.assertIn("-D SETUP_UI_ENABLE=FALSE", result.stdout)
        self.assertIn("-D LVGL_ENABLE=TRUE", result.stdout)

    def test_lvgl_kconfig_selects_compact_renderer_and_hid_modules(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_USB := y",
                    "CONFIG_CDK2_PS2_MOUSE := n",
                    "CONFIG_CDK2_GRAPHICS := y",
                    "CONFIG_CDK2_SETUP_UI := n",
                    "CONFIG_CDK2_LVGL := y",
                ]
            )
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf", result.stdout)
        self.assertIn("-D LVGL_ENABLE=TRUE", result.stdout)
        self.assertIn("-D SETUP_UI_ENABLE=FALSE", result.stdout)
        self.assertIn(
            "3rdparty/LvglPkg/LvglDisplayEngineDxe/LvglDisplayEngineDxe.inf",
            result.stdout,
        )
        self.assertIn("3rdparty/LvglPkg/LvglSetupDxe/LvglSetupDxe.inf", result.stdout)
        self.assertIn("MdeModulePkg/Bus/Usb/UsbKbDxe/UsbKbDxe.inf", result.stdout)
        self.assertIn(
            "MdeModulePkg/Bus/Usb/UsbMouseAbsolutePointerDxe/UsbMouseAbsolutePointerDxe.inf",
            result.stdout,
        )
        self.assertNotIn("UefiPayloadPkg/CfrSetupMenuDxe/CfrSetupMenuDxe.inf", result.stdout)
        self.assertNotIn("MdeModulePkg/Application/UiApp/UiApp.inf", result.stdout)
        self.assertNotIn(
            "MdeModulePkg/Application/BootManagerMenuApp/BootManagerMenuApp.inf",
            result.stdout,
        )
        self.assertNotIn(
            "MdeModulePkg/Universal/SetupBrowserDxe/SetupBrowserDxe.inf",
            result.stdout,
        )
        self.assertNotIn(
            "MdeModulePkg/Universal/PlatformDriOverrideDxe/PlatformDriOverrideDxe.inf",
            result.stdout,
        )
        self.assertNotIn(
            "UefiPayloadPkg/UserAuthPkg/UserAuthenticationDxe/UserAuthenticationDxe.inf",
            result.stdout,
        )
        self.assertNotIn(
            "MdeModulePkg/Universal/DisplayEngineDxe/DisplayEngineDxe.inf",
            result.stdout,
        )
        self.assertNotIn("MdeModulePkg/Bus/Usb/UsbMouseDxe/UsbMouseDxe.inf", result.stdout)

    def test_lvgl_rejects_ps2_mouse_simple_pointer_path(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_USB := y",
                    "CONFIG_CDK2_GRAPHICS := y",
                    "CONFIG_CDK2_SETUP_UI := n",
                    "CONFIG_CDK2_LVGL := y",
                    "CONFIG_CDK2_PS2_MOUSE := y",
                ]
            )
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "cdk2 LVGL setup requires AbsolutePointer mouse input; "
            "PS/2 mouse only provides SimplePointer here",
            result.stderr,
        )

    def test_lvgl_override_still_requires_usb_hid(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_GRAPHICS := y",
                    "CONFIG_CDK2_USB := n",
                    "CONFIG_CDK2_PS2_MOUSE := n",
                    "CONFIG_CDK2_SETUP_UI := n",
                ]
            ),
            extra_defines="-D LVGL_ENABLE=TRUE",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "cdk2 LVGL setup requires USB_ENABLE=TRUE for USB HID keyboard "
            "and AbsolutePointer mouse input",
            result.stderr,
        )

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
                    "CONFIG_CDK2_SETUP_UI := y",
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

    def test_capsule_define_uses_effective_guid_override(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_GRAPHICS := y",
                    "CONFIG_CDK2_SMM := y",
                    "CONFIG_CDK2_ESRT := y",
                    "CONFIG_CDK2_CAPSULE := y",
                    f'CONFIG_CDK2_CAPSULE_MAIN_FW_GUID := "{CAPSULE_GUID}"',
                ]
            ),
            extra_defines=f"-D CAPSULE_MAIN_FW_GUID={OVERRIDE_CAPSULE_GUID}",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"-D CAPSULE_MAIN_FW_GUID={OVERRIDE_CAPSULE_GUID}",
            result.stdout,
        )
        self.assertNotIn(f"-D CAPSULE_MAIN_FW_GUID={CAPSULE_GUID}", result.stdout)

    def test_storage_override_disables_storage_children(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_STORAGE := y",
                    "CONFIG_CDK2_NVME := y",
                    "CONFIG_CDK2_ATA := y",
                    "CONFIG_CDK2_SD := y",
                ]
            ),
            extra_defines="-D STORAGE_ENABLE=FALSE",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("MdeModulePkg/Bus/Pci/NvmExpressDxe/NvmExpressDxe.inf", result.stdout)
        self.assertNotIn("MdeModulePkg/Bus/Ata/AtaBusDxe/AtaBusDxe.inf", result.stdout)
        self.assertNotIn("MdeModulePkg/Bus/Sd/SdDxe/SdDxe.inf", result.stdout)
        self.assertIn("-D STORAGE_ENABLE=FALSE", result.stdout)
        self.assertIn("-D NVME_ENABLE=FALSE", result.stdout)
        self.assertIn("-D ATA_ENABLE=FALSE", result.stdout)
        self.assertIn("-D SD_ENABLE=FALSE", result.stdout)

    def test_child_override_rejects_disabled_parent(self) -> None:
        result = self._run_inspect(
            "\n".join(
                [
                    "CONFIG_CDK2_PCI := y",
                    "CONFIG_CDK2_STORAGE := y",
                    "CONFIG_CDK2_NVME := y",
                ]
            ),
            extra_defines="-D STORAGE_ENABLE=FALSE -D NVME_ENABLE=TRUE",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "cdk2 define NVME_ENABLE=TRUE requires STORAGE_ENABLE=TRUE",
            result.stderr,
        )

    def test_unsupported_variable_support_override_is_rejected(self) -> None:
        result = self._run_inspect(
            "CONFIG_CDK2_PCI := y",
            extra_defines="-D VARIABLE_SUPPORT=SPI",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "unsupported cdk2 VARIABLE_SUPPORT value: SPI",
            result.stderr,
        )

    def test_duplicate_define_override_is_rejected(self) -> None:
        result = self._run_inspect(
            "CONFIG_CDK2_PCI := y",
            extra_defines="-D PCI_ENABLE=FALSE --define=PCI_ENABLE=TRUE",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate cdk2 define override for PCI_ENABLE", result.stderr)

    def test_noncanonical_bool_override_is_rejected(self) -> None:
        result = self._run_inspect(
            "CONFIG_CDK2_PCI := y",
            extra_defines="-D PCI_ENABLE=1",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "cdk2 define PCI_ENABLE must use TRUE or FALSE",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
