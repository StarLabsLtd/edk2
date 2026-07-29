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
                CDK2_ROOT := {root}
                CDK2_DIR := {CDK2_DIR}
                CDK2_BUILD_DIR := {build}
                CDK2_TARGET := RELEASE
                CDK2_BACKEND_TOOLCHAIN := TEST
                CDK2_BACKEND_OUTPUT_DIRECTORY := out
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


if __name__ == "__main__":
    unittest.main()
