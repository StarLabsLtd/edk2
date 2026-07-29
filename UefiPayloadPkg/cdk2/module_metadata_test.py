#!/usr/bin/env python3
## SPDX-License-Identifier: BSD-2-Clause-Patent

"""Host tests for cdk2 module metadata emission."""

from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import tempfile
import unittest
from pathlib import Path

import module_metadata


DRIVER_GUID = "11111111-2222-3333-4444-555555555555"
OVERRIDE_GUID = "22222222-3333-4444-5555-666666666666"

DRIVER_INF = """\
[Defines]
  INF_VERSION = 1.30
  BASE_NAME = SampleDxe
  FILE_GUID = {driver_guid}
  MODULE_TYPE = DXE_DRIVER
  ENTRY_POINT = SampleEntry

[Sources]
  Common.c

[Sources.IA32]
  Ia32.c

[Sources.X64]
  X64.c

[Packages]
  MdePkg/MdePkg.dec

[LibraryClasses]
  DebugLib
  BaseLib

[LibraryClasses.IA32, LibraryClasses.X64]
  ArchLib

[LibraryClasses.AARCH64]
  ArmOnlyLib

[Pcd]
  gPkgTokenSpaceGuid.PcdCommon ## CONSUMES

[FeaturePcd.X64]
  gPkgTokenSpaceGuid.PcdX64Feature ## SOMETIMES_CONSUMES

[Pcd.AARCH64]
  gPkgTokenSpaceGuid.PcdArmOnly

[Depex]
  gEfiSampleProtocolGuid
  AND
  TRUE
""".format(driver_guid=DRIVER_GUID)

LIBRARY_INF = """\
[Defines]
  INF_VERSION = 1.30
  BASE_NAME = SampleLib
  FILE_GUID = AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
  MODULE_TYPE = BASE
  LIBRARY_CLASS = SampleLib|DXE_DRIVER UEFI_DRIVER

[Sources]
  SampleLib.c

[Packages]
  MdePkg/MdePkg.dec
"""


class ModuleMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.workspace = Path(self.tmp.name)
        self._write("Pkg/SampleDxe/SampleDxe.inf", DRIVER_INF)
        self._write("Pkg/SampleLib/SampleLib.inf", LIBRARY_INF)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, relpath: str, text: str) -> None:
        path = self.workspace / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_parse_x64_module_inputs(self) -> None:
        metadata = module_metadata.build_metadata(
            self.workspace,
            "X64",
            ["Pkg/SampleDxe/SampleDxe.inf"],
            ["Pkg/SampleLib/SampleLib.inf"],
        )

        self.assertEqual(metadata["module_count"], 1)
        self.assertEqual(metadata["library_count"], 1)
        module = metadata["modules"][0]
        self.assertEqual(module["file_guid"], DRIVER_GUID)
        self.assertEqual(module["module_type"], "DXE_DRIVER")
        self.assertIn("X64.c", module["sources"])
        self.assertNotIn("Ia32.c", module["sources"])
        self.assertEqual(module["library_classes"], ["ArchLib", "BaseLib", "DebugLib"])
        self.assertEqual(
            module["pcds"],
            [
                {
                    "section": "FeaturePcd",
                    "token": "gPkgTokenSpaceGuid.PcdX64Feature",
                    "usage": "SOMETIMES_CONSUMES",
                },
                {
                    "section": "Pcd",
                    "token": "gPkgTokenSpaceGuid.PcdCommon",
                    "usage": "CONSUMES",
                },
            ],
        )
        self.assertEqual(module["depex"], ["gEfiSampleProtocolGuid", "AND", "TRUE"])

        library = metadata["libraries"][0]
        self.assertEqual(library["defines"]["library_class"], "SampleLib|DXE_DRIVER UEFI_DRIVER")

    def test_write_outputs_are_stable(self) -> None:
        metadata = module_metadata.build_metadata(
            self.workspace,
            "X64",
            ["Pkg/SampleDxe/SampleDxe.inf"],
            [],
        )
        output = self.workspace / "Build/metadata.json"
        guid_map = self.workspace / "Build/guid-map.txt"

        module_metadata.write_outputs(metadata, output, guid_map)
        first = output.read_text(encoding="utf-8")
        module_metadata.write_outputs(metadata, output, guid_map)

        self.assertEqual(first, output.read_text(encoding="utf-8"))
        self.assertEqual(
            guid_map.read_text(encoding="utf-8"),
            f"{DRIVER_GUID} Pkg/SampleDxe/SampleDxe.inf\n",
        )
        parsed = json.loads(first)
        self.assertEqual(parsed["format"], 1)
        self.assertEqual(parsed["pcd_count"], 2)
        self.assertEqual(parsed["depex_module_count"], 1)

    def test_missing_required_define_is_rejected(self) -> None:
        self._write(
            "Pkg/Broken/Broken.inf",
            """\
[Defines]
  BASE_NAME = Broken
  MODULE_TYPE = DXE_DRIVER
""",
        )

        with self.assertRaises(module_metadata.MetadataError):
            module_metadata.build_metadata(
                self.workspace,
                "X64",
                ["Pkg/Broken/Broken.inf"],
                [],
            )

    def test_manifest_file_guid_override_replaces_inf_default(self) -> None:
        module_list = self.workspace / "Build/modules.txt"
        self._write(
            str(module_list.relative_to(self.workspace)),
            f"Pkg/SampleDxe/SampleDxe.inf FILE_GUID={OVERRIDE_GUID}\n",
        )

        metadata = module_metadata.build_metadata(
            self.workspace,
            "X64",
            module_metadata.read_path_list(module_list),
            [],
        )

        self.assertEqual(metadata["modules"][0]["file_guid"], OVERRIDE_GUID)

    def test_manifest_without_file_guid_override_uses_inf_default(self) -> None:
        module_list = self.workspace / "Build/modules.txt"
        self._write(
            str(module_list.relative_to(self.workspace)),
            "Pkg/SampleDxe/SampleDxe.inf\n",
        )

        metadata = module_metadata.build_metadata(
            self.workspace,
            "X64",
            module_metadata.read_path_list(module_list),
            [],
        )

        self.assertEqual(metadata["modules"][0]["file_guid"], DRIVER_GUID)

    def test_main_reports_invalid_manifest_file_guid_without_traceback(self) -> None:
        module_list = self.workspace / "Build/modules.txt"
        output = self.workspace / "Build/metadata.json"
        self._write(
            str(module_list.relative_to(self.workspace)),
            "Pkg/SampleDxe/SampleDxe.inf FILE_GUID=not-a-guid\n",
        )

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = module_metadata.main(
                [
                    "--workspace",
                    str(self.workspace),
                    "--module-list",
                    str(module_list),
                    "--output",
                    str(output),
                ]
            )

        self.assertEqual(result, 1)
        error = stderr.getvalue()
        self.assertIn("module_metadata.py:", error)
        self.assertIn("invalid GUID: not-a-guid", error)
        self.assertNotIn("Traceback", error)


if __name__ == "__main__":
    unittest.main()
