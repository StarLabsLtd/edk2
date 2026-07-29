## @file
# Unit tests for the RMAP manifest helper.
#
# Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

import importlib.util
import struct
import unittest
from pathlib import Path


TOOL_PATH = Path(__file__).resolve().parents[1] / "AppendRmapManifest.py"
TOOL_SPEC = importlib.util.spec_from_file_location("AppendRmapManifest", TOOL_PATH)
AppendRmapManifest = importlib.util.module_from_spec(TOOL_SPEC)
TOOL_SPEC.loader.exec_module(AppendRmapManifest)


class AppendRmapManifestTests(unittest.TestCase):
    def test_coreboot_ec_manifest_uses_16_byte_entries(self):
        manifest = AppendRmapManifest.build_manifest(["COREBOOT", "EC"])

        self.assertEqual(len(manifest), 16 + 16 + 8)
        self.assertEqual(manifest[0:16], b"COREBOOT" + b"\0" * 8)
        self.assertEqual(manifest[16:32], b"EC" + b"\0" * 14)
        self.assertEqual(
            manifest[32:],
            struct.pack(
                "<IHH",
                AppendRmapManifest.RMAP_SIGNATURE,
                AppendRmapManifest.RMAP_VERSION,
                2,
            ),
        )

    def test_rejects_names_longer_than_16_bytes(self):
        with self.assertRaisesRegex(ValueError, "longer than 16 bytes"):
            AppendRmapManifest.build_manifest(["1234567890ABCDEFG"])

    def test_rejects_invalid_names(self):
        for name in ("", "CORE BOOT", "EC\n"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "invalid characters"):
                    AppendRmapManifest.build_manifest([name])

    def test_rejects_duplicate_names(self):
        with self.assertRaisesRegex(ValueError, "duplicated"):
            AppendRmapManifest.build_manifest(["COREBOOT", "COREBOOT"])


if __name__ == "__main__":
    unittest.main()
