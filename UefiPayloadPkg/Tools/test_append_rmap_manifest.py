#!/usr/bin/env python3
#
# Unit tests for AppendRmapManifest.py.
#
# Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

import importlib.util
import os
import struct
import tempfile
import unittest
from unittest import mock


MODULE_PATH = os.path.join(os.path.dirname(__file__), 'AppendRmapManifest.py')
SPEC = importlib.util.spec_from_file_location('AppendRmapManifest', MODULE_PATH)
AppendRmapManifest = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AppendRmapManifest)


class AppendRmapManifestTests(unittest.TestCase):
    def test_manifest_entry_width_and_trailer_format(self):
        manifest = AppendRmapManifest.build_manifest(['1234567890ABCDEF'])

        self.assertEqual(len(manifest), AppendRmapManifest.ENTRY_SIZE + 8)
        self.assertEqual(manifest[:AppendRmapManifest.ENTRY_SIZE], b'1234567890ABCDEF')
        self.assertEqual(
            struct.unpack('<IHH', manifest[AppendRmapManifest.ENTRY_SIZE:]),
            (
                AppendRmapManifest.RMAP_SIGNATURE,
                AppendRmapManifest.RMAP_VERSION,
                1,
            ),
        )

    def test_short_manifest_names_are_zero_padded(self):
        manifest = AppendRmapManifest.build_manifest(['FW_MAIN_A'])

        self.assertEqual(
            manifest[:AppendRmapManifest.ENTRY_SIZE],
            b'FW_MAIN_A' + b'\0' * (AppendRmapManifest.ENTRY_SIZE - len('FW_MAIN_A')),
        )

    def test_malformed_region_names_are_rejected(self):
        for region_name in [
            '',
            'FW MAIN',
            'FW\tMAIN',
            'FW_MAIN_\u2603',
            '1234567890ABCDEFG',
        ]:
            with self.subTest(region_name=region_name):
                with self.assertRaises(ValueError):
                    AppendRmapManifest.build_manifest([region_name])

    def test_signed_capsule_and_fwupd_command_are_packaged(self):
        guid = '01234567-89ab-cdef-0123-456789abcdef'

        with tempfile.TemporaryDirectory() as temp_dir:
            payload = os.path.join(temp_dir, 'payload.bin')
            output = os.path.join(temp_dir, 'payload.rmap')
            capsule = os.path.join(temp_dir, 'payload.cap')
            fwupd_command = os.path.join(temp_dir, 'install-blob.cmd')

            with open(payload, 'wb') as payload_file:
                payload_file.write(b'firmware')

            with mock.patch.object(AppendRmapManifest.subprocess, 'check_call') as check_call:
                status = AppendRmapManifest.main([
                    payload,
                    '-o', output,
                    '-r', 'FW_MAIN_A',
                    '--cap-output', capsule,
                    '--generatecapsule', 'GenerateCapsule',
                    '--fmp-guid', guid,
                    '--fw-version', '7',
                    '--lsv', '3',
                    '--update-image-index', '1',
                    '--hardware-instance', '0x2',
                    '--signer-private-cert', 'signer.pem',
                    '--other-public-cert', 'other.pem',
                    '--trusted-public-cert', 'trusted.pem',
                    '--signing-tool-path', '/usr/bin/openssl',
                    '--hash-algorithm', 'sha384',
                    '--monotonic-count', '9',
                    '--fwupd-device', 'com.example.device',
                    '--fwupd-version', '7.3',
                    '--fwupd-command-output', fwupd_command,
                ])

            self.assertEqual(status, 0)
            check_call.assert_called_once_with([
                'GenerateCapsule',
                '-e',
                '--guid', guid,
                '--fw-version', '7',
                '--lsv', '3',
                '--capflag', 'PersistAcrossReset',
                '-o', capsule,
                '--update-image-index', '1',
                '--hardware-instance', '0x2',
                '--signer-private-cert', 'signer.pem',
                '--other-public-cert', 'other.pem',
                '--trusted-public-cert', 'trusted.pem',
                '--signing-tool-path', '/usr/bin/openssl',
                '--hash-algorithm', 'sha384',
                '--monotonic-count', '9',
                output,
            ])

            with open(output, 'rb') as output_file:
                self.assertTrue(output_file.read().startswith(b'firmware'))

            with open(fwupd_command, 'r') as command_file:
                self.assertEqual(
                    command_file.read().strip(),
                    'fwupdtool install-blob {} com.example.device 7.3'.format(capsule)
                )

    def test_capsule_options_fail_before_output_is_written(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = os.path.join(temp_dir, 'payload.bin')
            output = os.path.join(temp_dir, 'payload.rmap')

            with open(payload, 'wb') as payload_file:
                payload_file.write(b'firmware')

            status = AppendRmapManifest.main([
                payload,
                '-o', output,
                '-r', 'FW_MAIN_A',
                '--fwupd-device', 'com.example.device',
            ])

            self.assertEqual(status, 1)
            self.assertFalse(os.path.exists(output))

    def test_invalid_region_name_fails_before_output_is_written(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = os.path.join(temp_dir, 'payload.bin')
            output = os.path.join(temp_dir, 'payload.rmap')

            with open(payload, 'wb') as payload_file:
                payload_file.write(b'firmware')

            status = AppendRmapManifest.main([
                payload,
                '-o', output,
                '-r', 'FW MAIN',
            ])

            self.assertEqual(status, 1)
            self.assertFalse(os.path.exists(output))

    def test_openssl_signing_requires_complete_certificate_set(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = os.path.join(temp_dir, 'payload.bin')
            output = os.path.join(temp_dir, 'payload.rmap')
            capsule = os.path.join(temp_dir, 'payload.cap')

            with open(payload, 'wb') as payload_file:
                payload_file.write(b'firmware')

            status = AppendRmapManifest.main([
                payload,
                '-o', output,
                '-r', 'FW_MAIN_A',
                '--cap-output', capsule,
                '--fmp-guid', '01234567-89ab-cdef-0123-456789abcdef',
                '--signer-private-cert', 'signer.pem',
            ])

            self.assertEqual(status, 1)
            self.assertFalse(os.path.exists(output))

    def test_signtool_and_openssl_options_fail_before_output_is_written(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = os.path.join(temp_dir, 'payload.bin')
            output = os.path.join(temp_dir, 'payload.rmap')
            capsule = os.path.join(temp_dir, 'payload.cap')

            with open(payload, 'wb') as payload_file:
                payload_file.write(b'firmware')

            status = AppendRmapManifest.main([
                payload,
                '-o', output,
                '-r', 'FW_MAIN_A',
                '--cap-output', capsule,
                '--fmp-guid', '01234567-89ab-cdef-0123-456789abcdef',
                '--pfx-file', 'signing.pfx',
                '--signer-private-cert', 'signer.pem',
                '--other-public-cert', 'other.pem',
                '--trusted-public-cert', 'trusted.pem',
            ])

            self.assertEqual(status, 1)
            self.assertFalse(os.path.exists(output))

    def test_auth_controls_require_signing_credentials(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = os.path.join(temp_dir, 'payload.bin')
            output = os.path.join(temp_dir, 'payload.rmap')
            capsule = os.path.join(temp_dir, 'payload.cap')

            with open(payload, 'wb') as payload_file:
                payload_file.write(b'firmware')

            status = AppendRmapManifest.main([
                payload,
                '-o', output,
                '-r', 'FW_MAIN_A',
                '--cap-output', capsule,
                '--fmp-guid', '01234567-89ab-cdef-0123-456789abcdef',
                '--hash-algorithm', 'sha384',
                '--monotonic-count', '9',
            ])

            self.assertEqual(status, 1)
            self.assertFalse(os.path.exists(output))

    def test_signtool_is_rejected_on_non_windows_hosts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            payload = os.path.join(temp_dir, 'payload.bin')
            output = os.path.join(temp_dir, 'payload.rmap')
            capsule = os.path.join(temp_dir, 'payload.cap')

            with open(payload, 'wb') as payload_file:
                payload_file.write(b'firmware')

            with mock.patch.object(AppendRmapManifest.platform, 'system', return_value='Linux'):
                status = AppendRmapManifest.main([
                    payload,
                    '-o', output,
                    '-r', 'FW_MAIN_A',
                    '--cap-output', capsule,
                    '--fmp-guid', '01234567-89ab-cdef-0123-456789abcdef',
                    '--pfx-file', 'signing.pfx',
                ])

            self.assertEqual(status, 1)
            self.assertFalse(os.path.exists(output))

    def test_fwupd_command_quotes_shell_metacharacters(self):
        command = AppendRmapManifest.build_fwupd_install_blob_command(
            '/tmp/capsule path/payload.cap',
            'device id',
            '7.3',
        )

        self.assertEqual(
            AppendRmapManifest.format_shell_command(command),
            "fwupdtool install-blob '/tmp/capsule path/payload.cap' 'device id' 7.3",
        )


if __name__ == '__main__':
    unittest.main()
