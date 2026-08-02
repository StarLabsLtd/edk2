## @file
# Append an RMAP region manifest trailer to a firmware image.
#
# The manifest is a simple list of FMAP region names the firmware update
# should program. It is consumed by the UefiPayloadPkg FMP device library.
# If the manifest is absent, firmware falls back to full-flash updates.
#
# Copyright (c) 2025, 3mdeb Sp. z o.o. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

import argparse
import os
import shlex
import struct
import sys
import subprocess

#
# Globals for help information
#
__prog__        = 'AppendRmapManifest'
__description__ = 'Append an RMAP manifest trailer listing FMAP regions to flash.'
__copyright__   = 'Copyright (c) 2025, 3mdeb Sp. z o.o. All rights reserved.'

# SIGNATURE_32('R','M','A','P')
RMAP_SIGNATURE = 0x50414D52
RMAP_VERSION   = 1
ENTRY_SIZE     = 16


def _validate_region_name(name):
    try:
        encoded = name.encode('ascii')
    except UnicodeError:
        raise ValueError("Region name '{}' is not ASCII".format(name))

    if not encoded:
        raise ValueError("Region name must not be empty")

    if len(encoded) > ENTRY_SIZE:
        raise ValueError("Region name '{}' longer than {} bytes".format(name, ENTRY_SIZE))

    if any(byte < 0x21 or byte > 0x7e for byte in encoded):
        raise ValueError("Region name '{}' contains non-graphic characters".format(name))

    return encoded


def build_manifest(region_names):
    """Return the encoded manifest bytes for the given region names."""
    entries = []
    encoded_names = set()
    if not region_names or len(region_names) > 0xffff:
        raise ValueError("Manifest must contain between 1 and 65535 regions")

    for name in region_names:
        encoded = _validate_region_name(name)
        if encoded in encoded_names:
            raise ValueError("Region name '{}' is duplicated".format(name))
        encoded_names.add(encoded)
        entries.append(struct.pack('<{}s'.format(ENTRY_SIZE), encoded))

    trailer = struct.pack('<IHH', RMAP_SIGNATURE, RMAP_VERSION, len(entries))
    return b''.join(entries) + trailer


def _capsule_option_is_set(args):
    return any([
        args.fmp_guid,
        args.update_image_index is not None,
        args.hardware_instance is not None,
        args.embedded_driver,
        args.pfx_file,
        args.subject_name,
        args.signer_private_cert,
        args.other_public_cert,
        args.trusted_public_cert,
        args.signing_tool_path,
        args.hash_algorithm,
        args.monotonic_count is not None,
        args.fwupd_device,
        args.fwupd_version,
        args.fwupd_command_output,
    ])


def validate_options(args):
    if not args.cap_output and _capsule_option_is_set(args):
        return "--cap-output is required when capsule signing, FMP, or fwupd options are set"

    if args.cap_output and not args.fmp_guid:
        return "--fmp-guid is required when building a capsule"

    if (args.fwupd_device or args.fwupd_version or args.fwupd_command_output) and not args.fwupd_device:
        return "--fwupd-device is required when fwupd install-blob output is requested"

    openssl_args = [
        args.signer_private_cert,
        args.other_public_cert,
        args.trusted_public_cert,
    ]
    if any(openssl_args) and not all(openssl_args):
        return (
            "OpenSSL signing requires --signer-private-cert, "
            "--other-public-cert, and --trusted-public-cert"
        )

    return None


def _append_arg(command, option, value):
    if value is not None:
        command.extend([option, str(value)])


def build_generate_capsule_command(args, payload_path):
    generate_capsule_cmd = [
        args.generatecapsule,
        '-e',
        '--guid', args.fmp_guid,
        '--fw-version', str(args.fw_version),
        '--lsv', str(args.lsv),
        '--capflag', args.capflag,
        '-o', args.cap_output,
    ]

    _append_arg(generate_capsule_cmd, '--update-image-index', args.update_image_index)
    _append_arg(generate_capsule_cmd, '--hardware-instance', args.hardware_instance)
    _append_arg(generate_capsule_cmd, '--embedded-driver', args.embedded_driver)
    _append_arg(generate_capsule_cmd, '--pfx-file', args.pfx_file)
    _append_arg(generate_capsule_cmd, '--subject-name', args.subject_name)
    _append_arg(generate_capsule_cmd, '--signer-private-cert', args.signer_private_cert)
    _append_arg(generate_capsule_cmd, '--other-public-cert', args.other_public_cert)
    _append_arg(generate_capsule_cmd, '--trusted-public-cert', args.trusted_public_cert)
    _append_arg(generate_capsule_cmd, '--signing-tool-path', args.signing_tool_path)
    _append_arg(generate_capsule_cmd, '--hash-algorithm', args.hash_algorithm)
    _append_arg(generate_capsule_cmd, '--monotonic-count', args.monotonic_count)

    generate_capsule_cmd.append(payload_path)
    return generate_capsule_cmd


def build_fwupd_install_blob_command(capsule_path, device_id, version):
    fwupd_cmd = [
        'fwupdtool',
        'install-blob',
        os.path.abspath(capsule_path),
        device_id,
    ]
    if version:
        fwupd_cmd.append(version)

    return fwupd_cmd


def format_shell_command(command):
    return ' '.join(shlex.quote(part) for part in command)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument('input', help='Input firmware image (FMP payload)')
    parser.add_argument('-o', '--output', help='Output path (default: overwrite input)')
    parser.add_argument(
        '-r',
        '--region',
        action='append',
        dest='regions',
        required=True,
        help='FMAP region name to flash (repeat for multiple regions)'
    )
    parser.add_argument('--fmp-guid', help='FMP/ESRT ImageTypeId GUID for the capsule payload')
    parser.add_argument('--fw-version', type=int, default=1, help='Firmware version for capsule payload')
    parser.add_argument('--lsv', type=int, default=0, help='Lowest supported version for capsule payload')
    parser.add_argument('--update-image-index', type=int, help='UpdateImageIndex for the capsule payload')
    parser.add_argument('--hardware-instance', help='Optional GenerateCapsule hardware instance')
    parser.add_argument('--capsule-guid', help='(Deprecated) Ignored when using GenerateCapsule')
    parser.add_argument('--embedded-driver', help='Optional embedded driver (.efi) to include in capsule')
    parser.add_argument('--capflag', default='PersistAcrossReset',
                        choices=['PersistAcrossReset', 'InitiateReset'],
                        help='Capsule flag (default: PersistAcrossReset)')
    parser.add_argument('--cap-output', help='Optional .cap output; enables capsule build via GenerateCapsule')
    parser.add_argument('--generatecapsule', default='BaseTools/BinWrappers/PosixLike/GenerateCapsule',
                        help='Path to GenerateCapsule wrapper')
    parser.add_argument('--pfx-file', help='signtool PFX certificate file for signed capsules')
    parser.add_argument('--subject-name', help='signtool certificate subject name for signed capsules')
    parser.add_argument('--signer-private-cert', help='OpenSSL signer private certificate file')
    parser.add_argument('--other-public-cert', help='OpenSSL intermediate/other public certificate file')
    parser.add_argument('--trusted-public-cert', help='OpenSSL trusted public certificate file')
    parser.add_argument('--signing-tool-path', help='Path to signtool or OpenSSL for GenerateCapsule signing')
    parser.add_argument('--hash-algorithm', help='Payload digest hash algorithm for signed capsules')
    parser.add_argument('--monotonic-count', help='64-bit monotonic count for signed capsule authentication')
    parser.add_argument('--fwupd-device', help='fwupd DEVICE-ID/GUID for fwupdtool install-blob')
    parser.add_argument('--fwupd-version', help='Optional VERSION argument for fwupdtool install-blob')
    parser.add_argument('--fwupd-command-output', help='Write the fwupdtool install-blob command to this file')

    args = parser.parse_args(argv)

    error = validate_options(args)
    if error:
        print("error: {}".format(error), file=sys.stderr)
        return 1

    out_path = args.output or args.input
    try:
        with open(args.input, 'rb') as infile:
            image = infile.read()
    except IOError as exc:
        print("error: failed to read '{}': {}".format(args.input, exc), file=sys.stderr)
        return 1

    try:
        manifest = build_manifest(args.regions)
    except ValueError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1

    try:
        with open(out_path, 'wb') as outfile:
            outfile.write(image)
            outfile.write(manifest)
    except IOError as exc:
        print("error: failed to write '{}': {}".format(out_path, exc), file=sys.stderr)
        return 1

    print("Appended {} region(s) manifest to {}".format(len(args.regions), os.path.abspath(out_path)))

    if not args.cap_output:
        return 0

    if args.capsule_guid:
        print("warning: --capsule-guid is deprecated and ignored by GenerateCapsule", file=sys.stderr)

    generate_capsule_cmd = build_generate_capsule_command(args, out_path)

    try:
        subprocess.check_call(generate_capsule_cmd)
    except subprocess.CalledProcessError as exc:
        print("error: GenerateCapsule failed: {}".format(exc), file=sys.stderr)
        return 1

    print("Built capsule {}".format(os.path.abspath(args.cap_output)))
    if args.fwupd_device:
        fwupd_cmd = build_fwupd_install_blob_command(
            args.cap_output,
            args.fwupd_device,
            args.fwupd_version
        )
        fwupd_command_line = format_shell_command(fwupd_cmd)
        print("fwupd install-blob command: {}".format(fwupd_command_line))
        if args.fwupd_command_output:
            try:
                with open(args.fwupd_command_output, 'w') as command_file:
                    command_file.write(fwupd_command_line)
                    command_file.write('\n')
            except IOError as exc:
                print("error: failed to write '{}': {}".format(args.fwupd_command_output, exc), file=sys.stderr)
                return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
