#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause-Patent
"""Generate the dbxDefault append list without changing signed DBX updates."""

from pathlib import Path
import struct


def signature_lists(path):
    data = path.read_bytes()
    descriptor_size = 16 + struct.unpack_from('<I', data, 16)[0]
    if not 40 <= descriptor_size < len(data):
        raise ValueError(f'{path}: invalid authentication descriptor')
    offset = descriptor_size
    while offset < len(data):
        signature_type, size, header_size, entry_size = struct.unpack_from(
            '<16sIII', data, offset)
        start = offset + 28 + header_size
        end = offset + size
        if (entry_size < 16 or size < 28 + header_size or
                end > len(data) or (end - start) % entry_size):
            raise ValueError(f'{path}: invalid signature list')
        yield signature_type, data[offset:start], [
            data[pos:pos + entry_size] for pos in range(start, end, entry_size)]
        offset = end


def main():
    directory = Path(__file__).resolve().parent
    baseline = {
        (signature_type, entry)
        for signature_type, _, entries in signature_lists(
            directory / 'dbx_microsoft_baseline.bin')
        for entry in entries
    }
    result = bytearray()
    for signature_type, header, entries in signature_lists(
            directory / 'dbx_microsoft_update.bin'):
        # Match AuthVariableLib: compare type and complete EFI_SIGNATURE_DATA,
        # including the owner, and preserve the order of the update.
        added = b''.join(entry for entry in entries
                         if (signature_type, entry) not in baseline)
        if added:
            header = bytearray(header)
            struct.pack_into('<I', header, 16, len(header) + len(added))
            result += header + added
    (directory / 'dbx_microsoft_append.esl').write_bytes(result)


if __name__ == '__main__':
    main()
