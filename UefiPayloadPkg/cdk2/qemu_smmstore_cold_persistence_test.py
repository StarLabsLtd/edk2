#!/usr/bin/env python3
## SPDX-License-Identifier: BSD-2-Clause-Patent

"""QEMU smoke test for cdk2 SMMSTORE cold variable persistence.

The test needs a writable coreboot/QEMU ROM that already contains a cdk2 payload
with SMMSTORE enabled. It copies the ROM to a temporary file, writes a
non-volatile variable in one QEMU process, then starts QEMU again with the same
copied ROM image and checks that dmpstore can still see the variable.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


TEST_GUID = "7C9E5B12-5B8F-4D2C-9E79-65C9B0D7A021"
TEST_NAME = "Cdk2SmmStoreColdPersist"
TEST_BYTES = "de ad be ef"


def _skip(message: str) -> int:
    print(f"SKIP: {message}", file=sys.stderr)
    return 77


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--qemu",
        default=os.environ.get("CDK2_QEMU", "qemu-system-x86_64"),
        help="QEMU executable. Defaults to CDK2_QEMU or qemu-system-x86_64.",
    )
    parser.add_argument(
        "--rom",
        default=os.environ.get("CDK2_QEMU_COREBOOT_ROM"),
        help="Writable coreboot/QEMU ROM with cdk2 SMMSTORE enabled. Defaults to CDK2_QEMU_COREBOOT_ROM.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("CDK2_QEMU_TIMEOUT", "45")),
        help="Seconds to wait for each QEMU boot.",
    )
    parser.add_argument(
        "--firmware-mode",
        choices=("pflash", "bios"),
        default=os.environ.get("CDK2_QEMU_FIRMWARE_MODE", "pflash"),
        help="How to pass the copied ROM to QEMU.",
    )
    parser.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        help="Extra QEMU argument. May be repeated.",
    )
    return parser.parse_args()


def _write_startup(esp: Path, commands: list[str]) -> None:
    startup = esp / "startup.nsh"
    startup.write_text("\r\n".join(commands + ["reset -s", ""]), encoding="utf-8")


def _qemu_command(args: argparse.Namespace, flash: Path, esp: Path) -> list[str]:
    command = [
        args.qemu,
        "-machine",
        "q35,smm=on",
        "-m",
        "512M",
        "-display",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
    ]
    if args.firmware_mode == "pflash":
        command += ["-drive", f"if=pflash,format=raw,file={flash}"]
    else:
        command += ["-bios", str(flash)]

    command += [
        "-drive",
        f"file=fat:rw:{esp},format=raw,media=disk",
    ]
    command += args.extra_arg
    return command


def _run_qemu(args: argparse.Namespace, flash: Path, esp: Path) -> str:
    proc = subprocess.Popen(
        _qemu_command(args, flash, esp),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
    try:
        output, _ = proc.communicate(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        output, _ = proc.communicate()
        raise RuntimeError(f"QEMU timed out after {args.timeout}s\n{output}") from None

    if proc.returncode not in (0, 1):
        raise RuntimeError(f"QEMU exited with status {proc.returncode}\n{output}")

    return output


def main() -> int:
    args = _parse_args()
    qemu = shutil.which(args.qemu)
    if qemu is None:
        return _skip(f"QEMU executable not found: {args.qemu}")
    args.qemu = qemu

    if args.rom is None:
        return _skip("CDK2_QEMU_COREBOOT_ROM or --rom is required")

    rom = Path(args.rom)
    if not rom.is_file():
        return _skip(f"ROM does not exist: {rom}")

    with tempfile.TemporaryDirectory(prefix="cdk2-qemu-smmstore-") as temp_name:
        temp = Path(temp_name)
        flash = temp / "flash.rom"
        esp = temp / "esp"
        esp.mkdir()
        shutil.copyfile(rom, flash)

        _write_startup(
            esp,
            [
                f"setvar {TEST_NAME} -guid {TEST_GUID} -nv -bs -rt ={TEST_BYTES}",
            ],
        )
        _run_qemu(args, flash, esp)

        _write_startup(
            esp,
            [
                f"dmpstore {TEST_NAME} -guid {TEST_GUID}",
            ],
        )
        second = _run_qemu(args, flash, esp)
        if (TEST_NAME not in second) or ("DE AD BE EF" not in second.upper().replace("-", " ")):
            raise RuntimeError(f"SMMSTORE variable did not persist across cold QEMU boots\n{second}")

    print("cdk2 QEMU SMMSTORE cold persistence: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
