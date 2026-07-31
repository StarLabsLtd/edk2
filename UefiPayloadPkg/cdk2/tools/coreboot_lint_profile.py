## SPDX-License-Identifier: BSD-2-Clause-Patent

"""Local coreboot-quality checks for the cdk2 native payload."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


CDK2_DIR = Path(__file__).resolve().parents[1]
EDK2_ROOT = CDK2_DIR.parents[1]
NATIVE_SRC = CDK2_DIR / "src"
NATIVE_INCLUDE = CDK2_DIR / "include" / "cdk2"


def run(cmd: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, check=check)


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def display_path(path: Path, root: Path = EDK2_ROOT) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def check_path(path: Path, description: str, root: Path = EDK2_ROOT) -> None:
    if not path.exists():
        fail(f"missing {description}: {display_path(path, root)}")


def check_layout() -> None:
    check_path(NATIVE_SRC, "native source directory")
    check_path(NATIVE_INCLUDE, "native include directory")
    if (CDK2_DIR / "native").exists():
        fail("legacy UefiPayloadPkg/cdk2/native directory still exists")
    makefile_inc = sorted(NATIVE_SRC.rglob("Makefile.inc"))
    if makefile_inc:
        paths = ", ".join(display_path(path) for path in makefile_inc)
        fail(f"coreboot native source uses Makefile.inc: {paths}")


def check_native_includes() -> None:
    quoted_include = re.compile(r'^\s*#\s*include\s+"([^"]+)"')
    offenders: list[str] = []
    for suffix in ("*.c", "*.h"):
        for path in sorted(NATIVE_SRC.rglob(suffix)):
            for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                match = quoted_include.match(line)
                if match:
                    offenders.append(f"{display_path(path)}:{line_no}: {match.group(1)}")
    if offenders:
        fail("native source must include cdk2 headers as <cdk2/...>:\n" + "\n".join(offenders))


def check_module_list(build_dir: Path) -> None:
    cmd = [
        "make",
        "-f",
        "UefiPayloadPkg/cdk2/Makefile",
        f"CDK2_BUILD_DIR={build_dir}",
        "modules",
    ]
    result = subprocess.run(
        cmd,
        cwd=EDK2_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    modules = [line.strip() for line in result.stdout.splitlines() if line.strip().endswith(".inf")]
    if not modules:
        fail("cdk2 module list is empty")
    duplicates = sorted({module for module in modules if modules.count(module) > 1})
    if duplicates:
        fail("duplicate selected cdk2 modules:\n" + "\n".join(duplicates))


def check_coreboot_wrapper(coreboot_root: Path) -> None:
    wrapper_kconfig = coreboot_root / "payloads" / "external" / "edk2" / "Kconfig"
    wrapper_makefile = coreboot_root / "payloads" / "external" / "edk2" / "Makefile"
    check_path(wrapper_kconfig, "coreboot edk2 Kconfig", coreboot_root)
    check_path(wrapper_makefile, "coreboot edk2 Makefile", coreboot_root)
    run(["git", "diff", "--check"], coreboot_root)
    run(["util/lint/lint-stable-008-kconfig", str(wrapper_kconfig.relative_to(coreboot_root))], coreboot_root)
    run(
        [
            "util/lint/lint-stable-003-whitespace",
            str(wrapper_kconfig.relative_to(coreboot_root)),
            str(wrapper_makefile.relative_to(coreboot_root)),
        ],
        coreboot_root,
    )
    run(["util/lint/lint-stable-030-makefile-inc", str(wrapper_makefile.relative_to(coreboot_root))], coreboot_root)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--range", default="HEAD~1..HEAD", help="git range for diff/PatchCheck")
    parser.add_argument("--build-dir", default=str(EDK2_ROOT / "Build" / "cdk2-coreboot-lint"))
    parser.add_argument("--coreboot-root", help="optional coreboot tree for wrapper lint")
    parser.add_argument("--skip-patchcheck", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    os.environ.pop("MAKEFLAGS", None)
    os.environ.pop("MAKEOVERRIDES", None)

    check_layout()
    check_native_includes()
    run(["git", "diff", "--check", args.range], EDK2_ROOT)
    if not args.skip_patchcheck:
        run(["python3", "BaseTools/Scripts/PatchCheck.py", args.range], EDK2_ROOT)
    check_module_list(Path(args.build_dir))
    if args.coreboot_root:
        check_coreboot_wrapper(Path(args.coreboot_root).resolve())

    print("cdk2 coreboot-quality profile: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
