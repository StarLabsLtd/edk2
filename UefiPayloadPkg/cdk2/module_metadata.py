#!/usr/bin/env python3
## SPDX-License-Identifier: BSD-2-Clause-Patent

"""Emit deterministic cdk2 metadata from selected EDK II INF files."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import re
import sys
from pathlib import Path
from typing import TypeVar


ARCHES = {
    "AARCH64",
    "ARM",
    "EBC",
    "IA32",
    "LOONGARCH64",
    "RISCV64",
    "X64",
}

PCD_SECTIONS = {
    "featurepcd": "FeaturePcd",
    "fixedpcd": "FixedPcd",
    "patchpcd": "PatchPcd",
    "pcd": "Pcd",
    "pcdex": "PcdEx",
}

DEFINE_KEYS = (
    "BASE_NAME",
    "CONSTRUCTOR",
    "DESTRUCTOR",
    "ENTRY_POINT",
    "FILE_GUID",
    "LIBRARY_CLASS",
    "MODULE_TYPE",
    "UNLOAD_IMAGE",
)

GUID_PATTERN = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
T = TypeVar("T")


class MetadataError(RuntimeError):
    pass


@dataclass(frozen=True)
class ModuleSelection:
    path: str
    file_guid: str | None = None


def _strip_comment(line: str) -> tuple[str, str]:
    line = line.strip()
    if not line or line.startswith("#"):
        return "", ""

    entry, marker, usage = line.partition("##")
    if marker:
        return entry.strip(), usage.strip()

    entry = entry.split("#", 1)[0]
    return entry.strip(), ""


def _split_sections(header: str) -> list[str]:
    return [section.strip() for section in header.split(",") if section.strip()]


def _section_applies(section: str, arch: str) -> bool:
    tags = [tag.upper() for tag in section.split(".")[1:]]
    arch_tags = [tag for tag in tags if tag in ARCHES]
    return not arch_tags or arch.upper() in arch_tags


def _base_section(section: str) -> str:
    return section.split(".", 1)[0].lower()


def _uniq_sorted(values: list[str]) -> list[str]:
    return sorted(set(values))


def _uniq_dicts_sorted(values: list[dict[str, str]]) -> list[dict[str, str]]:
    keyed = {
        (value["section"], value["token"], value.get("usage", "")): value
        for value in values
    }
    return [keyed[key] for key in sorted(keyed)]


def _entry_token(line: str) -> str:
    token = line.split("|", 1)[0].strip()
    return token.split()[0] if token.split() else ""


def _source_path(line: str) -> str:
    return line.split("|", 1)[0].strip().split()[0]


def _parse_define(line: str) -> tuple[str, str] | None:
    if "=" not in line:
        return None
    key, value = line.split("=", 1)
    return key.strip().upper(), value.strip()


def _normalize_guid(value: str, source: str) -> str:
    guid = value.strip().strip('"')
    if not GUID_PATTERN.fullmatch(guid):
        raise MetadataError(f"{source}: invalid GUID: {value}")
    return guid.upper()


def _parse_module_selection(line: str, source: str) -> ModuleSelection:
    tokens = line.split()
    relpath = tokens[0]
    file_guid: str | None = None

    for attribute in tokens[1:]:
        key, separator, value = attribute.partition("=")
        if separator != "=" or not key:
            raise MetadataError(f"{source}: invalid module attribute: {attribute}")
        if key.upper() != "FILE_GUID":
            raise MetadataError(f"{source}: unsupported module attribute: {key}")
        if file_guid is not None:
            raise MetadataError(f"{source}: duplicate FILE_GUID attribute")
        file_guid = _normalize_guid(value, f"{source}: FILE_GUID")

    return ModuleSelection(relpath, file_guid)


def read_path_list(path: Path) -> list[ModuleSelection]:
    paths: list[ModuleSelection] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        paths.append(_parse_module_selection(line, f"{path}:{lineno}"))
    return paths


def parse_inf(
    workspace: Path,
    relpath: str,
    arch: str,
    file_guid_override: str | None = None,
) -> dict[str, object]:
    inf = workspace / relpath
    if not inf.is_file():
        raise MetadataError(f"missing INF: {relpath}")

    active_sections: list[str] = []
    defines: dict[str, str] = {}
    packages: list[str] = []
    libraries: list[str] = []
    sources: list[str] = []
    pcds: list[dict[str, str]] = []
    depex: list[str] = []

    for raw in inf.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            active_sections = [
                section
                for section in _split_sections(stripped[1:-1])
                if _section_applies(section, arch)
            ]
            continue

        line, usage = _strip_comment(raw)
        if not line or line.startswith("!"):
            continue

        for section in active_sections:
            base = _base_section(section)
            if base == "defines":
                define = _parse_define(line)
                if define is not None:
                    defines[define[0]] = define[1]
            elif base == "packages":
                packages.append(_entry_token(line))
            elif base == "libraryclasses":
                libraries.append(_entry_token(line))
            elif base == "sources":
                sources.append(_source_path(line))
            elif base in PCD_SECTIONS:
                token = _entry_token(line)
                if token:
                    pcds.append(
                        {
                            "section": PCD_SECTIONS[base],
                            "token": token,
                            "usage": usage,
                        }
                    )
            elif base == "depex":
                depex.append(line)

    missing = [key for key in ("BASE_NAME", "FILE_GUID", "MODULE_TYPE") if key not in defines]
    if missing:
        raise MetadataError(f"{relpath}: missing required INF defines: {', '.join(missing)}")

    selected_defines = {
        key.lower(): defines[key]
        for key in DEFINE_KEYS
        if key in defines and key not in ("BASE_NAME", "FILE_GUID", "MODULE_TYPE")
    }

    file_guid = (
        _normalize_guid(file_guid_override, f"{relpath}: FILE_GUID override")
        if file_guid_override is not None
        else _normalize_guid(defines["FILE_GUID"], f"{relpath}: FILE_GUID")
    )

    return {
        "path": relpath,
        "base_name": defines["BASE_NAME"],
        "file_guid": file_guid,
        "module_type": defines["MODULE_TYPE"],
        "defines": selected_defines,
        "packages": _uniq_sorted([package for package in packages if package]),
        "library_classes": _uniq_sorted([library for library in libraries if library]),
        "sources": _uniq_sorted([source for source in sources if source]),
        "pcds": _uniq_dicts_sorted(pcds),
        "depex": depex,
    }


def unique_preserve(values: list[T]) -> list[T]:
    seen: set[T] = set()
    result: list[T] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _module_selection(value: str | ModuleSelection) -> ModuleSelection:
    if isinstance(value, ModuleSelection):
        return value
    return ModuleSelection(value)


def build_metadata(
    workspace: Path,
    arch: str,
    modules: list[str | ModuleSelection],
    libraries: list[str],
) -> dict[str, object]:
    module_selections = unique_preserve(
        [_module_selection(module) for module in modules]
    )
    libraries = unique_preserve(libraries)

    module_records = [
        parse_inf(workspace, module.path, arch, module.file_guid)
        for module in module_selections
    ]
    library_records = [parse_inf(workspace, path, arch) for path in libraries]
    module_guids = [module["file_guid"] for module in module_records]

    if len(module_guids) != len(set(module_guids)):
        duplicates = sorted({guid for guid in module_guids if module_guids.count(guid) > 1})
        raise MetadataError(f"duplicate module FILE_GUID values: {', '.join(duplicates)}")

    return {
        "format": 1,
        "arch": arch.upper(),
        "module_count": len(module_records),
        "library_count": len(library_records),
        "pcd_count": sum(len(module["pcds"]) for module in module_records),
        "depex_module_count": sum(1 for module in module_records if module["depex"]),
        "modules": module_records,
        "libraries": library_records,
    }


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def write_outputs(metadata: dict[str, object], output: Path, guid_map: Path | None) -> None:
    json_text = json.dumps(metadata, indent=2, sort_keys=True)
    _atomic_write(output, f"{json_text}\n")

    if guid_map is not None:
        lines = [
            f"{module['file_guid']} {module['path']}"
            for module in metadata["modules"]
        ]
        _atomic_write(guid_map, "".join(f"{line}\n" for line in lines))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--arch", default="X64")
    parser.add_argument("--module", action="append", default=[])
    parser.add_argument("--module-list", action="append", default=[], type=Path)
    parser.add_argument("--library", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--guid-map", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    try:
        modules = list(args.module)
        for module_list in args.module_list:
            modules.extend(read_path_list(module_list))
        metadata = build_metadata(
            args.workspace.resolve(),
            args.arch,
            modules,
            list(args.library),
        )
        write_outputs(metadata, args.output, args.guid_map)
    except OSError as exc:
        print(f"module_metadata.py: {exc}", file=sys.stderr)
        return 1
    except MetadataError as exc:
        print(f"module_metadata.py: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
