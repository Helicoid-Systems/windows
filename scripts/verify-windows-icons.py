#!/usr/bin/env python3
"""Packaging/resource verification for Windows role icons.

Checks (no network, no downloads, no secrets):
  1. branding/source PNG and SVG hashes match branding/PROVENANCE.json
  2. branding/generated ICOs contain the required multi-size entries
  3. Optionally, a published folder has the staged ICO beside the exe
     (needed by AppWindow.SetIcon via AppContext.BaseDirectory)
  4. Optionally, a built exe's PE RT_GROUP_ICON / RT_ICON images match the
     role ICO (pure-Python PE parse; no GUI, no Windows-native tools)

Root can invoke on Windows CI after publish:

  python3 scripts/verify-windows-icons.py
  python3 scripts/verify-windows-icons.py --manager-publish artifacts/manager --computer-publish artifacts/computer

PE verification follows the single icon group's resource IDs and requires exact
PNG payloads for every size. No optional dependency or fuzzy pixel fallback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BRANDING_DIR = REPO_ROOT / "branding"
SOURCE_DIR = BRANDING_DIR / "source"
GENERATED_DIR = BRANDING_DIR / "generated"
PROVENANCE_PATH = BRANDING_DIR / "PROVENANCE.json"

REQUIRED_ICO_SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]

# RT_* resource type IDs
RT_ICON = 3
RT_GROUP_ICON = 14

ROLES = {
    "manager": {
        "source_png": "hs-manager-windowsicon.png",
        "source_svg": "hs-manager-windowsicon.svg",
        "output_ico": "hs-manager-windowsicon.ico",
        "staged_ico": "hs-manager-windowsicon.ico",
        "exe_name": "Helicoid.Manager.exe",
    },
    "computer": {
        "source_png": "hs-computer-windowsicon.png",
        "source_svg": "hs-computer-windowsicon.svg",
        "output_ico": "hs-computer-windowsicon.ico",
        "staged_ico": "hs-computer-windowsicon.ico",
        "exe_name": "Helicoid.Computer.exe",
    },
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class CheckFailure(Exception):
    pass


def parse_ico_entries(ico_path: Path) -> list[dict]:
    data = ico_path.read_bytes()
    if len(data) < 6:
        raise CheckFailure(f"{ico_path.name}: truncated ICO header")
    reserved, typ, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or typ != 1 or count == 0:
        raise CheckFailure(
            f"{ico_path.name}: invalid ICONDIR reserved={reserved} type={typ} count={count}"
        )
    entries = []
    off = 6
    for index in range(count):
        if off + 16 > len(data):
            raise CheckFailure(f"{ico_path.name}: truncated ICONDIRENTRY {index}")
        w, h, colors, _res, planes, bitcount, size, offset = struct.unpack_from(
            "<BBBBHHII", data, off
        )
        if offset + size > len(data):
            raise CheckFailure(f"{ico_path.name}: entry {index} payload out of range")
        payload = data[offset : offset + size]
        entries.append(
            {
                "width": w or 256,
                "height": h or 256,
                "colors": colors,
                "planes": planes,
                "bitcount": bitcount,
                "size": size,
                "offset": offset,
                "payload": payload,
                "payload_sha256": sha256_bytes(payload),
                "is_png": payload[:8] == b"\x89PNG\r\n\x1a\n",
            }
        )
        off += 16
    return entries


def rva_to_offset(rva: int, sections: list[tuple]) -> int | None:
    for va, raw_ptr, raw_size, virt_size in sections:
        span = max(raw_size, virt_size)
        if va <= rva < va + span:
            delta = rva - va
            if delta >= raw_size:
                return None
            return raw_ptr + delta
    return None


def parse_pe_resource_icons(exe_path: Path) -> list[dict]:
    """Return icon image payloads from PE RT_GROUP_ICON/RT_ICON resources."""
    data = exe_path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise CheckFailure(f"{exe_path.name}: not a PE file (no MZ)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise CheckFailure(f"{exe_path.name}: missing PE signature")
    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff_off + 2)[0]
    size_opt = struct.unpack_from("<H", data, coff_off + 16)[0]
    opt_off = coff_off + 20
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic == 0x20B:  # PE32+
        dd_off = opt_off + 112
    elif magic == 0x10B:  # PE32
        dd_off = opt_off + 96
    else:
        raise CheckFailure(f"{exe_path.name}: unknown optional header magic {magic:#x}")
    if dd_off + 24 > len(data):
        raise CheckFailure(f"{exe_path.name}: truncated optional header")
    res_rva, res_size = struct.unpack_from("<II", data, dd_off + 2 * 8)
    if res_rva == 0:
        raise CheckFailure(f"{exe_path.name}: no resource directory (ApplicationIcon missing?)")

    sections: list[tuple] = []
    sec_off = opt_off + size_opt
    for i in range(num_sections):
        s = sec_off + i * 40
        if s + 40 > len(data):
            raise CheckFailure(f"{exe_path.name}: truncated section table")
        virt_size, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, s + 8)
        sections.append((va, raw_ptr, raw_size, virt_size))

    res_off = rva_to_offset(res_rva, sections)
    if res_off is None:
        raise CheckFailure(f"{exe_path.name}: resource directory RVA not in sections")

    def read_entry(dir_off: int) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
        # IMAGE_RESOURCE_DIRECTORY
        named, ids = struct.unpack_from("<HH", data, dir_off + 12)
        entries = []
        base = dir_off + 16
        for i in range(named + ids):
            name, offset = struct.unpack_from("<II", data, base + i * 8)
            entries.append((name, offset))
        # High bit of offset => subdirectory
        subs = [(n, o & 0x7FFFFFFF) for n, o in entries if o & 0x80000000]
        leaves = [(n, o & 0x7FFFFFFF) for n, o in entries if not (o & 0x80000000)]
        return subs, leaves

    def data_entry(entry_off: int) -> bytes:
        rva, size = struct.unpack_from("<II", data, entry_off)
        file_off = rva_to_offset(rva, sections)
        if file_off is None or file_off + size > len(data):
            raise CheckFailure(f"{exe_path.name}: resource data RVA out of range")
        return data[file_off : file_off + size]

    type_subs, _ = read_entry(res_off)

    # Keep IDs and languages: unused correct images must not mask a wrong group.
    def walk_type(type_id: int) -> dict[tuple[int, int], bytes]:
        blobs = {}
        for tid, type_off in type_subs:
            if tid != type_id:
                continue
            name_subs, name_leaves = read_entry(res_off + type_off)
            if name_leaves:
                raise CheckFailure(f"{exe_path.name}: invalid resource name level")
            for name_id, name_off in name_subs:
                lang_subs, lang_leaves = read_entry(res_off + name_off)
                if lang_subs:
                    raise CheckFailure(f"{exe_path.name}: invalid resource language level")
                for lang_id, leaf_rel in lang_leaves:
                    key = (name_id, lang_id)
                    if key in blobs:
                        raise CheckFailure(f"{exe_path.name}: duplicate resource ID/language")
                    blobs[key] = data_entry(res_off + leaf_rel)
        return blobs

    icon_blobs = walk_type(RT_ICON)
    groups = walk_type(RT_GROUP_ICON)
    if len(groups) != 1:
        raise CheckFailure(f"{exe_path.name}: expected one icon group, got {len(groups)}")
    (_group_id, language), group = next(iter(groups.items()))
    if len(group) < 6:
        raise CheckFailure(f"{exe_path.name}: truncated icon group")
    reserved, kind, count = struct.unpack_from("<HHH", group)
    if reserved != 0 or kind != 1 or len(group) != 6 + count * 14:
        raise CheckFailure(f"{exe_path.name}: invalid icon group")
    images = []
    for index in range(count):
        w, h, colors, zero, planes, bits, length, resource_id = struct.unpack_from(
            "<BBBBHHIH", group, 6 + index * 14)
        blob = icon_blobs.get((resource_id, language))
        if blob is None or len(blob) != length:
            raise CheckFailure(f"{exe_path.name}: missing/mismatched referenced icon {resource_id}")
        if len(blob) < 24 or blob[:8] != b"\x89PNG\r\n\x1a\n":
            raise CheckFailure(f"{exe_path.name}: referenced icon is not supplied PNG encoding")
        width, height = struct.unpack_from(">II", blob, 16)
        if zero != 0 or (width, height) != (w or 256, h or 256):
            raise CheckFailure(f"{exe_path.name}: icon group dimensions mismatch")
        images.append({"width": width, "height": height,
                       "payload_sha256": sha256_bytes(blob)})
    return images


def compare_icon_payloads(role: str, ico_entries: list[dict], pe_images: list[dict]) -> list[str]:
    expected = sorted((e["width"], e["height"], e["payload_sha256"]) for e in ico_entries)
    actual = sorted((e["width"], e["height"], e["payload_sha256"]) for e in pe_images)
    return [] if actual == expected else [f"{role}: referenced PE icon group differs from role ICO"]


def verify_sources(prov: dict) -> list[str]:
    problems: list[str] = []
    listed = prov.get("canonicalSources", {}).get("files", [])
    expected = {Path(item["path"]).name: item["sha256"] for item in listed}
    for role, spec in ROLES.items():
        for kind in ("source_png", "source_svg"):
            name = spec[kind]
            path = SOURCE_DIR / name
            if not path.is_file():
                problems.append(f"{role}: missing source {name}")
                continue
            actual = sha256_file(path)
            want = expected.get(name)
            if want is None:
                problems.append(f"{role}: {name} not listed in canonicalSources.files")
            elif actual != want:
                problems.append(
                    f"{role}: {name} sha256 mismatch expected={want} actual={actual}"
                )
    return problems


def verify_ico_files(prov: dict) -> list[str]:
    problems: list[str] = []
    generated = {
        Path(item["path"]).name: item for item in prov.get("generated", [])
    }
    for role, spec in ROLES.items():
        ico_path = GENERATED_DIR / spec["output_ico"]
        if not ico_path.is_file():
            problems.append(f"{role}: missing generated ICO {spec['output_ico']}")
            continue
        entries = parse_ico_entries(ico_path)
        got = sorted((e["width"], e["height"]) for e in entries)
        want = sorted(REQUIRED_ICO_SIZES)
        if got != want:
            problems.append(f"{role}: ICO sizes {got} != required {want}")
        recorded = generated.get(spec["output_ico"])
        if recorded is None:
            problems.append(f"{role}: {spec['output_ico']} not listed in generated")
        else:
            actual = sha256_file(ico_path)
            if actual != recorded["sha256"]:
                problems.append(
                    f"{role}: {spec['output_ico']} sha256 mismatch "
                    f"expected={recorded['sha256']} actual={actual}"
                )
    return problems


def verify_publish(role: str, spec: dict, publish_dir: Path) -> list[str]:
    problems: list[str] = []
    exe_path = publish_dir / spec["exe_name"]
    staged = publish_dir / spec["staged_ico"]
    if not exe_path.is_file():
        problems.append(f"{role}: missing published exe {exe_path}")
        return problems
    if not staged.is_file():
        problems.append(
            f"{role}: missing staged ICO beside published exe: {staged} "
            f"(required for AppWindow.SetIcon via AppContext.BaseDirectory)"
        )
    else:
        # Staged copy must match the generated role ICO byte-for-byte.
        gen = GENERATED_DIR / spec["output_ico"]
        if gen.is_file() and sha256_file(staged) != sha256_file(gen):
            problems.append(f"{role}: staged ICO hash differs from generated ICO")

    ico_path = GENERATED_DIR / spec["output_ico"]
    if not ico_path.is_file():
        problems.append(f"{role}: cannot PE-check without generated ICO")
        return problems
    ico_entries = parse_ico_entries(ico_path)
    try:
        pe_images = parse_pe_resource_icons(exe_path)
    except CheckFailure as exc:
        problems.append(str(exc))
        return problems
    problems.extend(compare_icon_payloads(role, ico_entries, pe_images))
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manager-publish",
        type=Path,
        default=None,
        help="published Manager folder (checks staged ICO + PE icon resources)",
    )
    parser.add_argument(
        "--computer-publish",
        type=Path,
        default=None,
        help="published Computer folder (checks staged ICO + PE icon resources)",
    )
    args = parser.parse_args()

    if not PROVENANCE_PATH.is_file():
        print(f"FAIL missing {PROVENANCE_PATH}", file=sys.stderr)
        return 1
    prov = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))

    problems: list[str] = []
    problems.extend(verify_sources(prov))
    problems.extend(verify_ico_files(prov))

    if args.manager_publish is not None:
        problems.extend(
            verify_publish("manager", ROLES["manager"], args.manager_publish)
        )
    if args.computer_publish is not None:
        problems.extend(
            verify_publish("computer", ROLES["computer"], args.computer_publish)
        )

    if problems:
        for problem in problems:
            print(f"FAIL {problem}", file=sys.stderr)
        print(f"verify-windows-icons: {len(problems)} problem(s)", file=sys.stderr)
        return 1

    checked = ["source hashes", "ICO multi-size entries"]
    if args.manager_publish:
        checked.append("manager publish staging + PE icons")
    if args.computer_publish:
        checked.append("computer publish staging + PE icons")
    print(f"PASS verify-windows-icons ({', '.join(checked)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
