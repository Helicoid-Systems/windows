#!/usr/bin/env python3
"""Deterministic conversion of supplied Windows icon PNGs into multi-resolution ICOs.

Source of truth: branding/source/*-windowsicon.png (2000x2000 RGBA, user-supplied).
Output: branding/generated/*-windowsicon.ico with entries 16,24,32,48,64,128,256.

Recipe (no generative redesign; no geometry or color changes):
  1. Load the exact source PNG as RGBA (verify 2000x2000 and recorded sha256).
  2. Hand the full frame to Pillow's ICO writer with sizes
     16,24,32,48,64,128,256. Pillow downsamples each entry with
     Image.Resampling.LANCZOS (square source to square target preserves
     supplied transparency and padding proportionally).
  3. ICO entries are PNG-encoded (alpha preserved). No crop, recolor, or
     recomposition.

Isolated toolchain only (no global installs):
  uv run --with pillow==12.3.0 python3 scripts/build-windows-icons.py
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from PIL import Image

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = REPO_ROOT / "branding" / "source"
OUTPUT_DIR = REPO_ROOT / "branding" / "generated"

# Fixed ICO sizes. 256 is stored as 0 in the ICONDIR width/height bytes.
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]

ROLES = {
    "manager": {
        "source_png": "hs-manager-windowsicon.png",
        "output_ico": "hs-manager-windowsicon.ico",
    },
    "computer": {
        "source_png": "hs-computer-windowsicon.png",
        "output_ico": "hs-computer-windowsicon.ico",
    },
}

EXPECTED_SOURCE_PNG_SHA256 = {
    "hs-manager-windowsicon.png": "a8c0c3de635c8f65cb848b1e57f63024d8cd7a1f25fcbf651084b9cde4c45fc9",
    "hs-computer-windowsicon.png": "191d74434f21ab77130b5b76e7bf6a1494d117443af504930b8e27affbc007a9",
}

SOURCE_PNG_WIDTH = 2000
SOURCE_PNG_HEIGHT = 2000


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_role(role: str, spec: dict[str, str]) -> Path:
    source_path = SOURCE_DIR / spec["source_png"]
    output_path = OUTPUT_DIR / spec["output_ico"]

    if not source_path.is_file():
        raise FileNotFoundError(f"missing source PNG: {source_path}")

    actual_hash = sha256_file(source_path)
    expected_hash = EXPECTED_SOURCE_PNG_SHA256[spec["source_png"]]
    if actual_hash != expected_hash:
        raise ValueError(
            f"{spec['source_png']} sha256 mismatch: expected {expected_hash}, got {actual_hash}"
        )

    with Image.open(source_path) as im:
        im.load()
        if im.size != (SOURCE_PNG_WIDTH, SOURCE_PNG_HEIGHT):
            raise ValueError(
                f"{spec['source_png']} is {im.size}, expected "
                f"{(SOURCE_PNG_WIDTH, SOURCE_PNG_HEIGHT)}"
            )
        # Keep the supplied RGBA frame exactly; only standard downsampling follows.
        frame = im.convert("RGBA")
        frame.save(output_path, format="ICO", sizes=[(s, s) for s in ICO_SIZES])

    print(f"role={role} source={source_path.name} -> {output_path.relative_to(REPO_ROOT)}")
    print(f"  source_sha256={actual_hash}")
    print(f"  ico_sha256={sha256_file(output_path)}")
    print(f"  sizes={ICO_SIZES}")
    return output_path


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for role, spec in ROLES.items():
        build_role(role, spec)
    return 0


if __name__ == "__main__":
    sys.exit(main())
