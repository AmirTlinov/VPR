#!/usr/bin/env python3
"""
Synchronize TLS fingerprint overrides from declarative sources.

Usage:
    python scripts/tls-fp-sync.py \
        --source config/tls_fp_sync_sources.json \
        --output config/tls_fingerprint_overrides.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update TLS fingerprint overrides")
    parser.add_argument(
        "--source",
        default="config/tls_fp_sync_sources.json",
        help="Path to JSON file describing profiles",
    )
    parser.add_argument(
        "--output",
        default="config/tls_fingerprint_overrides.json",
        help="Destination JSON file for overrides",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print result instead of writing to disk",
    )
    return parser.parse_args()


def load_json_from_url(url: str) -> Dict[str, Any]:
    with urllib.request.urlopen(url, timeout=10) as resp:  # nosec B310
        payload = resp.read().decode("utf-8")
    return json.loads(payload)


def load_profile_data(entry: Dict[str, Any], base_dir: Path) -> Dict[str, Any]:
    if "data" in entry:
        data = entry["data"]
    elif "file" in entry:
        data_path = (base_dir / entry["file"]).resolve()
        data = json.loads(data_path.read_text(encoding="utf-8"))
    elif "url" in entry:
        data = load_json_from_url(entry["url"])
    else:
        raise ValueError(f"Profile {entry!r} missing 'data', 'file', or 'url'")

    if "ja3" in entry:
        apply_ja3_string(data, entry["ja3"])

    return data


def apply_ja3_string(data: Dict[str, Any], ja3: str) -> None:
    """Merge JA3 string into the data map."""
    parts = ja3.split(",")
    if len(parts) != 5:
        raise ValueError(f"Invalid JA3 string: {ja3}")

    data["tls_version"] = int(parts[0])
    data["cipher_suites"] = _parse_ja3_component(parts[1])
    data["extensions"] = _parse_ja3_component(parts[2])
    data["elliptic_curves"] = _parse_ja3_component(parts[3])
    data["ec_point_formats"] = _parse_ja3_component(parts[4])


def _parse_ja3_component(component: str) -> Any:
    if not component:
        return []
    return [int(segment) for segment in component.split("-") if segment]


def main() -> None:
    args = parse_args()
    source_path = Path(args.source).resolve()
    base_dir = source_path.parent

    try:
        source_spec = json.loads(source_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"[tls-fp-sync] source file not found: {source_path}", file=sys.stderr)
        sys.exit(1)

    overrides: Dict[str, Any] = {
        "generated_at": dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "profiles": {},
    }

    for entry in source_spec.get("profiles", []):
        name = entry.get("name")
        if not name:
            print("[tls-fp-sync] skipping entry without name", file=sys.stderr)
            continue

        try:
            profile_data = load_profile_data(entry, base_dir)
        except Exception as exc:  # pylint: disable=broad-except
            print(f"[tls-fp-sync] failed to load {name}: {exc}", file=sys.stderr)
            continue

        overrides["profiles"][name.lower()] = profile_data

    output = json.dumps(overrides, indent=2, sort_keys=True)

    if args.dry_run:
        print(output)
    else:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output + "\n", encoding="utf-8")
        print(f"[tls-fp-sync] updated {output_path}")


if __name__ == "__main__":
    main()

