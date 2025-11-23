#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from statistics import mean
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from gui.vpr_studio.health_parser import classify_suspicion

DEFAULT_PATH = Path.home() / ".vpr" / "health_reports.jsonl"


def load_reports(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    reports: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                reports.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"[WARN] Skipping malformed line {line_no} in {path}")
    return reports


def format_transport(entry: dict[str, Any]) -> str:
    name = entry.get("transport", "?").upper()
    status = "OK" if entry.get("ok") else "FAIL"
    latency = entry.get("latency_ms", 0)
    jitter = entry.get("jitter_ms", 0)
    suspicion = entry.get("detail") if not entry.get("ok") else ""
    extras = f"lat={latency}ms jitter={jitter:.1f}"
    if suspicion:
        extras += f" detail={suspicion}"
    return f"{name}:{status}({extras})"


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect vpr health reports")
    parser.add_argument("--path", type=Path, default=DEFAULT_PATH, help="JSONL file path")
    parser.add_argument("--tail", type=int, default=10, help="number of latest reports to show")
    parser.add_argument("--json", action="store_true", help="emit raw JSON instead of text summary")
    args = parser.parse_args()

    reports = load_reports(args.path)
    if not reports:
        print(f"[INFO] No reports found at {args.path}")
        return

    if args.tail > 0:
        reports = reports[-args.tail :]

    if args.json:
        print(json.dumps(reports, indent=2))
        return

    suspicions = [float(r.get("suspicion", 0.0)) for r in reports if isinstance(r.get("suspicion"), (int, float))]
    avg_susp = mean(suspicions) if suspicions else 0.0
    print(f"Showing {len(reports)} report(s) from {args.path}")
    print(f"Average suspicion: {avg_susp:.2f}")

    for report in reversed(reports):
        ts = report.get("generated_at", 0)
        target = report.get("target", report.get("query", "node"))
        suspicion_val = report.get("suspicion", 0.0)
        try:
            suspicion_float = float(suspicion_val)
            severity = classify_suspicion(suspicion_float)
            suspicion_display = f"{suspicion_float:.2f}"
        except (TypeError, ValueError):
            suspicion_display = "?"
            severity = "UNKNOWN"
        transports = ", ".join(format_transport(t) for t in report.get("results", []))
        print(f"- ts={ts} target={target} suspicion={suspicion_display} [{severity}]")
        if transports:
            print(f"  transports: {transports}")


if __name__ == "__main__":
    main()
