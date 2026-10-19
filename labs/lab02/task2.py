from __future__ import annotations

import argparse
import csv
import json
import logging
import re
from pathlib import Path
from typing import Any

REQUIRED_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
)
VERSION_PATTERN = re.compile(r"[A-Za-z]+[/ ]\d+(?:\.\d+)+")
LOGGER = logging.getLogger(__name__)


def load_targets(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as source:
        data = json.load(source)
    if isinstance(data, dict):
        if "resources" in data:
            data = data["resources"]
        elif "targets" in data:
            data = data["targets"]
        else:
            raise TypeError("Input JSON object must contain resources or targets")
    if not isinstance(data, list):
        raise TypeError("Input JSON must contain a list or a resources list")
    if not all(isinstance(item, dict) for item in data):
        raise TypeError("Each input resource must be an object")
    return data


def audit_resource(resource: dict[str, Any], strict: bool = False) -> dict[str, Any]:
    url = str(resource.get("url", resource.get("resource", resource.get("target", ""))))
    headers = resource.get("headers", {})
    if not isinstance(headers, dict):
        raise TypeError(f"Headers for {url or 'unnamed resource'} must be an object")
    normalized = {str(key).lower(): str(value) for key, value in headers.items()}
    missing = [
        header for header in REQUIRED_HEADERS if header.lower() not in normalized
    ]
    leaks = []
    for header in ("Server", "X-Powered-By"):
        value = normalized.get(header.lower(), "")
        if value and VERSION_PATTERN.search(str(value)):
            leaks.append(f"{header}: {value}")
    score = max(0, 100 - len(missing) * 20 - len(leaks) * 5)
    if not missing and not leaks:
        status = "PASS"
    elif strict or len(missing) >= 2 or score < 50:
        status = "FAIL"
    else:
        status = "WARN"
    return {
        "resource": url,
        "score": score,
        "status": status,
        "missing_headers": ", ".join(missing) or "None",
        "software_leaks": "; ".join(leaks) or "None",
    }


def audit_file(
    input_path: Path, output_path: Path, strict: bool = False
) -> list[dict[str, Any]]:
    LOGGER.info("Auditing HTTP response headers from %s", input_path)
    results = [audit_resource(item, strict) for item in load_targets(input_path)]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(
            destination, fieldnames=list(results[0]) if results else ["resource"]
        )
        writer.writeheader()
        writer.writerows(results)
    for result in results:
        if result["missing_headers"] != "None":
            LOGGER.warning(
                "%s is missing: %s", result["resource"], result["missing_headers"]
            )
        if result["software_leaks"] != "None":
            LOGGER.warning(
                "%s exposes software details: %s",
                result["resource"],
                result["software_leaks"],
            )
    return results


def print_report(results: list[dict[str, Any]], output_path: Path) -> None:
    print("\n=== TASK 2: HTTP Security Headers Audit ===")
    print("--- Audit results ---")
    print(f"{'Resource':<32} {'Score':>7}  {'Status':<6}")
    print("-" * 51)
    for result in results:
        resource = result["resource"].removeprefix("https://").removesuffix("/")
        print(f"{resource:<32} {result['score']:>3}/100  {result['status']:<6}")

    problems = [
        result
        for result in results
        if result["missing_headers"] != "None" or result["software_leaks"] != "None"
    ]
    if problems:
        print("\n=== Detected Problems ===")
        for result in problems:
            resource = result["resource"].removeprefix("https://").removesuffix("/")
            print(f"\n[WARNING] {resource}")
            if result["missing_headers"] != "None":
                print(f"  Missing headers: {result['missing_headers']}")
            if result["software_leaks"] != "None":
                print(f"  Software leaks: {result['software_leaks']}")
    print(f"\n[INFO] Audit report saved to:\n       {output_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit HTTP response security headers")
    parser.add_argument("--headers-file", type=Path, required=True)
    parser.add_argument("--output-csv", type=Path, required=True)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument(
        "--log-level", choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level), format="[%(levelname)s] %(message)s"
    )
    try:
        results = audit_file(args.headers_file, args.output_csv, args.strict)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        LOGGER.error("Analysis failed: %s", error)
        return 1
    print_report(results, args.output_csv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
