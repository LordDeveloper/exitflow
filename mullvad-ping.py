#!/usr/bin/env python3
"""Ping Mullvad WireGuard relays and rank by latency. Single-binary friendly."""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import platform
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

APP_NAME = "mullvad-ping"
BUNDLED_RELAYS = "relays.json"


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def resource_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return app_dir()


def load_relays(source: str | None) -> list[dict]:
    candidates: list[Path] = []
    if source:
        candidates.append(Path(source))
    else:
        candidates.extend(
            [
                resource_dir() / BUNDLED_RELAYS,
                app_dir() / BUNDLED_RELAYS,
                app_dir() / "storage" / BUNDLED_RELAYS,
                Path.cwd() / BUNDLED_RELAYS,
                Path.cwd() / "storage" / BUNDLED_RELAYS,
            ]
        )

    for path in candidates:
        if not path.is_file():
            continue
        with path.open(encoding="utf-8-sig") as handle:
            rows = json.load(handle)
        print(f"Loaded {len(rows)} relays from {path}")
        return rows

    raise FileNotFoundError(
        "relays.json not found. Rebuild the binary with the catalog embedded, "
        "or pass --source /path/to/relays.json"
    )


def normalize_relays(rows: list[dict], country: str | None, city: str | None) -> list[dict]:
    country_q = (country or "").strip().lower()
    city_q = (city or "").strip().lower()
    relays = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or row.get("active") is False:
            continue
        hostname = str(row.get("hostname") or "").strip()
        try:
            ip = str(ipaddress.IPv4Address(row.get("ipv4_addr_in")))
        except (ValueError, TypeError):
            continue
        if not hostname or ip in seen:
            continue
        country_name = str(row.get("country_name") or "")
        city_name = str(row.get("city_name") or "")
        country_code = str(row.get("country_code") or "").lower()
        if country_q and country_q not in country_name.lower() and country_q != country_code:
            continue
        if city_q and city_q not in city_name.lower():
            continue
        seen.add(ip)
        relays.append(
            {
                "hostname": hostname,
                "ip": ip,
                "country": country_name,
                "city": city_name,
                "provider": str(row.get("provider") or ""),
            }
        )
    return relays


def ping_command(ip: str, count: int, timeout_sec: float) -> list[str]:
    system = platform.system().lower()
    timeout_ms = max(1, int(timeout_sec * 1000))
    if system == "windows":
        return ["ping", "-n", str(count), "-w", str(timeout_ms), ip]
    if system == "darwin":
        return ["ping", "-c", str(count), "-W", str(timeout_ms), ip]
    timeout_s = max(1, int(round(timeout_sec)))
    return ["ping", "-c", str(count), "-W", str(timeout_s), ip]


def parse_latencies(output: str) -> list[float]:
    return [float(match.group(1)) for match in re.finditer(r"time[=<]([\d.]+)\s*ms", output, re.IGNORECASE)]


def ping_relay(relay: dict, count: int, timeout_sec: float) -> dict:
    command = ping_command(relay["ip"], count, timeout_sec)
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_sec * count + 5,
            check=False,
        )
        output = (completed.stdout or "") + "\n" + (completed.stderr or "")
        samples = parse_latencies(output)
        ok = completed.returncode == 0 and bool(samples)
        avg = statistics.mean(samples) if samples else None
        best = min(samples) if samples else None
        loss = None
        loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*packet\s*loss", output, re.IGNORECASE)
        if loss_match:
            loss = float(loss_match.group(1))
        elif samples:
            loss = max(0.0, (1 - (len(samples) / count)) * 100)
        return {
            **relay,
            "ok": ok,
            "avg": avg,
            "best": best,
            "loss": loss,
            "samples": len(samples),
            "elapsed": time.perf_counter() - started,
            "error": "" if ok else "no reply",
        }
    except subprocess.TimeoutExpired:
        return {
            **relay,
            "ok": False,
            "avg": None,
            "best": None,
            "loss": 100.0,
            "samples": 0,
            "elapsed": time.perf_counter() - started,
            "error": "timeout",
        }
    except OSError as error:
        return {
            **relay,
            "ok": False,
            "avg": None,
            "best": None,
            "loss": 100.0,
            "samples": 0,
            "elapsed": time.perf_counter() - started,
            "error": str(error),
        }


def format_ms(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value:.1f} ms"


def main() -> int:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Find the lowest-latency Mullvad WireGuard relays from this host.",
    )
    parser.add_argument("--source", help="Optional relays JSON path. Default: embedded relays.json")
    parser.add_argument("--country", help="Filter by country name or code, e.g. Germany / de")
    parser.add_argument("--city", help="Filter by city name, e.g. Frankfurt")
    parser.add_argument("--count", type=int, default=3, help="ICMP packets per relay (default: 3)")
    parser.add_argument("--timeout", type=float, default=1.5, help="Per-packet timeout seconds (default: 1.5)")
    parser.add_argument("--workers", type=int, default=64, help="Parallel ping workers (default: 64)")
    parser.add_argument("--top", type=int, default=30, help="How many best relays to print (default: 30)")
    parser.add_argument("--json-out", help="Optional path to write full ranked JSON results")
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be >= 1")
    if args.workers < 1:
        parser.error("--workers must be >= 1")

    try:
        relays = normalize_relays(load_relays(args.source), args.country, args.city)
    except FileNotFoundError as error:
        print(str(error), file=sys.stderr)
        return 1

    if not relays:
        print("No matching active IPv4 relays found.", file=sys.stderr)
        return 1

    print(f"Pinging {len(relays)} relays with {args.count} packet(s), workers={args.workers}...")
    results = []
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(ping_relay, relay, args.count, args.timeout) for relay in relays]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            done += 1
            if done % 25 == 0 or done == len(relays):
                print(f"  progress: {done}/{len(relays)}", flush=True)

    reachable = [row for row in results if row["ok"] and row["avg"] is not None]
    reachable.sort(
        key=lambda row: (
            row["avg"],
            row["best"] if row["best"] is not None else 1e9,
            row["hostname"],
        )
    )
    unreachable = sorted((row for row in results if not row["ok"]), key=lambda row: row["hostname"])

    print()
    print(f"Reachable: {len(reachable)} / {len(results)}")
    if reachable:
        best = reachable[0]
        print(
            f"Best overall: {best['hostname']} ({best['city']}, {best['country']}) "
            f"avg={format_ms(best['avg'])}"
        )
        print()
        print(f"{'#':>3}  {'avg':>9}  {'best':>9}  {'loss':>6}  hostname                 city / country")
        print("-" * 90)
        for index, row in enumerate(reachable[: max(1, args.top)], start=1):
            place = f"{row['city']} / {row['country']}".strip(" /")
            loss = f"{row['loss']:.0f}%" if row["loss"] is not None else "—"
            print(
                f"{index:>3}  {format_ms(row['avg']):>9}  {format_ms(row['best']):>9}  {loss:>6}  "
                f"{row['hostname']:<24} {place}"
            )
    else:
        print(
            "No relay answered ICMP. Many Mullvad hosts block ping; "
            "try another network or raise --timeout."
        )

    if args.json_out:
        payload = {
            "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reachable": reachable,
            "unreachable": unreachable,
        }
        out = Path(args.json_out)
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nWrote {out}")

    return 0 if reachable else 2


if __name__ == "__main__":
    raise SystemExit(main())
