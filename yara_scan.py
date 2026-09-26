"""
YARA Scanner — scans a PE binary against Elastic protections-artifacts rules.

Modes:
  Interactive (default):  coloured console output with detection cards.
  JSON (--json):          machine-readable JSON to stdout (progress on stderr).
"""

import yara
import sys
import os
import io
import json
import math
import time
import argparse
from pathlib import Path
from collections import Counter

# ── colours (ANSI) ──────────────────────────────────────────────────────────

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
BG_RED  = "\033[41m"

SEV_COLOUR = {
    "critical": BG_RED + WHITE,
    "high":     RED,
    "medium":   YELLOW,
    "low":      DIM,
    "unknown":  DIM,
}

# ── helpers ─────────────────────────────────────────────────────────────────

def file_entropy(path: str) -> float:
    data = open(path, "rb").read()
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def severity_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev, 4)


def format_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"

# ── detection card (interactive mode) ───────────────────────────────────────

BOX_W = 66

def detection_card(hit: dict):
    sev       = hit.get("severity", "unknown")
    sev_col   = SEV_COLOUR.get(sev, DIM)
    rule_name = hit["rule"]
    source    = hit["file"]
    tags      = ", ".join(hit.get("tags", [])) or "none"
    strings   = hit.get("strings", [])

    print(f"\n  {RED}┌─ DETECTION {'─' * (BOX_W - 14)}┐{RESET}")
    print(f"  {RED}│{RESET} {BOLD}Rule:{RESET}     {rule_name:<{BOX_W - 12}}{RED}│{RESET}")
    print(f"  {RED}│{RESET} Source:   {source:<{BOX_W - 12}}{RED}│{RESET}")
    print(f"  {RED}│{RESET} Severity: {sev_col}{sev:<{BOX_W - 12}}{RESET}{RED}│{RESET}")
    print(f"  {RED}│{RESET} Tags:     {tags:<{BOX_W - 12}}{RED}│{RESET}")

    if strings:
        print(f"  {RED}│{RESET} Strings:  {len(strings)} matched{' ' * (BOX_W - 22)}{RED}│{RESET}")
        for s in strings[:5]:
            ident  = s.get("identifier", "?")
            offset = s.get("offset", "?")
            data   = s.get("data", "")
            if len(data) > 40:
                data = data[:37] + "..."
            line = f"   {ident} @ 0x{offset:X}: {data}" if isinstance(offset, int) else f"   {ident}: {data}"
            print(f"  {RED}│{RESET}   {DIM}{line:<{BOX_W - 6}}{RESET}{RED}│{RESET}")
        if len(strings) > 5:
            more = f"   ... and {len(strings) - 5} more"
            print(f"  {RED}│{RESET}   {DIM}{more:<{BOX_W - 6}}{RESET}{RED}│{RESET}")

    meta = hit.get("meta", {})
    desc = meta.get("description", "")
    if desc:
        if len(desc) > BOX_W - 12:
            desc = desc[:BOX_W - 15] + "..."
        print(f"  {RED}│{RESET} {DIM}{desc:<{BOX_W - 4}}{RESET}{RED}│{RESET}")

    print(f"  {RED}└{'─' * (BOX_W - 2)}┘{RESET}")

# ── clean card ──────────────────────────────────────────────────────────────

def clean_card(scanned: int, errors: int, elapsed: float):
    print(f"\n  {GREEN}┌─ RESULT {'─' * (BOX_W - 11)}┐{RESET}")
    print(f"  {GREEN}│{RESET}  {GREEN}{BOLD}CLEAN — no YARA signatures matched{' ' * (BOX_W - 38)}{RESET}{GREEN}│{RESET}")
    print(f"  {GREEN}│{RESET}  Rules scanned: {scanned:<{BOX_W - 21}}{GREEN}│{RESET}")
    if errors:
        print(f"  {GREEN}│{RESET}  Parse errors:  {errors} (non-critical){' ' * (BOX_W - 37)}{GREEN}│{RESET}")
    print(f"  {GREEN}│{RESET}  Elapsed:       {elapsed:.1f}s{' ' * (BOX_W - 22)}{GREEN}│{RESET}")
    print(f"  {GREEN}└{'─' * (BOX_W - 2)}┘{RESET}")

# ── scanner ─────────────────────────────────────────────────────────────────

def scan(binary_path: str, rules_dir: str, json_mode: bool = False) -> dict:
    out = sys.stderr if json_mode else sys.stdout
    rule_files = sorted(Path(rules_dir).rglob("*.yar"))

    if not rule_files:
        msg = f"No .yar files found in {rules_dir}"
        if json_mode:
            return {"status": "error", "message": msg}
        print(f"  {RED}[-] {msg}{RESET}", file=out)
        return {"status": "error", "message": msg}

    entropy = round(file_entropy(binary_path), 2)
    fsize   = os.path.getsize(binary_path)

    if not json_mode:
        print(f"  {CYAN}Binary:{RESET}  {binary_path}")
        print(f"  {CYAN}Size:{RESET}    {format_size(fsize)}")
        print(f"  {CYAN}Entropy:{RESET} {entropy}/8.0", end="")
        if entropy > 7.5:
            print(f"  {RED}(likely packed){RESET}")
        elif entropy > 7.0:
            print(f"  {YELLOW}(elevated — possible packing){RESET}")
        else:
            print(f"  {GREEN}(normal){RESET}")
        print(f"  {CYAN}Rules:{RESET}   {len(rule_files)} files from {rules_dir}")
        print(f"  {DIM}{'─' * 60}{RESET}")

    hits   = []
    errors = []
    t0     = time.time()

    for i, rf in enumerate(rule_files, 1):
        if not json_mode and i % 100 == 0:
            print(f"\r  Scanning... {i}/{len(rule_files)}", end="", flush=True, file=out)
        try:
            rules   = yara.compile(filepath=str(rf))
            matches = rules.match(binary_path)
            for m in matches:
                string_details = []
                for string_match in m.strings:
                    for instance in string_match.instances:
                        string_details.append({
                            "identifier": string_match.identifier,
                            "offset":     instance.offset,
                            "data":       instance.plaintext().decode("utf-8", errors="replace"),
                        })

                hit = {
                    "rule":      m.rule,
                    "namespace": m.namespace,
                    "file":      rf.name,
                    "tags":      list(m.tags),
                    "meta":      {k: str(v) for k, v in m.meta.items()} if m.meta else {},
                    "severity":  m.meta.get("severity", "unknown") if m.meta else "unknown",
                    "strings":   string_details,
                }
                hits.append(hit)

                if not json_mode:
                    print(f"\r{' ' * 40}\r", end="")
                    detection_card(hit)
        except yara.SyntaxError:
            errors.append(rf.name)
        except Exception as e:
            errors.append(f"{rf.name}: {e}")

    elapsed = time.time() - t0

    if not json_mode:
        print(f"\r{' ' * 40}\r", end="")
        if not hits:
            clean_card(len(rule_files) - len(errors), len(errors), elapsed)
        else:
            hits.sort(key=lambda h: severity_rank(h["severity"]))
            sev_counts = Counter(h["severity"] for h in hits)
            print(f"\n  {RED}{BOLD}DETECTED — {len(hits)} YARA signature(s) matched{RESET}")
            for sev, cnt in sorted(sev_counts.items(), key=lambda x: severity_rank(x[0])):
                col = SEV_COLOUR.get(sev, DIM)
                print(f"    {col}{sev}: {cnt}{RESET}")
            if errors:
                print(f"  {DIM}{len(errors)} rule file(s) had parse errors (non-critical){RESET}")
            print(f"  {DIM}Elapsed: {elapsed:.1f}s{RESET}")

    return {
        "status":        "clean" if not hits else "detected",
        "binary":        binary_path,
        "size_bytes":    fsize,
        "entropy":       entropy,
        "rules_scanned": len(rule_files) - len(errors),
        "rules_errors":  len(errors),
        "hits":          len(hits),
        "details":       hits,
        "elapsed_sec":   round(elapsed, 2),
        "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

# ── CLI ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="YARA scanner for Elastic protections-artifacts")
    ap.add_argument("binary", help="path to PE binary")
    ap.add_argument("rules_dir", nargs="?", default=r"C:\tools\protections-artifacts\yara\rules",
                    help="path to YARA rules directory")
    ap.add_argument("--json", dest="json_mode", action="store_true",
                    help="output JSON to stdout (progress on stderr)")
    args = ap.parse_args()

    if not os.path.isfile(args.binary):
        print(f"Binary not found: {args.binary}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(args.rules_dir):
        print(f"Rules directory not found: {args.rules_dir}", file=sys.stderr)
        sys.exit(1)

    result = scan(args.binary, args.rules_dir, json_mode=args.json_mode)

    if args.json_mode:
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        report_dir = "results"
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, f"yara-{time.strftime('%Y%m%d-%H%M%S')}.json")
        with open(report_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n  {DIM}Report saved: {report_path}{RESET}")

    sys.exit(0 if result["status"] == "clean" else 1)


if __name__ == "__main__":
    main()
