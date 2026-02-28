#!/usr/bin/env python3
"""
Coverage Branch Analysis Tool for Zaseon

Parses Forge LCOV output and identifies uncovered branches,
generating targeted test recommendations for improving coverage.

Usage:
    python scripts/analyze_coverage.py
    python scripts/analyze_coverage.py --lcov lcov.info
    python scripts/analyze_coverage.py --threshold 85 --top 20
    python scripts/analyze_coverage.py --module contracts/security
"""

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BranchInfo:
    """Single branch point."""
    line: int
    block: int
    branch: int
    hits: int  # 0 = uncovered, >0 = covered, -1 = unreachable


@dataclass
class FunctionInfo:
    """Function‐level coverage data."""
    name: str
    start_line: int
    hits: int


@dataclass
class FileCoverage:
    """Aggregated coverage for one source file."""
    path: str
    lines_found: int = 0
    lines_hit: int = 0
    branches_found: int = 0
    branches_hit: int = 0
    functions_found: int = 0
    functions_hit: int = 0
    uncovered_lines: List[int] = field(default_factory=list)
    uncovered_branches: List[BranchInfo] = field(default_factory=list)
    uncovered_functions: List[str] = field(default_factory=list)


@dataclass
class TestRecommendation:
    """Auto-generated test suggestion."""
    file: str
    function: str
    branch_line: int
    kind: str  # "branch", "function", "line"
    description: str
    priority: int  # 1=critical 2=high 3=medium


# ---------------------------------------------------------------------------
# LCOV parser
# ---------------------------------------------------------------------------

def parse_lcov(lcov_path: Path) -> Dict[str, FileCoverage]:
    """
    Parse an LCOV info file into per‐file coverage records.

    Supports the standard LCOV record types:
        SF, FNF, FNH, FN, FNDA, LF, LH, DA, BRF, BRH, BRDA, end_of_record
    """
    files: Dict[str, FileCoverage] = {}
    current: Optional[FileCoverage] = None

    if not lcov_path.exists():
        print(f"Error: LCOV file not found at {lcov_path}")
        sys.exit(1)

    with open(lcov_path) as fh:
        for raw_line in fh:
            line = raw_line.strip()

            # Source file
            if line.startswith("SF:"):
                path = line[3:]
                current = FileCoverage(path=path)
                continue

            if current is None:
                continue

            # Function names
            if line.startswith("FN:"):
                parts = line[3:].split(",", 1)
                if len(parts) == 2:
                    start_line = int(parts[0])
                    func_name = parts[1]
                    # stored temporarily; FNDA gives hit count
                continue

            # Function hit data
            if line.startswith("FNDA:"):
                parts = line[5:].split(",", 1)
                if len(parts) == 2:
                    hits = int(parts[0])
                    func_name = parts[1]
                    if hits == 0:
                        current.uncovered_functions.append(func_name)
                continue

            # Function summary
            if line.startswith("FNF:"):
                current.functions_found = int(line[4:])
                continue
            if line.startswith("FNH:"):
                current.functions_hit = int(line[4:])
                continue

            # Line data
            if line.startswith("DA:"):
                parts = line[3:].split(",")
                if len(parts) >= 2:
                    line_no = int(parts[0])
                    hits = int(parts[1])
                    if hits == 0:
                        current.uncovered_lines.append(line_no)
                continue

            # Line summary
            if line.startswith("LF:"):
                current.lines_found = int(line[3:])
                continue
            if line.startswith("LH:"):
                current.lines_hit = int(line[3:])
                continue

            # Branch data
            if line.startswith("BRDA:"):
                parts = line[5:].split(",")
                if len(parts) >= 4:
                    br_line = int(parts[0])
                    br_block = int(parts[1])
                    br_branch = int(parts[2])
                    try:
                        br_hits = int(parts[3])
                    except ValueError:
                        br_hits = -1  # "-" means unreachable
                    branch = BranchInfo(br_line, br_block, br_branch, br_hits)
                    if br_hits == 0:
                        current.uncovered_branches.append(branch)
                continue

            # Branch summary
            if line.startswith("BRF:"):
                current.branches_found = int(line[4:])
                continue
            if line.startswith("BRH:"):
                current.branches_hit = int(line[4:])
                continue

            # End of record
            if line == "end_of_record":
                if current.path:
                    files[current.path] = current
                current = None
                continue

    return files


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def _pct(hit: int, found: int) -> float:
    return (hit / found * 100) if found > 0 else 100.0


def rank_files(files: Dict[str, FileCoverage]) -> List[Tuple[str, float, FileCoverage]]:
    """Return files sorted by combined coverage (ascending = worst first)."""
    ranked: List[Tuple[str, float, FileCoverage]] = []
    for path, fc in files.items():
        line_pct = _pct(fc.lines_hit, fc.lines_found)
        branch_pct = _pct(fc.branches_hit, fc.branches_found)
        combined = (line_pct + branch_pct) / 2
        ranked.append((path, combined, fc))
    ranked.sort(key=lambda x: x[1])
    return ranked


def generate_recommendations(
    files: Dict[str, FileCoverage],
    top_n: int = 20,
) -> List[TestRecommendation]:
    """
    Generates test recommendations for the worst‐covered branches
    and functions across the project.
    """
    recs: List[TestRecommendation] = []

    for path, fc in files.items():
        # Uncovered functions → high priority
        for func_name in fc.uncovered_functions:
            recs.append(TestRecommendation(
                file=path,
                function=func_name,
                branch_line=0,
                kind="function",
                description=f"Function `{func_name}` in {Path(path).name} has zero calls. "
                            f"Add a test that invokes this function.",
                priority=1,
            ))

        # Uncovered branches
        for br in fc.uncovered_branches:
            recs.append(TestRecommendation(
                file=path,
                function="",
                branch_line=br.line,
                kind="branch",
                description=f"Branch at line {br.line} (block {br.block}, "
                            f"branch {br.branch}) in {Path(path).name} is never taken. "
                            f"Add a test exercising this path.",
                priority=2,
            ))

    recs.sort(key=lambda r: (r.priority, r.file, r.branch_line))
    return recs[:top_n]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_summary(files: Dict[str, FileCoverage], module_filter: Optional[str] = None):
    """Print per‐file and aggregate coverage summary."""
    filtered = {
        p: fc for p, fc in files.items()
        if module_filter is None or module_filter in p
    }

    if not filtered:
        print("No files matched the filter.")
        return

    total_lf = total_lh = total_bf = total_bh = total_ff = total_fh = 0

    print("\n" + "=" * 78)
    print("ZASEON – COVERAGE BRANCH ANALYSIS")
    print("=" * 78)

    ranked = rank_files(filtered)

    print(f"\n{'File':<50} {'Lines':>8} {'Branch':>8} {'Funcs':>8}")
    print("-" * 78)

    for path, combined, fc in ranked:
        lp = _pct(fc.lines_hit, fc.lines_found)
        bp = _pct(fc.branches_hit, fc.branches_found)
        fp = _pct(fc.functions_hit, fc.functions_found)
        short = path if len(path) <= 49 else "…" + path[-(48):]
        print(f"{short:<50} {lp:>7.1f}% {bp:>7.1f}% {fp:>7.1f}%")
        total_lf += fc.lines_found
        total_lh += fc.lines_hit
        total_bf += fc.branches_found
        total_bh += fc.branches_hit
        total_ff += fc.functions_found
        total_fh += fc.functions_hit

    print("-" * 78)
    print(
        f"{'TOTAL':<50} "
        f"{_pct(total_lh, total_lf):>7.1f}% "
        f"{_pct(total_bh, total_bf):>7.1f}% "
        f"{_pct(total_fh, total_ff):>7.1f}%"
    )
    print()


def print_recommendations(recs: List[TestRecommendation]):
    """Pretty‐print test recommendations."""
    if not recs:
        print("✅ No critical coverage gaps found!")
        return

    priority_labels = {1: "🔴 CRITICAL", 2: "🟡 HIGH", 3: "🟢 MEDIUM"}

    print("\n" + "=" * 78)
    print("TEST RECOMMENDATIONS")
    print("=" * 78)

    for i, rec in enumerate(recs, 1):
        label = priority_labels.get(rec.priority, "")
        print(f"\n  {i}. [{label}] {rec.kind.upper()}")
        print(f"     File:   {rec.file}")
        if rec.branch_line:
            print(f"     Line:   {rec.branch_line}")
        if rec.function:
            print(f"     Func:   {rec.function}")
        print(f"     Action: {rec.description}")

    print()


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Forge LCOV output and recommend coverage improvements"
    )
    parser.add_argument(
        "--lcov", default="lcov.info",
        help="Path to LCOV info file (default: lcov.info)",
    )
    parser.add_argument(
        "--threshold", type=float, default=85.0,
        help="Minimum overall line-coverage threshold in percent (default: 85)",
    )
    parser.add_argument(
        "--top", type=int, default=20,
        help="Number of recommendations to show (default: 20)",
    )
    parser.add_argument(
        "--module", default=None,
        help="Filter to a specific directory, e.g. contracts/security",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output recommendations as JSON for CI integration",
    )

    args = parser.parse_args()

    lcov_path = Path(args.lcov)
    files = parse_lcov(lcov_path)

    if not files:
        print("Error: No coverage records found in LCOV file.")
        sys.exit(1)

    # Summary
    print_summary(files, module_filter=args.module)

    # Recommendations
    filtered = {
        p: fc for p, fc in files.items()
        if args.module is None or args.module in p
    }
    recs = generate_recommendations(filtered, top_n=args.top)
    print_recommendations(recs)

    # JSON output
    if args.json:
        import json
        data = [
            {
                "file": r.file,
                "function": r.function,
                "line": r.branch_line,
                "kind": r.kind,
                "priority": r.priority,
                "description": r.description,
            }
            for r in recs
        ]
        print(json.dumps(data, indent=2))

    # Threshold check
    total_lf = sum(fc.lines_found for fc in filtered.values())
    total_lh = sum(fc.lines_hit for fc in filtered.values())
    overall = _pct(total_lh, total_lf)

    if overall < args.threshold:
        print(f"❌ FAILED: Line coverage {overall:.1f}% < threshold {args.threshold}%")
        sys.exit(1)
    else:
        print(f"✅ PASSED: Line coverage {overall:.1f}% ≥ threshold {args.threshold}%")
        sys.exit(0)


if __name__ == "__main__":
    main()
