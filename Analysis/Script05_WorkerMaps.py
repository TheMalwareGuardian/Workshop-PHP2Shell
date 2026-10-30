#!/usr/bin/env python3
"""Read PHP worker ELF mappings and compare one saved code leak with live workers.

The comparison is meaningful only before the PHP container restarts. The PoC may crash PID 1, so a saved pointer from an earlier container can have a different ASLR base even when the binary hash has not changed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

# The shell runs inside only the local PHP container. It reads /proc maps; no debugger attach, ptrace permission, or service configuration is needed.
MAPS_COMMAND = (
	'for d in /proc/[0-9]*; do '
	'p=${d##*/}; [ -r "$d/maps" ] || continue; '
	'awk -v p="$p" \'$6=="/usr/local/bin/php" '
	'{print p, $1, $3}\' "$d/maps"; '
	'done'
)


def parse_mappings(output: str) -> dict[int, tuple[int, list[tuple[int, int]]]]:
	"""Return each PID's ELF load bias and actual mapped address ranges."""
	bases: dict[int, int] = {}
	spans: dict[int, list[tuple[int, int]]] = {}
	for line in output.splitlines():
		parts = line.split()
		if len(parts) != 3 or "-" not in parts[1]:
			continue
		pid = int(parts[0])
		start_text, end_text = parts[1].split("-", 1)
		start, end = int(start_text, 16), int(end_text, 16)
		file_offset = int(parts[2], 16)
		bias = start - file_offset
		bases[pid] = min(bases.get(pid, bias), bias)
		spans.setdefault(pid, []).append((start, end))
	return {pid: (bias, spans[pid]) for pid, bias in bases.items()}


def main() -> int:
	"""Compare a saved code pointer only with currently running PHP mappings."""
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--run-dir", type=Path,
						help="Compare with a run's Code.json before PHP restarts")
	args = parser.parse_args()
	completed = subprocess.run(
		["docker", "compose", "exec", "-T", "php", "sh", "-c", MAPS_COMMAND],
		capture_output=True, text=True, check=False)
	if completed.returncode:
		print(completed.stderr.strip(), file=sys.stderr)
		return completed.returncode
	bases = parse_mappings(completed.stdout)
	if not bases:
		print("No readable PHP executable mappings were found")
		return 1
	leaked = None
	if args.run_dir:
		code_report = args.run_dir / "Code.json"
		if not code_report.exists():
			code_report = args.run_dir / "code.json"  # earlier saved runs
		report = json.loads(
			code_report.read_text(encoding="utf-8"))
		candidates = report.get("candidate_addresses") or []
		if len(candidates) != 1:
			print("Run must contain exactly one strict code candidate")
			return 1
		leaked = int(candidates[0], 16)
		print(f"Saved zval_ptr_dtor pointer: {leaked:#x}")
	print("PID  ELF load bias  Saved pointer offset")
	for pid, (bias, spans) in sorted(bases.items()):
		if leaked is None:
			display = "not supplied"
		elif any(start <= leaked < end for start, end in spans):
			display = f"{leaked - bias:#x}"
		else:
			display = "outside current PHP mappings"
		print(f"{pid:>3}  {bias:#014x}  {display}")
	print("A matching offset is a live mapping check, not proof that the "
		"forged heap structure or callback will work.")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
