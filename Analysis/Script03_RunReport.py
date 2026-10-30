#!/usr/bin/env python3
"""Summarize PoC evidence without printing the vault key or final proof."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_json(path: Path) -> dict:
	"""Read a stage report; raw HTTP responses stay off the terminal."""
	return json.loads(path.read_text(encoding="utf-8"))


def artifact(folder: Path, current: str, earlier: str) -> Path:
	"""Read the new capitalized name, or an earlier saved lowercase run."""
	preferred = folder / current
	return preferred if preferred.exists() else folder / earlier


def main() -> int:
	"""Summarize stage evidence without revealing the runtime vault proof."""
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("run_dir", type=Path, help="PoC-Run-... directory")
	args = parser.parse_args()
	folder = args.run_dir.resolve()
	run = read_json(artifact(folder, "Run.json", "run.json"))
	print(f"Target: {run.get('target', 'unknown')}")
	print(f"Error: {run.get('error', 'none')}")
	for name in ("Heap", "Code"):
		path = artifact(folder, f"{name}.json", f"{name.lower()}.json")
		if not path.exists():
			print(f"{name}: no stage report")
			continue
		stage = read_json(path)
		producer = stage.get("producer") or {}
		consumers = stage.get("consumers") or []
		lengths = [item.get("cookie_bytes") for item in consumers]
		print(f"{name}: OOM={producer.get('oom')} "
			f"consumers={len(consumers)} cookie lengths={lengths} "
			f"strict candidates={len(stage.get('candidate_addresses') or [])}")
	path = artifact(folder, "Final.json", "final.json")
	if path.exists():
		final = read_json(path)
		print("final: execution proof="
			f"{final.get('execution_proof_verified')} "
			f"command mode={final.get('custom_command_mode', False)} "
			f"completion marker={final.get('command_done_seen', False)} "
			f"vault proof seen={final.get('vault_proof_seen')}")
	else:
		print("final: no callback request report")
	print("Raw HTTP files can contain the runtime proof; keep this directory private.")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
