#!/usr/bin/env python3
"""Read-only Docker probe for the pinned PHP binary and relevant settings."""
from __future__ import annotations

import subprocess
import sys

COMMANDS = (
	("Binary SHA-256", ["docker", "compose", "exec", "-T", "php",
					"sha256sum", "/usr/local/bin/php"]),
	("PHP settings", ["docker", "compose", "exec", "-T", "php", "php", "-r",
					"echo 'version=',PHP_VERSION,PHP_EOL;"
					"echo 'sapi=',PHP_SAPI,PHP_EOL;"
					"foreach (['memory_limit','session.upload_progress.enabled',"
					"'session.upload_progress.cleanup'] as $k) "
					"{echo $k,'=',ini_get($k),PHP_EOL;}"]),
)


def main() -> int:
	"""Read the PHP ELF hash and settings from the running local container."""
	for label, command in COMMANDS:
		print(f"\n[{label}]")
		completed = subprocess.run(command, text=True, stdout=subprocess.PIPE,
								stderr=subprocess.PIPE, check=False)
		print(completed.stdout.strip())
		if completed.returncode:
			print(completed.stderr.strip(), file=sys.stderr)
			return completed.returncode
	print("\nCompare this hash only with the same image and architecture.")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
