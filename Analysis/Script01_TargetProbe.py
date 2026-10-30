#!/usr/bin/env python3
"""Read-only target probe for the local PHP2Shell workshop."""
from __future__ import annotations

import http.client
import re

HOST = "127.0.0.1"
PORT = 8080
PATH = "/php-version.php"


def main() -> int:
	"""Send ordinary GETs and show version and worker reuse without exploitation."""
	print(f"Target: http://{HOST}:{PORT}{PATH}")
	print("Request  Status  PHP header   Worker")
	workers: set[str] = set()
	for number in range(1, 7):
		connection = http.client.HTTPConnection(HOST, PORT, timeout=5)
		try:
			connection.request("GET", PATH, headers={"Connection": "close"})
			response = connection.getresponse()
			body = response.read(4096).decode("utf-8", "replace")
			match = re.search(r"^PID: (\d+)$", body, re.MULTILINE)
			worker = match.group(1) if match else "unknown"
			workers.add(worker)
			print(f"{number:>7}  {response.status:>6}  "
				f"{str(response.getheader('X-Powered-By')):12}  {worker}")
			if response.status != 200 or not body.startswith("PHP 8.4.26\n"):
				return 1
		finally:
			connection.close()
	print(f"Observed worker PIDs: {len(workers - {'unknown'})}")
	print("Repeated PIDs show reuse; differing PIDs show distribution across workers.")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
