# ***🛠️ Script03 - Debugging a Workshop Run***



---
---
---



## ***First establish the target***

```console
python Analysis/Script01_TargetProbe.py
python Analysis/Script02_BuildIdentity.py
```

Check PHP 8.4.26, the binary hash, `memory_limit=128M`, and enabled upload progress. A different image, architecture, memory limit, or worker count can invalidate the PoC's measured heap and code layout. The target probe makes ordinary GET requests only.



---
---
---



## ***Then inspect the exact failed stage***

The PoC creates `PoC-Run-<timestamp>/` and writes `Run.json`. It also writes `Heap.json`, `Code.json`, and `Final.json` if those stages were reached. The report readers still accept earlier lowercase run files.

```console
python Analysis/Script03_RunReport.py PoC-Run-<timestamp>
```

| Observation | What it means | Next check |
|---|---|---|
| Preflight error | The endpoint or PHP header does not match | Confirm `docker compose ps`, the URL and PHP image |
| Producer `oom=false` | The expected fatal was not observed | Check PHP memory limit, upload progress, and response body |
| Ordinary 32-byte cookies only | Consumers missed the stale worker or allocation shape | Check four-worker setting and the producer response; retry |
| Several or no strict addresses | Leak validation is inconclusive | Inspect cookie lengths and stage JSON; do not feed guessed addresses to the final stage |
| `execution_proof_verified=false` | The final response lacks the guided nonce/id/hash evidence or the selected-command nonce/`:OK` markers | Inspect `Final.json`, mode, status and response completeness |
| `failure_reason` says final PHP OOM only | The final request reached PHP, but no callback output was observed | Keep this as a final-stage miss; retry with fresh leaks and do not diagnose the vault from this response |
| Execution true, vault false | The command ran but the vault response was not seen | Ask the instructor to verify the mounted key and `print-flag` path |
| Next run says `service "php" is not running` | The PHP container exited or was stopped after a previous run | Save `docker compose ps -a` and `docker compose logs --tail=50 php`; apply the current Compose restart policy with `docker compose up -d --force-recreate php` without `down -v` |
| PHP exits with code 139 and nginx returns 502 | A worker handling malformed memory state crashed the PHP CLI server process | Keep the run report; the PHP service now uses `restart: on-failure`. Wait for the endpoint to recover before retrying |

The workshop's first full validation showed all three nonfatal misses on the same running stack: heap consumers with only 32-byte cookies, a code stage with no strict address, and a final response containing only the PHP OOM fatal. Later runs returned both execution and vault proof markers. These are distinct observations; do not label a final OOM alone as code execution.

A selected-command run also produced a verified `id` response followed by PHP container exit code 139. Subsequent attempts on that stopped container got nginx 502 responses, which cannot be interpreted as exploit-stage misses. The current Compose file restarts PHP on failure, and the selected-command PoC waits for preflight to pass between bounded attempts. Recreate the PHP service once after updating this file so Docker applies the new restart policy.

The raw `.http` and `.body` files can contain the generated proof. Keep them local and share only redacted observations. A failed race may be retried, but record the first failed assertion before doing so.



---
---
---



## ***Instructor-only post-compromise check***

```console
docker compose exec php php /opt/workshop/Script01_CheckVault.php
```

This verifies the private vault route without exploiting PHP. It is a diagnostic, not a student shortcut. If it fails, investigate the vault health and shared volume before debugging the memory corruption stage.
