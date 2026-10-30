# ***👩‍🏫 Instructor Guide: PHP2Shell Vault***



---
---
---



## ***✅ Validate the stack***

```console
docker compose up --build -d
docker compose ps
docker compose exec php php -v
docker compose exec php php /opt/workshop/Script01_CheckVault.php
docker compose exec php ledger records
```

Expect PHP 8.4.26, a healthy vault, the public landing page at `127.0.0.1:8080`, a JSON proof from the wallet command, and account records from `ledger records`. Only nginx publishes a host port. The `docker compose exec` commands are instructor diagnostics that bypass exploitation.

Run the student PoC with `python PoC/Script01_Php2Shell.py --url http://127.0.0.1:8080/php-version.php`. A successful run should report verified command execution and include the vault response. The exploit is timing and build sensitive; retain the pinned PHP image, worker count, and memory settings when preparing the class. Verify a full run on the same hardware students will use before assigning it.

---

### Observed local validation

On the Windows Docker Desktop host used to build this workshop, the pinned PHP binary reported SHA-256 `5123326076cd3e77bf5e9f97e8f63b7368f7bfa18b37da7a749e29cc1342d437`, `memory_limit=128M`, and enabled session upload progress. Two consecutive later PoC runs reached both address leaks and returned `execution_proof_verified=true` and `vault_proof_seen=true`. The saved `Final.json` reports also reported HTTP 200, a fresh nonce, `id`, a `print-flag` hash, and a complete response. This verifies the full local path on that host; it does not make every attempt deterministic.

After adding the records route, a local `ledger records` diagnostic returned the account JSON, and `Script02_LocalCommand.py --command "ledger records" --attempts 5` returned a fresh nonce, the records, `:OK`, and both selected-command verification fields set to true. The guided PoC was rerun afterward and reached `execution_proof_verified=true` plus `vault_proof_seen=true` twice, with intervening heap and code race misses. This validates the current student route on that host without implying every attempt will succeed.

Earlier runs on the same stack produced three useful classroom outcomes: an OOM producer with only ordinary 32-byte consumer cookies, a successful heap leak followed by no strict code address, and both leaks followed by a final OOM response without execution markers. Each is a race or callback miss. Students should name the first failed stage, preserve its report, and retry on the running stack without resetting the vault.

A later selected-command run executed `id` and returned its completion marker, then the PHP container exited with code 139. That code indicates a segmentation fault; nginx subsequently returned 502 for new requests. The PHP service now has `restart: on-failure`, and the second PoC waits for preflight before retrying. Existing containers need `docker compose up -d --force-recreate php` once to pick up the policy. This preserves the vault volume.



---
---
---



## ***🧭 Teaching checkpoints***

1. Identify nginx, PHP CLI server workers, and the private vault.
2. Explain both CVEs at the PHP request lifecycle level.
3. Trace the producer and consumer requests and why a repeated worker matters.
4. Show the evidence checks for heap address, code address, and `zif_system` callback.
5. Follow the post-compromise route from PHP to the vault: operator note, runtime key, `ledger records`, then wallet proof.



---
---
---



## ***🗣️ Presentation and self-guided pacing***

| Approximate block | Instructor slide or demo | Student work while you present |
|---|---|---|
| 0–10 min | Browser → nginx → PHP → private vault | Start Compose, draw the network, run the target probe |
| 10–25 min | Request startup, OOM, worker reuse, and the two CVE groups | Read `Script01_VulnerabilityMechanics.md`; answer its questions |
| 25–45 min | Producer, consumers, heap and code disclosures | Work through `Script02_CodeWalkthrough.md`; run guided PoC and inspect reports |
| 45–60 min | Forged callback and post-compromise vault route | Explain execution markers, inspect the operator clue, run selected command |
| 60–75 min | Binary identity, ELF symbols, ASLR and version changes | Complete the offset checks and surprise-version worksheet |

Pause after each block for students to show one observation, not just a proof string. A group that misses a race can use its saved JSON report as a valid debugging exercise while others continue.



---
---
---



## ***🧾 Answer key and evidence standards***

- The browser reaches only nginx on `127.0.0.1:8080`. PHP has access to both the front network and private vault network. `vault:9000` is not published to the host. `docker compose ps` may display `9000/tcp` for the PHP image because the upstream FPM image declares that port as metadata; this lab starts the CLI server on 8000 and does not publish PHP port 9000.
- `Script02_BuildIdentity.py` runs a separate **CLI** process, so its `sapi=cli` is expected. The HTTP landing page runs under `cli-server`; this difference is a useful check that students know which process they measured.
- The nested multipart request produces a 128 MiB PHP OOM. That fatal alone proves memory pressure, not a leak or RCE. A 256-byte cookie with agreeing heap pointers and a 16-byte cookie with a matching code fingerprint are separate evidence.
- The session upload-progress producer/consumer lifecycle maps to **CVE-2026-109619** in the PHP advisory. **CVE-2026-109618** covers OOM corruption around incomplete initialization; nested multipart OOM is a related technique, not proof that this CLI-server PoC exercises the advisory's mod_php route.
- For the guided PoC, require `execution_proof_verified=true` **and** `vault_proof_seen=true`. For the selected-command PoC, require a fresh nonce and `:OK` completion marker plus the command output. A PHP OOM page, nginx 502, or exit code 139 is not execution proof.
- The known binary SHA-256 and low-21-bit fingerprint identify this validated amd64 build, but neither proves the forged structure is correct on a new version. If the PHP process restarts, its ASLR addresses change; students must acquire fresh leaks.
- The real ELF inspector found `zval_ptr_dtor=0x712930` and an aligned load bias from a saved code leak. It did **not** find an exposed `zif_system` symbol. Treat the `-0x204BC0` delta as validated by the successful local callback run, not as independently recovered from this stripped symbol table. Require new symbol or debugger evidence before using it on a surprise build.

The independent student sequence is in [Student.md](Student.md). Use [Analysis/Script01_VulnerabilityMechanics.md](Analysis/Script01_VulnerabilityMechanics.md) as the CVE explanation, [Analysis/Script02_CodeWalkthrough.md](Analysis/Script02_CodeWalkthrough.md) beside the code, and [Analysis/Script03_Debugging.md](Analysis/Script03_Debugging.md) when a run misses a worker. The five read-only scripts in `Analysis/` give students concrete observations while you present. The supplied PoC follows the session upload-progress lifecycle case described under CVE-2026-109619. CVE-2026-109618 is the separate OOM-corruption comparison topic; do not label every OOM in the PoC as exploitation of that CVE.
The offset extension is [Analysis/Script04_OffsetsAndPorting.md](Analysis/Script04_OffsetsAndPorting.md). Its ELF inspector shows symbol values when exposed, while `PoC/Script02_LocalCommand.py` records the exact running binary hash and runs a selected local command using the same exploit stages. A different hash or PHP version produces a visible warning, not an abort. The script still uses the PHP 8.4.26 calibration and does not automatically port the exploit to other versions.

For the surprise task, use [Analysis/Script06_SurpriseVersion.md](Analysis/Script06_SurpriseVersion.md) as the worksheet. Choose the candidate deliberately: both PHP advisories list 8.4.27 as patched, so a patched release is appropriate only if the expected answer can be an evidence-based non-exploitability conclusion. If you want students to attempt a working port, provide a candidate build that you have independently confirmed still reaches the relevant session lifecycle path. Grade the measurements and reasoning, not a guessed address or a process crash.

The vault generates a new key and proof every time its process starts. `docker compose restart vault` rotates both while preserving the Docker volume; `docker compose up -d php` restarts only PHP and keeps the existing proof. Do not distribute a run transcript containing a prior proof as a student answer.
