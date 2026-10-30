# ***🧑‍🎓 Student Guide: PHP2Shell and the Vault***



---
---
---



## ***🎯 Objective***

Recover the runtime `PHP2SHELL{...}` proof from the private ledger vault by exploiting the local PHP service. Record what each stage proves; the final proof alone is not the full exercise.



---
---
---



## ***🚀 Setup***

Use a local **amd64** machine with Docker Desktop or Docker Engine plus Compose, and **Python 3.11 or newer** on the host. Run every command from the repository root. The Python scripts use only the standard library; no `pip install` step is needed. Allow Docker enough memory for the PHP service's 1 GiB container limit. The only published lab port is loopback `127.0.0.1:8080`.

```console
docker compose up --build -d
docker compose ps
```

Wait until `vault` is healthy and `web` and `php` are running. Open `http://127.0.0.1:8080/` and `http://127.0.0.1:8080/php-version.php`. The latter should show PHP 8.4.26. Write down the PHP version, SAPI, worker behavior and network path to the vault. Identify which services have published host ports.



---
---
---



## ***🧪 Investigation***

1. Read [Analysis/Script01_VulnerabilityMechanics.md](Analysis/Script01_VulnerabilityMechanics.md) and the two PHP advisories. Explain which request phases matter, why worker reuse matters, and which CVE the supplied PoC exercises.
2. Run `python Analysis/Script01_TargetProbe.py` and `python Analysis/Script02_BuildIdentity.py`. Record the version, worker observations, binary hash, memory limit, and upload-progress setting.
3. Read [Analysis/Script02_CodeWalkthrough.md](Analysis/Script02_CodeWalkthrough.md) with `PoC/Script01_Php2Shell.py` open. Answer each student task before running the PoC.
4. Run `python PoC/Script01_Php2Shell.py --url http://127.0.0.1:8080/php-version.php`. Then use `python Analysis/Script03_RunReport.py PoC-Run-<timestamp>` and [the debugging guide](Analysis/Script03_Debugging.md) to explain the observed stages. If a race fails, identify its first failed assertion before retrying.
5. Explain how execution in the PHP container reaches the private vault. Locate the operator note and key path in `Challenge/`. Explain how `print-flag` obtains the vault response.
6. Run `python Analysis/Script04_OffsetInspector.py` and read [the offset lesson](Analysis/Script04_OffsetsAndPorting.md). Compare exposed code symbols with the PoC constants. Then try `python PoC/Script02_LocalCommand.py --command "id"` and one other short command. Explain what a version or hash warning means and why the script's old offsets are not automatically adapted.
7. If the PHP process has not restarted, use `python Analysis/Script05_WorkerMaps.py --run-dir PoC-Run-<timestamp>` to compare the leaked code pointer with a live mapping. Complete [the surprise-version worksheet](Analysis/Script06_SurpriseVersion.md) when the instructor provides another build. If ELF symbols are stripped, say so and use the available run evidence without inventing missing offsets.



---
---
---



## ***🔐 From the PHP foothold to the vault***

The guided PoC performs the last hop for you: after command execution, it invokes `print-flag` inside PHP. Its successful result requires both `execution_proof_verified=true` and `vault_proof_seen=true`. Read `Final.json` for those checks and `Final.Response.body` for the vault JSON; these files are inside the run directory printed by the PoC.

For example, if the PoC prints `PoC-Run-20261028T165056879386Z\Final.Response.http`, use `PoC-Run-20261028T165056879386Z` as the run directory in `Script03_RunReport.py`. For the selected-command PoC, use the specific successful `Attempt-XX` subdirectory. The runner creates a new directory for every invocation and never reuses an earlier leak.

To reconstruct that hop yourself, run these selected commands **one at a time**. Each command starts a fresh exploit attempt, so allow for a race miss and inspect its `Attempt-XX/Run.json` before retrying:

```console
python PoC/Script02_LocalCommand.py --command "id"
python PoC/Script02_LocalCommand.py --command "cat /opt/workshop/OperatorNote.txt"
python PoC/Script02_LocalCommand.py --command "cat /opt/workshop/access/vault.key"
python PoC/Script02_LocalCommand.py --command "ledger records"
python PoC/Script02_LocalCommand.py --command "print-flag"
```

The note identifies the private vault and mounted key. The key is generated at runtime and is not in Git. `ledger records` uses that key to read the account records; `print-flag` requests `http://vault:9000/wallet` for the proof. The vault has no published host port. For each selected-command result, require `execution_proof_verified=true`, `command_done_seen=true`, and the `:OK` marker before treating its output as real. Compare [the helper implementation](Challenge/Script01_CheckVault.php) with [the ledger wrapper](Challenge/Script03_Ledger.sh) and [the proof wrapper](Challenge/Script02_PrintFlag.sh) to explain the key header and network hop. Keep the key and proof in your local run files.



---
---
---



## ***🛠️ If a run misses***

The heap or code stage may report "expected one strict address, found 0". This is a race miss; open that run's `Run.json` and use `Script03_RunReport.py` to identify the first failed stage. A final response containing only PHP's memory-limit error is a final callback miss, even if both leaks succeeded. Retry with a fresh run; for selected commands, `--attempts 5` permits up to five fresh attempts. A 502 can mean PHP is restarting after a crash. Check `docker compose ps -a`, wait for `php` to return, and use [the debugging table](Analysis/Script03_Debugging.md). Do not reuse leaked addresses or reset the vault while investigating a miss.



---
---
---



## ***🧹 Finish***

Stop the lab with `docker compose down`. This removes the containers and networks while keeping the named volume. Restarting the vault process generates a new key and proof. Do not publish `PoC-Run-...` directories: their raw HTTP files can contain the runtime key or proof.



---
---
---



## ***📝 Submit***

- Version, SAPI, binary hash, network diagram and both CVEs in your own words. Identify which CVE the PoC exercises.
- One evidence line for each successful exploit stage: memory exhaustion, heap leak, code leak, callback execution.
- The vault JSON response and final proof.
- A short account of why the PoC's offsets are specific to this build.
- The selected command's completion marker, and a list of values that would need re-measurement for another PHP build.
- The completed version-change evidence table, including a justified stop if the chosen build is patched or the offset evidence is insufficient.



---
---
---



## ***💡 Hints***

<details><summary>Hint 1 - target</summary>The version endpoint is the PoC target. The landing page is background; the issue is in PHP request parsing.</details>

<details><summary>Hint 2 - worker</summary>One request creates the abnormal state; later requests must land on a worker that retains it.</details>

<details><summary>Hint 3 - addresses</summary>The heap and code disclosures are separate because ASLR moves them independently.</details>

<details><summary>Hint 4 - vault</summary>The final command runs `print-flag` inside the PHP container. That script reads the runtime key and asks `vault:9000/wallet` for the proof.</details>
