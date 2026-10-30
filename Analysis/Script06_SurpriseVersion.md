# ***🎲 Script06 - Surprise PHP Version Assignment***



<p align="center">
	<i>Use the same local workshop topology with an instructor-chosen PHP build. Decide whether the exploit path still exists, then justify every changed constant with evidence.</i>
</p>



---
---
---



## ***The assignment boundary***

Your instructor may change the PHP base image in `Dockerfile`. The public route remains `127.0.0.1:8080`, and the vault remains private. **Do not point either PoC at another host.** A new version string is not enough to port a memory-corruption exploit.

Before you begin, check the [OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp). For the 8.4 branch, both list **8.4.27 as patched**. If the instructor chooses a patched build, the correct result may be a negative finding with evidence; no offset adjustment should be expected to restore a fixed vulnerability.



---
---
---



## ***Checkpoint 1 - Identify the changed target***

```console
docker compose up --build -d --force-recreate
python Analysis/Script01_TargetProbe.py
python Analysis/Script02_BuildIdentity.py
python Analysis/Script04_OffsetInspector.py
```

The target probe is intentionally calibrated to PHP 8.4.26, so a version mismatch is an expected observation in this exercise. Record the actual version from `php-version.php`, the branch, image tag, architecture, PHP binary SHA-256, `memory_limit`, session upload-progress settings, SAPI, and worker count. Distinguish the HTTP SAPI shown on the landing page (`cli-server`) from the `cli` SAPI printed by a separate `docker compose exec php php -r ...` process.

| Evidence | Original lab | Surprise build |
|---|---|---|
| Image tag and architecture | `php:8.4.26-fpm-alpine3.23`, amd64 | Fill in |
| PHP version and HTTP SAPI | 8.4.26, `cli-server` | Fill in |
| Binary SHA-256 | `5123326076cd3e77bf5e9f97e8f63b7368f7bfa18b37da7a749e29cc1342d437` on the validated host | Fill in |
| Worker count and memory limit | 4, 128M | Fill in |
| Advisory status | Affected release | Fill in |

If the build is patched or the required session path is unavailable, stop at a documented negative result. A PoC that crashes a process or causes OOM is not evidence of code execution.

To make one bounded exploratory attempt against the changed build in the same Compose project, run:

```console
python PoC/Script02_LocalCommand.py --command "id" --attempts 1
```

The script warns about a different PHP version or binary hash and continues with its **old** calibration. Treat the first failed stage as a measurement to explain, not as an offset it has already fixed. If your instructor hosts the changed PHP endpoint on another loopback port, add `--url http://127.0.0.1:<port>/php-version.php --elf path/to/exact/php`; the supplied ELF must come from that target.



---
---
---



## ***Checkpoint 2 - Separate static offsets from live addresses***

The supplied code pointer check is `DTOR_LOW21 = 0x112930`. The known relative function distance is `ZIF_SYSTEM_FROM_DTOR = -0x204BC0`. These are **not** heap addresses and cannot be reused solely because PHP reports the same version.

Use `Analysis/Script04_OffsetInspector.py --elf path/to/php` on the exact candidate ELF, or run it without `--elf` to inspect the current `php` service. If the binary exposes both symbols, record their `st_value` values and compute `zif_system - zval_ptr_dtor`. If it is stripped, obtain matching debug symbols from the same build or report that the offset cannot be independently verified. Do not substitute symbols from a nearby package or another architecture.

After a *successful* code leak, compare the saved pointer:

```console
python Analysis/Script04_OffsetInspector.py --run-dir PoC-Run-<timestamp>
python Analysis/Script05_WorkerMaps.py --run-dir PoC-Run-<timestamp>
```

For the second PoC, use its `Attempt-XX` directory as `--run-dir`. The first command compares the observed pointer with the calibration and, when available, the ELF symbol. The second reads live worker maps and shows the pointer offset from each PHP executable mapping. **Run it before the PHP container restarts**; ASLR bases from an older process are not comparable. A calculated `zif_system` candidate is still a calculation until the exact ELF or debugger confirms it.



---
---
---



## ***Checkpoint 3 - Reassess the trigger and heap geometry***

Read `ProducerShape`, `leak_producer()`, `heap_consumer()`, `code_consumer()`, and `STAGES` in `PoC/Script01_Php2Shell.py`. For a new build, test one claim at a time:

1. Does a multipart producer still produce the expected OOM in a surviving worker?
2. Can a later consumer reach the same worker and return a nonordinary cookie?
3. Does `heap_candidate()` find one aligned base from multiple agreeing pointers?
4. Does `code_candidate()` find one plausible function pointer with a fingerprint measured from the candidate ELF?
5. Does the final callback land at the predicted heap location? A correct function delta alone does not answer this.

The `HEAP_CARRIER_DELTA` and `HEAP_CARRIER_OFFSET` constants came from the original allocation layout. `CARRIER_SIZE`, `COMMAND_OFFSET`, and the fields packed by `fake_hashtable()` reflect a particular 64-bit PHP ABI. Re-measure them using the candidate PHP headers and an instrumented local debugger run. Keep the request body size and producer/consumer ordering in the notes because changing either can alter allocation geometry. A process crash or nginx 502 is a debugging observation, not proof that a guessed value is correct.



---
---
---



## ***Checkpoint 4 - Edit only after measurement***

| File or symbol | Why it may change |
|---|---|
| `Dockerfile` base image | Instructor's candidate build |
| `PoC/Script01_Php2Shell.py: PHP_VERSION` and `preflight()` | Exact version guard and response expectations |
| `DTOR_LOW21`, `ZIF_SYSTEM_FROM_DTOR` | Candidate ELF symbol values and alignment |
| `ProducerShape`, `heap_consumer()`, `code_consumer()` | Changed parser and allocator behavior |
| `HEAP_CARRIER_DELTA`, `HEAP_CARRIER_OFFSET` | Changed controlled-value placement |
| `fake_hashtable()`, `CARRIER_SIZE`, `COMMAND_OFFSET` | Changed structure ABI or packing |
| `PoC/Script02_LocalCommand.py: PINNED_SHA256` | Reference hash for warnings; update only after validating a new calibration |

Do not start by editing `PINNED_SHA256` to hide a mismatch. The exploratory PoC will warn and attempt the local target anyway, using the old values. Preserve the original measured values in your notes, and record each replacement alongside the observation that supports it. A completed attempt on a different build is not proof that the offsets were ported unless the stage evidence supports that conclusion.



---
---
---



## ***Checkpoint 5 - Defend your result***

Submit one of two outcomes:

- **Validated port:** exact binary identity, updated static offsets, observed producer and consumer behavior, fresh heap and code leaks, and a final response with the nonce and completion marker.
- **Evidence-based stop:** identify the first failed checkpoint, show the saved report or debugger observation, and explain why the build cannot yet be claimed exploitable with this PoC. If the release is patched, explain that as the likely reason and avoid presenting a forced crash as success.

The instructor can grade either outcome. The purpose is to learn how an exploit is tied to a binary, SAPI, allocator layout, and request lifecycle-not to turn version strings into guessed offsets.
