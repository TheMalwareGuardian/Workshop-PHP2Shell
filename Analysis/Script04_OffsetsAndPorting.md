# ***🧮 Script04 - Offsets, Build Identity, and Porting***



---
---
---



## ***What the inspector can establish***

Run `python Analysis/Script04_OffsetInspector.py` from the repository root. It copies the running PHP ELF into a temporary local directory, computes SHA-256, and reads ELF64 symbol tables when available. Use `--elf path/to/another/php` to inspect a separately obtained candidate binary without changing the running workshop. It looks for `zval_ptr_dtor` and `zif_system` and prints their values, the low 21 bits of the former, and the signed delta between them. If a stripped binary exposes no symbol, the tool says **unavailable**; it never invents an offset.

With a saved successful run, add `--run-dir PoC-Run-<timestamp>` to compare the leaked code pointer with the exact ELF. If the binary cannot currently be read, `--no-elf --run-dir PoC-Run-<timestamp>` still checks the leak's low 21 bits and shows the `zif_system` *candidate* calculated from the old delta. That candidate is not independent verification. For the second PoC, pass `PoC-Run-.../Attempt-XX` as the run directory.

`python Analysis/Script05_WorkerMaps.py --run-dir PoC-Run-<timestamp>` reads live PHP executable mappings and reports the pointer's offset from each process's load bias. Run it before a crash or restart changes ASLR. It does not attach a debugger or alter the worker.

The [selected-command PoC](../PoC/Script02_LocalCommand.py) asks Docker for the workshop PHP binary's SHA-256. On another loopback port, it requires `--elf` with that target's binary and hashes the supplied file instead; students must ensure it actually belongs to the target. It warns and continues when the hash or PHP version differs from the validated lab, recording both mismatches in `Run.json`. A version string alone is insufficient. Two packages can both report PHP 8.4.26 while having different function addresses or structure layouts.



---
---
---



## ***Which values the PoC uses***

| Value in `Script01_Php2Shell.py` | Meaning | How to recheck it |
|---|---|---|
| `PHP_VERSION` | HTTP preflight version guard | Read the target's response and package build |
| `DTOR_LOW21` | Low 21-bit fingerprint in a leaked cookie | Compare the leak with a symbol from the exact ELF and its load alignment; this is not a normal 4 KiB page offset |
| `ZIF_SYSTEM_FROM_DTOR` | Signed distance from `zval_ptr_dtor` to `zif_system` | Subtract the two symbols in the same ELF |
| `HEAP_CARRIER_DELTA`, `HEAP_CARRIER_OFFSET` | Where a controlled field lands relative to the leaked Zend chunk | Measure allocation layout under the exact worker and request geometry |
| `ProducerShape` and consumer counts | Allocation and race geometry | Observe OOM and cookie lengths on the new build |
| `CARRIER_SIZE`, `COMMAND_OFFSET`, structure fields | Forged PHP data layout | Check the new PHP headers, ABI, and a debugger trace |

**The ELF inspector does not determine the heap carrier distances or the forged structure layout.** Those depend on allocation behavior and PHP internals. A matching function delta is therefore necessary evidence for one part of a port, not proof that the whole exploit works.

For the validated amd64 workshop build, the PoC currently uses `DTOR_LOW21=0x112930`, `ZIF_SYSTEM_FROM_DTOR=-0x204BC0`, `HEAP_CARRIER_DELTA=0x8400000`, and `HEAP_CARRIER_OFFSET=0x16D1D8`. One saved run leaked `zval_ptr_dtor=0x57e158912930` and calculated `zif_system=0x57e15870dd70`. Those full addresses belonged to that process run; a later PHP restart changed them. The function delta is a static build relationship, while both full addresses and the heap base are runtime values.

On the instructor's validated amd64 PHP ELF (SHA-256 `5123326076cd3e77bf5e9f97e8f63b7368f7bfa18b37da7a749e29cc1342d437`), the inspector found `zval_ptr_dtor` at ELF symbol value `0x712930`. A saved run leaked `0x5f29c9b12930`, giving the aligned load bias `0x5f29c9400000`. The same ELF **does not expose `zif_system` in its symbol tables**, so the inspector cannot independently confirm `-0x204BC0` by symbol subtraction. The successful selected-command PoC is dynamic evidence that the calibrated callback target works on this exact build; it is not a reusable static offset measurement for another build.



---
---
---



## ***A disciplined porting exercise***

1. Pin a new candidate image and record the full tag, architecture, PHP version, SAPI, relevant INI values, worker count, and SHA-256. Keep the original values in your notes while the new build is unverified.
2. Compare source changes and the two PHP advisories. Check whether the vulnerability is still present and whether the same trigger reaches it. A patched build may not be exploitable at all.
3. If the exact ELF exposes symbols, measure both function values and their delta. If not, use a matching debug-symbol build or another verified symbol source. Do not copy the old delta from the version number.
4. Recheck the request parser and session upload-progress behavior. Confirm the producer OOM and the consumer cookie lengths before interpreting bytes as addresses.
5. Re-measure the heap placement and the forged data structure with a debugger on the candidate build. The 64-bit fields, type tags, and offsets in `fake_hashtable()` are not portable promises.
6. Update the build guard only after all preceding checks. Keep the original workshop image pinned for students while the new build remains unverified.

The selected-command PoC **warns and proceeds** on a binary hash or version mismatch. It does not automatically "adjust" a memory-corruption exploit from one PHP version to another. The unchanged leak fingerprint, heap geometry, and forged structure checks can still fail; those failures are observations for the porting worksheet.

Use [Script06_SurpriseVersion.md](Script06_SurpriseVersion.md) as the student worksheet. For PHP 8.4, both official advisories list 8.4.27 as patched; a patched build can be a valid negative-result assignment.
