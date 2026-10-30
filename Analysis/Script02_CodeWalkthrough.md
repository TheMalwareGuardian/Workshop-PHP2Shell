# ***🧩 Script02 - Annotated PoC Walkthrough***



---
---
---



Open [the PoC](../PoC/Script01_Php2Shell.py) beside this page. Work through the functions in order. For each checkpoint, predict the output before running the script.

## ***0. Calibration and guard***

`PHP_VERSION`, `DTOR_LOW21`, `ZIF_SYSTEM_FROM_DTOR`, and the heap carrier distances are constants measured for the pinned PHP 8.4.26 Alpine layout. `parse_target()` accepts only this lab's loopback endpoint. `preflight()` checks HTTP 200, the PHP version header, and the version page body. These checks prevent accidentally sending the PoC to an unrelated host or a different PHP build; they do not prove every byte of the binary is identical.

**Student task:** Use `Analysis/Script02_BuildIdentity.py` to record the binary hash. Explain why a changed binary can invalidate the constants while the PHP version string still matches.



---
---
---



## ***1. Multipart building blocks***

`multipart_part()` encodes a field with CRLF separators. `finish_multipart()` closes the body and enforces a 1 MiB wire cap. `ProducerShape` controls the number and depth of nested field names. `leak_producer()` includes `PHPSESSID`, `PHP_SESSION_UPLOAD_PROGRESS`, a file part, and the nested names. PHP expands the names into nested arrays during parsing, causing more memory allocation than the wire size suggests.

**Student task:** Find the two `ProducerShape` values in `STAGES`. Which properties change between the heap and code leak stages?



---
---
---



## ***2. Heap leak***

`heap_consumer()` builds a follow-on multipart request. It tries to reclaim the stale session string header and changes its apparent length to 256 bytes. `heap_candidate()` checks that a returned cookie is exactly 256 bytes and that several plausible pointers agree on one 2 MiB-aligned Zend chunk. This is a validation rule, not a claim that every 256-byte cookie is a leak.

**Student task:** In `Heap.json`, compare the producer's `oom` value with the consumers' `cookie_bytes` values. Why are ordinary 32-byte cookies treated as misses?



---
---
---



## ***3. Code leak***

`code_consumer()` changes the allocation shape to expose a code pointer. `code_candidate()` requires a 16-byte cookie and checks the low 21 bits of `zval_ptr_dtor`. In this build that value is stable because the PHP image is loaded on an aligned region; it is not the normal 4 KiB page offset. The pointer and heap base are independent run-time observations.

**Student task:** Explain what the `DTOR_LOW21` check rules out and what it cannot guarantee.



---
---
---



## ***4. Final callback***

`fake_hashtable()` packs a forged `HashTable`, call frame, and `zend_string` into one 384-byte buffer. `final_multipart()` calculates where that buffer should land from the heap leak and places it before the field that triggers the final OOM. The forged destructor pointer uses the leaked `zval_ptr_dtor` address plus the measured `ZIF_SYSTEM_FROM_DTOR` delta. If the pointer or geometry is wrong, a worker may fail rather than execute the command.

`proof_command()` emits a fresh nonce, `id`, and the hash of `print-flag`, then runs `print-flag` once. `final_request()` checks the markers and the `PHP2SHELL{...}` vault response. The marker proves command execution; the vault proof shows the post-compromise network hop succeeded.

**Student task:** Distinguish `execution_proof_verified` from `vault_proof_seen`. Why does the script require both for a successful exit?



---
---
---



## ***5. HTTP and race***

`http_frame()` and `final_http_frame()` preserve the tested request framing. `run_leak_stage()` sends one producer and eight consumers on a single connection before reading the replies. That gives the consumers a chance to reach the same poisoned worker. `receive()` records status, PHP version header, OOM text, and cookie length. `main()` stops at the first failed stage and saves the run report.

**Student task:** Follow one unsuccessful run through `Run.json` and the stage JSON files. Name the first failed assertion instead of calling every failure "the exploit did not work".



---
---
---



## ***6. Selected-command entry point***

Open `PoC/Script02_LocalCommand.py` and trace `binary_hash()`, `wait_for_php()`, and `main()`. The script records the target PHP version and an ELF SHA-256 before calling any leak stage. It prints a warning but still makes bounded attempts when either differs from the calibrated build. On another loopback port, `--elf` must identify that target's exact binary. Each attempt writes a separate report and obtains fresh addresses. The command is packed by `local_command()`, which rejects shell control characters and checks the carrier size before sending anything. `final_request()` requires the fresh nonce and `:OK` completion marker for this mode; the guided vault mode instead requires `id`, the `print-flag` hash, and the vault proof for a successful exit.

**Student task:** Explain why a hash warning does not recalculate offsets, why a previous attempt's leaked address must not be reused after a PHP restart, and why a 502 after exit code 139 is a service crash rather than proof of code execution. Then complete [the surprise-version worksheet](Script06_SurpriseVersion.md).
