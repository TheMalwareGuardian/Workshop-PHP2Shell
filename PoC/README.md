# ***🧨 PoC: PHP2Shell on the Local Vault Lab***



---
---
---



This directory contains two entry points for the same local exploit chain. [Script01_Php2Shell.py](Script01_Php2Shell.py) retrieves the vault proof from the pinned `127.0.0.1:8080/php-version.php` lab. [Script02_LocalCommand.py](Script02_LocalCommand.py) accepts a short selected command, reports the running PHP version and binary hash, and can use another loopback port with `--url`. Both derive from [KillaBoi's PHP 8.4.26 PoC](https://github.com/KillaBoi/StealMyBitcoin-PoC). Neither accepts a nonlocal host.

```console
docker compose up --build -d
python PoC/Script01_Php2Shell.py --url http://127.0.0.1:8080/php-version.php
python PoC/Script02_LocalCommand.py --command "id"
python PoC/Script02_LocalCommand.py --command "ls /opt/workshop" --attempts 3
```



---
---
---



## ***🔬 Read the stages***

| Stage | In the script | Evidence to record |
|---|---|---|
| 1. Exhaust | Multipart field construction | Worker exhaustion and follow-on response |
| 2. Leak heap | Pipelined consumers | Agreed 2 MiB Zend heap chunk base |
| 3. Leak code | Second producer/consumer shape | `zval_ptr_dtor` fingerprint and PHP image base |
| 4. Call back | Forged HashTable | Guided mode: nonce, process identity, binary hash, vault JSON. Selected-command mode: nonce, output, `:OK` |

The hardcoded constants are measured relationships within the PHP 8.4.26 Alpine build used here; the actual heap and code addresses are freshly leaked on each run. These constants do not carry over to the OffSec PHP 8.5.11 example or another build. The script generates a per-run transcript; do not publish runtime proof values.

The final payload calls `print-flag` once. In this lab, that program requests the wallet record from the private vault using the runtime key mounted into the PHP container.

The second entry point uses a different completion marker, `:OK`, and prints the selected command's response. Its command field accepts plain ASCII words, paths and arguments only; the forged string has a strict size limit. Try `id`, `php -v`, `ls /opt/workshop`, or `cat /opt/workshop/OperatorNote.txt`. It makes up to three fresh attempts by default (configurable from one to five), keeping each run under `PoC-Run-.../Attempt-XX/`. Every attempt obtains new leaks; addresses from earlier attempts are never reused. A binary hash or PHP version mismatch prints a warning and is saved in each `Run.json`; the script still attempts the local target with its existing calibration. For a second local web stack, pass `--url http://127.0.0.1:<port>/php-version.php --elf path/to/that/php` so the reported hash comes from that stack's exact binary. Memory corruption can terminate the PHP process with exit code 139 even after command output is observed; Compose restarts the workshop PHP service on failure. See [the offset and porting lesson](../Analysis/Script04_OffsetsAndPorting.md) for the measurements needed on another PHP build.

For the complete post-compromise sequence, follow [the student guide](../Student.md): inspect the operator note, identify the runtime key, run `ledger records`, and then run `print-flag` through `Script02_LocalCommand.py`. The guided `Script01_Php2Shell.py` invokes `print-flag` itself. Successful guided runs save `Final.json` and `Final.Response.body`; selected-command runs save them under the successful `Attempt-XX` directory. These response files may contain the generated key or proof.



---
---
---



## ***🎲 If the instructor changes PHP***

Follow [the surprise-version worksheet](../Analysis/Script06_SurpriseVersion.md). Recheck vulnerability status, SAPI, binary hash, ELF symbol values, code-pointer fingerprint, heap carrier placement, and the forged structure layout. `Script02_LocalCommand.py` **warns but runs** on a different version or hash. It does not change its offsets automatically, and a failed stage is useful evidence. **Do not edit its reference hash just to silence the warning.** A patched PHP build may be a correct negative-result exercise rather than a porting target.
