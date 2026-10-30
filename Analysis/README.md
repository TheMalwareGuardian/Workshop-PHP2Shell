# ***🔬 Analysis Lab: Observe, Verify, Explain***



<p align="center">
	<i>Five read-only helpers connect the live target, PHP binary, PoC transcript, worker mappings, and offset evidence to the lesson.</i>
</p>



---
---
---



## ***🧭 Order***

1. Start the one workshop stack with `docker compose up --build -d`.
2. Run `python Analysis/Script01_TargetProbe.py`. Record the PHP header and worker PIDs. Six ordinary GETs may show one or several workers; neither result proves a vulnerability.
3. Run `python Analysis/Script02_BuildIdentity.py`. Record the PHP binary hash, version, memory limit, and upload-progress settings. This identifies the binary and configuration that the PoC expects. A hash is an identity check, not an offset by itself.
4. Read [Script01_VulnerabilityMechanics.md](Script01_VulnerabilityMechanics.md) and [Script02_CodeWalkthrough.md](Script02_CodeWalkthrough.md).
5. Run the guided PoC from the repository root. Then run `python Analysis/Script03_RunReport.py PoC-Run-<timestamp>` with the directory printed by the PoC. It summarizes evidence without displaying the vault proof.
6. Compare `Heap.json`, `Code.json`, `Final.json`, and `Run.json` with the questions in [Script03_Debugging.md](Script03_Debugging.md). Raw HTTP artifacts may include the runtime proof.
7. Run `python Analysis/Script04_OffsetInspector.py`, then read [Script04_OffsetsAndPorting.md](Script04_OffsetsAndPorting.md). Only after the guided run, try `python PoC/Script02_LocalCommand.py --command "id"` and explain its version/hash warnings. The second PoC stores each bounded attempt in an `Attempt-XX` subdirectory; pass that subdirectory to `Script03_RunReport.py`.
8. Before the PHP container restarts, run `python Analysis/Script05_WorkerMaps.py --run-dir PoC-Run-<timestamp>` to compare a saved code pointer with live PHP executable mappings. If the process already restarted, record that the ASLR comparison is no longer valid.
9. Finish with [Script06_SurpriseVersion.md](Script06_SurpriseVersion.md). It identifies every value that must be rechecked when the instructor changes the PHP build.

The analysis helpers do not attempt exploitation or change the container. The two PoC entry points use the same pinned exploit implementation.
