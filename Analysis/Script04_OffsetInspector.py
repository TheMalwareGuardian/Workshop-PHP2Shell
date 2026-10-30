#!/usr/bin/env python3
"""Inspect local PHP ELF symbols and compare them with the workshop calibration.

Copies /usr/local/bin/php from the running php container into a temporary directory. Works with ELF64 little-endian binaries that retain symbol tables. Missing symbols are reported as unknown; no offsets are guessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

SYMBOLS = ("zval_ptr_dtor", "zif_system")
CALIBRATED_DTOR_LOW21 = 0x112930
CALIBRATED_DELTA = -0x204BC0


def cstring(table: bytes, offset: int) -> str:
	"""Resolve an ELF symbol-name offset inside its linked string table."""
	if offset >= len(table):
		return ""
	end = table.find(b"\0", offset)
	return table[offset:end if end >= 0 else len(table)].decode(
		"ascii", "replace")


def elf_symbols(data: bytes) -> dict[str, int]:
	"""Read named function st_value fields from ELF symbol tables.

	st_value is a file/build-relative symbol value for a PIE image. It is not a live process address; the worker's load bias must be added later.
	"""
	if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
		raise ValueError("Expected a little-endian 64-bit ELF")
	# ELF64 header: e_shoff, e_shentsize, e_shnum.
	section_offset = struct.unpack_from("<Q", data, 0x28)[0]
	section_size = struct.unpack_from("<H", data, 0x3A)[0]
	section_count = struct.unpack_from("<H", data, 0x3C)[0]
	if (not section_offset or section_size < 64
			or not 0 < section_count <= 4096
			or section_offset + section_count * section_size > len(data)):
		raise ValueError("ELF section table missing or invalid")
	sections = []
	for index in range(section_count):
		base = section_offset + index * section_size
		if base + 64 > len(data):
			raise ValueError("ELF section table extends past the file")
		# The section table provides both the symbol bytes and the linked string table needed to turn a name index into a function name.
		kind = struct.unpack_from("<I", data, base + 4)[0]
		offset, size = struct.unpack_from("<QQ", data, base + 0x18)
		link = struct.unpack_from("<I", data, base + 0x28)[0]
		entry_size = struct.unpack_from("<Q", data, base + 0x38)[0]
		# SHT_NOBITS (8), such as .bss, occupies memory but contributes no bytes to the ELF file. Its sh_size may extend past EOF legitimately.
		if kind != 8 and offset + size > len(data):
			raise ValueError("ELF section extends past the file")
		sections.append((kind, offset, size, link, entry_size))
	found = {}
	for kind, offset, size, link, entry_size in sections:
		# SHT_SYMTAB (2) and SHT_DYNSYM (11) hold ELF symbol entries.
		# Their sh_link field points to the associated string table.
		if kind not in (2, 11) or entry_size < 24 or link >= len(sections):
			continue
		_, string_offset, string_size, _, _ = sections[link]
		strings = data[string_offset:string_offset + string_size]
		for position in range(offset, offset + size, entry_size):
			if position + 24 > offset + size:
				break
			name_offset = struct.unpack_from("<I", data, position)[0]
			value = struct.unpack_from("<Q", data, position + 8)[0]
			name = cstring(strings, name_offset)
			if name in SYMBOLS and value:
				found[name] = value
	return found


def main() -> int:
	"""Inspect the exact ELF or compare a saved code leak with calibration."""
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--elf", type=Path,
						help="Inspect a supplied PHP ELF instead of the running lab")
	parser.add_argument("--run-dir", type=Path,
						help="Compare with a PoC run containing Code.json")
	parser.add_argument("--no-elf", action="store_true",
						help="Inspect only the run's leaked pointer and PoC constants")
	args = parser.parse_args()
	if args.no_elf and not args.run_dir:
		parser.error("--no-elf requires --run-dir")
	if args.no_elf and args.elf:
		parser.error("--no-elf cannot be combined with --elf")
	data = None
	if args.no_elf:
		pass
	elif args.elf:
		data = args.elf.read_bytes()
	else:
		with tempfile.TemporaryDirectory(
				prefix="php2shell-elf-", dir=Path.cwd()) as folder:
			target = Path(folder) / "php"
			completed = subprocess.run(
				["docker", "compose", "cp", "php:/usr/local/bin/php", str(target)],
				capture_output=True, text=True, check=False)
			if completed.returncode:
				print(completed.stderr.strip())
				return completed.returncode
			data = target.read_bytes()
	print(f"Workshop calibration: dtor low21="
		f"{CALIBRATED_DTOR_LOW21:#x}, "
		f"zif_system delta={CALIBRATED_DELTA:+#x}")
	found = {}
	if data is not None:
		digest = hashlib.sha256(data).hexdigest()
		print(f"PHP ELF SHA-256: {digest}")
		elf_type = struct.unpack_from("<H", data, 0x10)[0] if len(data) >= 0x12 else 0
		machine = struct.unpack_from("<H", data, 0x12)[0] if len(data) >= 0x14 else 0
		print(f"ELF type={elf_type} (3 is PIE/shared); machine={machine} "
			"(62 is x86-64)")
		try:
			found = elf_symbols(data)
		except ValueError as exc:
			print(f"ELF inspection unavailable: {exc}")
			return 1
	for name in SYMBOLS:
		value = found.get(name)
		print(f"{name}: {value:#x}" if value is not None
			else (f"{name}: ELF not inspected"
					if data is None else
					f"{name}: unavailable in exposed symbol tables"))
	dtor, system = (found.get(name) for name in SYMBOLS)
	if dtor is not None:
		print(f"zval_ptr_dtor low 21 bits: {dtor & ((1 << 21) - 1):#x}")
		print(f"Matches workshop fingerprint: "
			f"{(dtor & ((1 << 21) - 1)) == CALIBRATED_DTOR_LOW21}")
	if dtor is not None and system is not None:
		delta = system - dtor
		print(f"zif_system - zval_ptr_dtor: {delta:+#x}")
		print(f"Matches workshop delta: {delta == CALIBRATED_DELTA}")
	elif data is not None and dtor is not None:
		print("zif_system is not exposed in this ELF's symbol tables; "
			"the calibrated delta cannot be checked statically here")
	if args.run_dir:
		# A leak is a runtime virtual address. Subtracting the ELF st_value yields a tentative load bias only when both refer to the same build.
		code_report = args.run_dir / "Code.json"
		if not code_report.exists():
			code_report = args.run_dir / "code.json"  # earlier saved runs
		report = json.loads(
			code_report.read_text(encoding="utf-8"))
		candidates = report.get("candidate_addresses") or []
		if len(candidates) != 1:
			print(f"Run has {len(candidates)} strict code candidates; "
				"one is required for comparison")
			return 1
		leaked_dtor = int(candidates[0], 16)
		print(f"Observed zval_ptr_dtor pointer: {leaked_dtor:#x}")
		print(f"Observed low21 matches calibration: "
			f"{(leaked_dtor & ((1 << 21) - 1)) == CALIBRATED_DTOR_LOW21}")
		print(f"Candidate zif_system using calibrated delta: "
			f"{leaked_dtor + CALIBRATED_DELTA:#x} "
			"(calculated, not independently leaked)")
		if dtor is not None:
			load_bias = leaked_dtor - dtor
			print(f"Inferred ELF load bias: {load_bias:#x}")
			print(f"Load bias aligned to 2 MiB: "
				f"{load_bias % (1 << 21) == 0}")
			if system is not None:
				print(f"ELF-derived zif_system at this bias: "
					f"{load_bias + system:#x}")
	print("ELF symbols can check code offsets. Heap placement, request timing, "
		"and the forged structure still require separate validation.")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
