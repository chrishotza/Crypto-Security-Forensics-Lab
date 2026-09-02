# CASE-007 — SBPF Memory and Dynamic CALLX Runtime

## Objective

Document the low-level runtime investigation of the Phoenix execution
path, including memory mapping, CALLX resolution and syscall entry.

## Evidence

- phoenix/runtime/v15_92_probe.py
- phoenix/runtime/v15_94_probe.py
- phoenix/runtime/v15_98_probe.py
- phoenix/runtime/v16_11_probe.py
- phoenix/sbpf/interpreter.rs
- phoenix/sbpf/memory_management.rs
- phoenix/sbpf/memory_region.rs
- phoenix/sbpf/aligned_memory.rs

## Investigated surfaces

- SBPF instruction dispatch
- MemoryMapping / region translation
- Dynamic CALLX resolution
- ELF relocation behavior
- External syscall resolution
- Runtime store semantics

## Interpretation

These artifacts document runtime behavior observed in the forensic
harness. They are not, by themselves, an exploit or a claim of a
production vulnerability.

## Limitations

The complete deployed binary and private runtime harness are not part
of the public corpus.
