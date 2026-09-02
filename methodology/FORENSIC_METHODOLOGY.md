# Forensic Methodology

## 1. Preserve

The private working corpus is kept separate from the public repository.

No publication step should modify the original forensic workspace.

## 2. Inventory

Artifacts are enumerated and classified by source, type, evidence value,
publication risk and provenance.

## 3. Deduplicate

Duplicate artifacts are collapsed using SHA-256 where appropriate.

## 4. Isolate

Build products, caches, historical backups, authentication/session
material, live bundles and uncontrolled runtime state are excluded.

## 5. Correlate

Static code, data-flow traces, call graphs, runtime probes and ground-truth
artifacts are compared rather than interpreted independently.

## 6. Reproduce

A claim should be accompanied by the smallest published evidence set
that demonstrates the relevant observation.

## 7. Separate observation from conclusion

The repository distinguishes:

- observed behavior
- reconstructed control/data flow
- inferred mechanism
- security impact hypothesis
- confirmed vulnerability

These are not interchangeable.

## 8. Publication boundary

The public repository is intentionally smaller than the private
working corpus.

## 9. Hash provenance

SHA-256 values in the public manifest identify the content actually
published in the repository.
