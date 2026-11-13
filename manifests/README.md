# Evidence manifests: two different claims

This repository preserves two historically distinct inventories for the 52
curated published forensic artifacts:

- `repo-v0.1-manifest.csv`: the **original historical SHA-256 and byte-size
  claims**. These are **not** automatically assumed to match the current Git
  working tree. During the November 2026 structural review, **43 of 52 size
  fields differed** from the then-current Git blob sizes. This discrepancy
  needs a separate provenance investigation. The archive has **not** been
  silently rewritten to make CI pass.
- `current-tree-blobs.csv`: a **newly recorded Git blob SHA-1 baseline** for
  the exact 52 source files observed in the current repository tree. The
  default CI gate rehashes their bytes with Git's `blob <size>\\0<bytes>`
  object encoding and fails on changes. The hashes are source-control object
  identities, **not independent chain-of-custody evidence** or a security
  certification of upstream archives.

Run `python scripts/verify_publication_manifest.py` to enforce current
tree identity, or `python scripts/verify_publication_manifest.py --legacy-strict`
to independently check the historical SHA-256/size claims (currently expected
to fail pending reconciliation). Never label the two checks equivalent.

Updating the current snapshot requires deliberate evidence review; do not
regenerate it during ordinary CI, and do not infer a confirmed vulnerability
from a forensic trace. No private runtime bundle is downloaded or executed.
