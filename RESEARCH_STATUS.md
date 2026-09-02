# Research Status

## v0.1 — Corpus Publication

The first public release is a curated subset of a larger private
forensic workspace.

### Sana / Trading Forensics

Current corpus includes material covering:

- order implementation → transaction flow
- provider boundaries
- execution/data-flow analysis
- call-graph reconstruction
- state-to-parameter propagation
- TraderState ingress/consumption
- reducer behavior
- rollback/differential analysis
- ground-truth artifacts

### Phoenix / Solana Execution Forensics

Current corpus includes material covering:

- TraderState analysis
- capability/risk boundaries
- SBPF memory behavior
- interpreter behavior
- runtime probes
- dynamic CALLX analysis

## Interpretation

The corpus documents technical investigation.

It does not, by itself, establish that a vulnerability exists,
that an observed behavior is exploitable, or that a production
security boundary is broken.

Those claims require a case-specific evidence chain and scope.

## Publication boundary

The public corpus deliberately omits private runtime state,
authentication/session material, production bundles and local
working-directory artifacts.
