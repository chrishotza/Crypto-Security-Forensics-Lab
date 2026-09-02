# Crypto Security Forensics Lab

Public research laboratory for reproducible forensic analysis of
crypto trading infrastructure, Solana execution paths, order-flow
boundaries, state propagation, authorization boundaries and SBPF
runtime behavior.

## Scope

This repository is organized around evidence and reproducibility,
not around raw working-directory dumps.

The v0.1 corpus was selected from a larger local forensic archive
and deduplicated using SHA-256 provenance.

## Research Areas

### Sana / Trading Forensics

- Order implementation to transaction flow
- Provider and execution boundaries
- Order call graphs
- State-to-parameter propagation
- TraderState ingress and consumption
- Reducer behavior
- Rollback and differential analysis
- Ground-truth artifacts

### Phoenix / Solana Execution Forensics

- TraderState analysis
- Capability / risk authorization boundaries
- SBPF memory mapping
- Interpreter behavior
- Runtime probes
- Dynamic execution / CALLX analysis

## Evidence Policy

This repository intentionally excludes:

- build artifacts
- dependency trees
- caches
- working backups
- credentials and private material
- live authentication/session material
- raw production bundles
- uncontrolled dumps

The repository should contain only artifacts that can be explained,
attributed and reproduced.

## Provenance

Each selected artifact is recorded in:

manifests/repo-v0.1-manifest.csv

The manifest preserves the original path, SHA-256 hash, forensic
bucket, score and publication role used during corpus selection.

## Status

v0.1 — forensic corpus assembly.

The contents are research artifacts and should not be interpreted
as a claim of vulnerability without the corresponding evidence,
reproduction procedure and scope.
