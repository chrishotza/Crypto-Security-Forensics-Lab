# Crypto Security Forensics Lab

A curated public research corpus for forensic analysis of crypto
trading infrastructure, Solana execution paths, order-flow boundaries,
state propagation, authorization boundaries and SBPF runtime behavior.

## What this repository is

This repository contains selected artifacts from a larger private
forensic workspace.

The goal is to preserve technical evidence in a form that can be
inspected, compared and independently reasoned about without exposing
private runtime state or authentication material.

## Research tracks

### Sana / Trading Forensics

- Order implementation → transaction flow
- Provider and execution boundaries
- Order call graphs
- State-to-parameter propagation
- TraderState ingress and consumption
- Reducer behavior
- Rollback and differential analysis
- Ground-truth artifacts

### Phoenix / Solana Execution Forensics

- TraderState analysis
- Capability and risk boundaries
- SBPF memory mapping
- Interpreter behavior
- Runtime probes
- Dynamic CALLX analysis

## Important distinction

This is an **evidence corpus**, not a turnkey application.

Some historical experiments depended on local bundles, runtime
captures, private working data or specific analysis environments that
are intentionally not published.

Accordingly, "reproducible" here means that the published artifacts
preserve the relevant evidence and analysis inputs where possible;
it does not mean every historical script runs unchanged from a clean
clone.

## Evidence policy

The public repository excludes:

- credentials and private keys
- authentication/session secrets
- raw production bundles
- uncontrolled runtime dumps
- private user data
- build/dependency artifacts
- local machine paths where avoidable

## How to read the corpus

Start with:

1. CASE_INDEX.md
2. RESEARCH_STATUS.md
3. manifests/repo-v0.1-manifest.csv

Then follow the chain from:

order construction → provider boundary → state → execution → transaction

and, separately:

TraderState → capability/risk boundary → SBPF/runtime behavior

## Provenance

manifests/repo-v0.1-manifest.csv records the curated public corpus.

Its SHA-256 values refer to the **content actually published** in the
repository.

## Research claims

No individual script, trace or report should be interpreted as proof
of a vulnerability on its own.

Security claims require an explicit hypothesis, evidence chain,
reproduction, impact analysis and scope.

## Status

**v0.1 — Public Forensic Corpus**
