# CASE-006 — Phoenix Capability and Risk Boundary

## Objective

Trace the investigated Phoenix capability/risk authorization surface
and identify the relationship between state and permitted operations.

## Evidence

- sana/state-boundaries/phoenix_risk_capability_boundary_v145.py
- sana/state-boundaries/phoenix_capability_gate_v146.py
- sana/trader-state/PHOENIX_TRADERSTATE_CONSUMER_v13_1.txt
- sana/trader-state/PHOENIX_TRADERSTATE_CONFIG_TRACE_v12_5.txt

## Questions

1. Which state reaches the capability boundary?
2. What conditions are evaluated?
3. Which operations are gated?
4. How does the authorization surface connect to risk logic?

## Interpretation

This case organizes the Phoenix-related authorization research
without asserting that a production authorization control is broken.

## Limitations

The public repository intentionally omits private authentication/session
material and live product runtime state.
