# CASE-002 — State to Risk Boundary

## Objective

Trace how application state is transformed into values that participate
in order and risk decisions.

## Evidence

- sana/state-boundaries/STATE_TO_RISK_BOUNDARY_EXACT_v3_1.txt
- sana/state-boundaries/order_send_exact_boundary_v37.py
- sana/state-boundaries/isolated_order_exact_runtime_boundary_v50.py
- sana/state-boundaries/provider_order_module_boundary_v52.py

## Questions

1. Which state fields cross the boundary?
2. Where are parameters normalized or transformed?
3. Which checks occur before transaction construction?
4. Which boundary owns the final decision?

## Interpretation

This case organizes state/risk propagation analysis and should be read
together with the order-flow and TraderState cases.

## Limitations

A boundary trace is evidence of program structure and behavior, not proof
that the boundary is exploitable.
