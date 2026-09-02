# CASE-005 — Reducer and State Reconstruction

## Objective

Understand how incoming events are reduced into snapshots and deltas.

## Evidence

- sana/reducers/GROUND_TRUTH_TRADER_SNAPSHOT_REDUCER.txt
- sana/reducers/GROUND_TRUTH_TRADER_DELTA_REDUCER.txt
- sana/reducers/exact_reducer_forensics_v05.py

## Questions

1. Which event becomes which state mutation?
2. Which fields are derived versus copied?
3. How are deltas reconciled with snapshots?
4. What assumptions are embedded in reducer behavior?

## Interpretation

Reducer analysis provides the state-machine layer needed to interpret
downstream order and risk boundaries.

## Limitations

The public corpus represents the investigated implementation surface,
not every possible production message or state.
