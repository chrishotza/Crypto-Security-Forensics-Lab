# CASE-004 — Rollback and Differential State Behavior

## Objective

Examine state transitions under rollback/differential conditions and
identify invariants or discrepancies worth investigating.

## Evidence

- sana/rollback/GROUND_TRUTH_ROLLBACK_DIFFERENTIAL_v1_8.txt
- sana/rollback/ROLLBACK_GROUND_TRUTH_v2_0.json
- sana/rollback/SLOT_ROLLBACK_GROUND_TRUTH_v1_6.json
- sana/rollback/slot_rollback_ground_truth_v16.py
- sana/ground-truth/GROUND_TRUTH_DIFFERENTIAL_v2_0.txt

## Questions

1. Which state changes survive a rollback?
2. Which transitions are reversible?
3. Which invariants remain stable?
4. Where do differential traces diverge?

## Interpretation

The public artifacts preserve rollback/differential analysis and provide
a basis for comparing state transitions.

## Limitations

Observed differential behavior must be tied to its exact execution
conditions before making a production security claim.
