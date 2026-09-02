# CASE-003 — TraderState Ingress and Consumption

## Objective

Reconstruct how TraderState-related information enters the observed
application/runtime flow and where it is consumed.

## Evidence

- sana/trader-state/TRADERSTATE_GROUND_TRUTH_v1_2.json
- sana/trader-state/traderstate_ingress_ground_truth_v11.py
- sana/trader-state/traderstate_ingress_ground_truth_v12.py
- sana/trader-state/PHOENIX_TRADERSTATE_CONSUMER_v13_1.txt
- sana/trader-state/PHOENIX_TRADERSTATE_CONFIG_TRACE_v12_5.txt
- sana/trader-state/PHOENIX_TRADERSTATE_EVENT_EMITTER_v13_2.txt

## Questions

1. Where does TraderState enter the observed flow?
2. Which consumers depend on it?
3. Which fields are propagated downstream?
4. Where are state-derived values used by order/risk logic?

## Interpretation

The artifacts provide complementary views of TraderState ingress,
configuration, consumption and emission.

## Limitations

These artifacts are forensic traces and analysis outputs, not a
complete specification of the production TraderState system.
