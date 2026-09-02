# Case Index

## 1. Order Flow

Core artifacts:

- `sana/order-flow/order_exact_provider_to_tx_v62.py`
- `sana/order-flow/order_implementation_to_transaction_v54.py`
- `sana/order-flow/orders_provider_implementation_trace_v64.py`
- `sana/order-flow/order_provider_transaction_trace_v63.py`
- `sana/order-flow/placeorder_callgraph_exact_v44.py`

Questions addressed:

- Where is an order constructed?
- Which provider/module owns the next transition?
- How do parameters propagate?
- Where does execution become transaction construction?

## 2. State / Boundary Analysis

- `sana/state-boundaries/STATE_TO_RISK_BOUNDARY_EXACT_v3_1.txt`
- `sana/state-boundaries/order_send_exact_boundary_v37.py`
- `sana/state-boundaries/isolated_order_exact_runtime_boundary_v50.py`
- `sana/state-boundaries/provider_order_module_boundary_v52.py`

## 3. TraderState

- `sana/trader-state/TRADERSTATE_GROUND_TRUTH_v1_2.json`
- `sana/trader-state/traderstate_ingress_ground_truth_v11.py`
- `sana/trader-state/traderstate_ingress_ground_truth_v12.py`
- `sana/trader-state/PHOENIX_TRADERSTATE_CONSUMER_v13_1.txt`
- `sana/trader-state/PHOENIX_TRADERSTATE_CONFIG_TRACE_v12_5.txt`
- `sana/trader-state/PHOENIX_TRADERSTATE_EVENT_EMITTER_v13_2.txt`

## 4. Rollback / Reducers

- `sana/rollback/GROUND_TRUTH_ROLLBACK_DIFFERENTIAL_v1_8.txt`
- `sana/rollback/ROLLBACK_GROUND_TRUTH_v2_0.json`
- `sana/rollback/SLOT_ROLLBACK_GROUND_TRUTH_v1_6.json`
- `sana/reducers/GROUND_TRUTH_TRADER_DELTA_REDUCER.txt`
- `sana/reducers/GROUND_TRUTH_TRADER_SNAPSHOT_REDUCER.txt`

## 5. Phoenix / SBPF

- `phoenix/runtime/`
- `phoenix/sbpf/interpreter.rs`
- `phoenix/sbpf/memory_region.rs`
- `phoenix/sbpf/memory_management.rs`
- `phoenix/sbpf/aligned_memory.rs`

The Phoenix materials document execution/runtime investigation
rather than a complete standalone Phoenix reproduction environment.
