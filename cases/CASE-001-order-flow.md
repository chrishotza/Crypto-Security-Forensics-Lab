# CASE-001 — Order Construction to Transaction

## Objective

Reconstruct the path by which an order moves from the application
surface through provider/module boundaries and into transaction
construction.

## Evidence

- sana/order-flow/order_exact_provider_to_tx_v62.py
- sana/order-flow/order_implementation_to_transaction_v54.py
- sana/order-flow/order_provider_transaction_trace_v63.py
- sana/order-flow/placeorder_callgraph_exact_v44.py
- sana/execution/placeorder_exact_dataflow_v34.py
- sana/execution/order_execution_dataflow_v47.py

## Questions

1. Where is the order object constructed?
2. Which provider/module receives it next?
3. Which parameters survive each boundary?
4. Where does execution become transaction construction?

## Interpretation

The public corpus contains static, data-flow and call-graph artifacts
for reconstructing this chain. These artifacts document an analysis
path; they do not by themselves establish a security vulnerability.

## Reproduction

Reproduction requires the published scripts plus any explicitly
documented input artifacts they reference. Historical private bundles
and runtime state are intentionally outside the public corpus.

## Limitations

The complete historical working environment is not published.
