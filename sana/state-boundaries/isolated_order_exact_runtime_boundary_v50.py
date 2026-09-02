import json
import re
from pathlib import Path
from collections import deque

ROOT = Path(r"SANA_FORENSICS_ROOT")
BUNDLE = ROOT / "data" / "raw" / "sana_bundle.js"
REPORTS = ROOT / "data" / "reports"
CORPUS = ROOT / "data" / "corpus"

text = BUNDLE.read_text(
    encoding="utf-8",
    errors="replace"
)

def compact(s):
    return re.sub(r"\s+", " ", s).strip()

def ctx(source, pos, before=2500, after=5000):
    return compact(
        source[
            max(0, pos-before):
            min(len(source), pos+after)
        ]
    )

def balanced(source, start, opener="{", limit=250000):
    p = source.find(opener, start)

    if p < 0:
        return None

    pairs = {
        "{": "}",
        "(": ")",
        "[": "]"
    }

    reverse = {
        "}": "{",
        ")": "(",
        "]": "["
    }

    stack = []
    quote = None
    escaped = False
    line_comment = False
    block_comment = False

    i = p
    end = min(
        len(source),
        start + limit
    )

    while i < end:

        ch = source[i]
        nx = (
            source[i+1]
            if i + 1 < end
            else ""
        )

        if line_comment:
            if ch in "\r\n":
                line_comment = False
            i += 1
            continue

        if block_comment:
            if ch == "*" and nx == "/":
                block_comment = False
                i += 2
                continue
            i += 1
            continue

        if quote is not None:

            if escaped:
                escaped = False

            elif ch == "\\":
                escaped = True

            elif ch == quote:
                quote = None

            i += 1
            continue

        if ch == "/" and nx == "/":
            line_comment = True
            i += 2
            continue

        if ch == "/" and nx == "*":
            block_comment = True
            i += 2
            continue

        if ch in ("'", '"', ""):
            quote = ch
            i += 1
            continue

        if ch in pairs:
            stack.append(ch)

        elif ch in reverse:

            if not stack:
                return None

            if stack[-1] != reverse[ch]:
                return None

            stack.pop()

            if not stack:
                return source[
                    start:i+1
                ]

        i += 1

    return None

def exact_refs(
    source,
    pattern,
    flags=0,
    limit=2000
):
    out = []

    for m in re.finditer(
        pattern,
        source,
        flags
    ):
        out.append({
            "offset":
                m.start(),

            "match":
                m.group(0)
        })

        if len(out) >= limit:
            break

    return out

# ============================================================
# 1. RECUPERAR EXACTAMENTE LOS OBJETOS EXPORTADOS
# ============================================================

place_export = re.search(
    r"\bplaceOrder\s*:\s*R\b",
    text
)

limit_export = re.search(
    r"\bplaceIsolatedLimitOrder\s*:",
    text
)

market_export = re.search(
    r"\bplaceIsolatedMarketOrder\s*:",
    text
)

if not place_export:
    raise RuntimeError(
        "placeOrder:R no encontrado"
    )

# ============================================================
# 2. LOCALIZAR EL OBJECT LITERAL QUE CONTIENE
#    placeIsolatedLimitOrder/placeIsolatedMarketOrder
# ============================================================

def containing_object(pos, search_back=50000):
    start = max(
        0,
        pos-search_back
    )

    region = text[
        start:
        pos
    ]

    # encontrar los últimos "{" candidatos y comprobar
    # cuál balancea hasta más allá de pos
    candidates = [
        m.start()
        for m in re.finditer(
            r"\{",
            region
        )
    ]

    candidates.reverse()

    for local in candidates[:5000]:

        absolute = start + local

        raw = balanced(
            text,
            absolute,
            "{",
            150000
        )

        if not raw:
            continue

        end = (
            absolute +
            len(raw)
        )

        if absolute <= pos <= end:

            return {
                "offset":
                    absolute,

                "length":
                    len(raw),

                "code":
                    compact(raw)
            }

    return None

objects = {}

for name, match in [
    (
        "placeOrder",
        place_export
    ),

    (
        "placeIsolatedLimitOrder",
        limit_export
    ),

    (
        "placeIsolatedMarketOrder",
        market_export
    ),
]:

    if not match:
        continue

    obj = containing_object(
        match.start()
    )

    if obj:

        objects[
            name
        ] = obj

# ============================================================
# 3. RESOLVER DE PROPERTY VALUE
# ============================================================

def property_binding(
    name,
    source
):

    m = re.search(
        rf"\b{re.escape(name)}\s*:\s*"
        r"([A-Za-z_$][A-Za-z0-9_$]*)",
        source
    )

    if not m:
        return None

    return {
        "property":
            name,

        "binding":
            m.group(1),

        "offset":
            m.start(),

        "text":
            m.group(0)
    }

bindings = {}

for name, obj in objects.items():

    value = property_binding(
        name,
        obj["code"]
    )

    if value:
        bindings[
            name
        ] = value

# ============================================================
# 4. DEFINICIONES GENERICAS
# ============================================================

def definitions_for(name):

    out = []
    seen = set()

    patterns = [

        rf"\bfunction\s+{re.escape(name)}\s*\(",

        rf"\b{re.escape(name)}\s*=\s*",

        rf"\b{re.escape(name)}\s*:\s*",

        rf"\bconst\s+{re.escape(name)}\b",

        rf"\blet\s+{re.escape(name)}\b",

        rf"\bvar\s+{re.escape(name)}\b",
    ]

    for pattern in patterns:

        for m in re.finditer(
            pattern,
            text
        ):

            p = m.start()

            if p in seen:
                continue

            seen.add(p)

            raw = balanced(
                text,
                p,
                "{",
                180000
            )

            if not raw:
                continue

            out.append({

                "offset":
                    p,

                "length":
                    len(raw),

                "declaration":
                    m.group(0),

                "code":
                    compact(raw)
            })

    return out

# ============================================================
# 5. RESOLVER CORRECTO DE LAS FUNCIONES:
#    placeIsolated* SON PROPIEDADES ALIAS.
#    HAY QUE SEGUIR EL VALUE DEL PROPERTY.
# ============================================================

isolated_resolution = {}

for target in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder"
]:

    obj = objects.get(
        target
    )

    bind = bindings.get(
        target
    )

    rows = []

    if bind:

        defs = definitions_for(
            bind[
                "binding"
            ]
        )

        for d in defs:

            score = 0
            low = d[
                "code"
            ].lower()

            for term in [
                "authority",
                "symbol",
                "side",
                "price",
                "priceusd",
                "baseunits",
                "quantity",
                "numbaselots",
                "orderflags",
                "reduceonly",
                "leverage",
                "sessionmanager",
                "wallet",
                "sign",
                "transaction",
                "send",
                "request",
                "rpc",
            ]:

                if term in low:
                    score += 1

            rows.append({

                **d,

                "semanticScore":
                    score
            })

        rows.sort(
            key=lambda x: (
                x[
                    "semanticScore"
                ],
                x[
                    "length"
                ]
            ),
            reverse=True
        )

    isolated_resolution[
        target
    ] = {

        "property":
            obj,

        "binding":
            bind,

        "definitions":
            rows[:30]
    }

# ============================================================
# 6. PLACEORDER -> R
# ============================================================

r_binding = property_binding(
    "placeOrder",
    objects[
        "placeOrder"
    ][
        "code"
    ]
)

if not r_binding:
    raise RuntimeError(
        "No se pudo resolver placeOrder:R"
    )

r_defs = definitions_for(
    r_binding[
        "binding"
    ]
)

if not r_defs:
    raise RuntimeError(
        "No se encontró definición de R"
    )

# La R ya fue encontrada previamente en 452460.
r_defs.sort(
    key=lambda x: (
        x[
            "length"
        ],
        x[
            "offset"
        ]
    ),
    reverse=True
)

# Preferir la R que contenga placeIsolated*
r_def = max(
    r_defs,
    key=lambda x: (
        int(
            "placeIsolatedLimitOrder"
            in x[
                "code"
            ]
        ),
        int(
            "placeIsolatedMarketOrder"
            in x[
                "code"
            ]
        ),
        x[
            "length"
        ]
    )
)

r_code = r_def[
    "code"
]

# ============================================================
# 7. EXTRAER ARGUMENTOS EXACTOS DE R
# ============================================================

def extract_call_args(
    source,
    name
):

    rows = []

    for m in re.finditer(
        rf"\b{re.escape(name)}\s*\(",
        source
    ):

        p = m.start()

        raw = balanced(
            source,
            p,
            "(",
            30000
        )

        if not raw:
            continue

        # raw incluye (...)
        args = raw[
            1:-1
        ]

        rows.append({

            "offset":
                p,

            "args":
                compact(args)
        })

    return rows

r_calls = {}

for target in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
    "buildLimitOrderPacket",
    "buildMarketOrderPacket",
    "buildPlaceLimitOrder",
    "buildPlaceMarketOrder",
]:

    r_calls[
        target
    ] = extract_call_args(
        r_code,
        target
    )

# ============================================================
# 8. RESOLVER BINDINGS DE LOS BUILDER CALLS
# ============================================================

builder_resolution = {}

for target in [
    "buildLimitOrderPacket",
    "buildMarketOrderPacket",
    "buildPlaceLimitOrder",
    "buildPlaceMarketOrder",
]:

    rows = []

    for call in r_calls[
        target
    ]:

        args = call[
            "args"
        ]

        # Los builders pueden ser alias locales:
        #     async = ...
        #     r = ...
        #     a = ...
        # No asumir por nombre. Guardamos argumentos exactos.
        rows.append({

            "offset":
                call[
                    "offset"
                ],

            "arguments":
                args
        })

    builder_resolution[
        target
    ] = rows

# ============================================================
# 9. ANALIZAR LAS DEFINICIONES RESUELTAS DE placeIsolated*
# ============================================================

isolated_details = {}

for target, item in isolated_resolution.items():

    rows = []

    for d in item[
        "definitions"
    ][:10]:

        code = d[
            "code"
        ]

        order_fields = [
            x
            for x in [
                "authority",
                "symbol",
                "side",
                "price",
                "priceUsd",
                "baseUnits",
                "quantity",
                "numBaseLots",
                "orderFlags",
                "reduceOnly",
                "leverage",
                "orderType",
                "subaccountIndex"
            ]
            if re.search(
                rf"\b{re.escape(x)}\b",
                code,
                flags=re.I
            )
        ]

        state_fields = [
            x
            for x in [
                "collateral",
                "marginInputs",
                "ordersBySymbol",
                "ordersBySequence",
                "positionsBySymbol",
                "subaccountsByIndex",
                "sequence",
                "slot",
                "version",
                "lastMessage",
            ]
            if re.search(
                rf"\b{re.escape(x)}\b",
                code,
                flags=re.I
            )
        ]

        auth_fields = [
            x
            for x in [
                "sessionManager",
                "knownAuthToken",
                "wallet",
                "sign",
                "transaction",
                "sendTransaction",
                "signAndSend"
            ]
            if re.search(
                rf"\b{re.escape(x)}\b",
                code,
                flags=re.I
            )
        ]

        calls = sorted(
            set(
                m.group(1)
                for m in re.finditer(
                    r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
                    code
                )
                if m.group(1)
                not in {
                    "if",
                    "for",
                    "while",
                    "switch",
                    "catch",
                    "return",
                    "throw",
                    "Error",
                    "Number",
                    "String",
                    "Object",
                    "Array",
                    "Math",
                    "JSON",
                }
            )
        )

        rows.append({

            "offset":
                d[
                    "offset"
                ],

            "length":
                d[
                    "length"
                ],

            "semanticScore":
                d[
                    "semanticScore"
                ],

            "orderFields":
                order_fields,

            "stateFields":
                state_fields,

            "authFields":
                auth_fields,

            "calls":
                calls,

            "code":
                code
        })

    isolated_details[
        target
    ] = rows

# ============================================================
# 10. RESOLVER DE LOS CALLEES DE placeIsolated*
# ============================================================

def best_definition(
    name,
    caller_offset=None
):

    defs = definitions_for(
        name
    )

    if not defs:
        return None

    def rank(d):

        low = d[
            "code"
        ].lower()

        semantic = sum(
            token in low
            for token in [
                "order",
                "orders",
                "limit",
                "market",
                "isolated",
                "perp",
                "position",
                "transaction",
                "request",
                "rpc",
                "send",
                "sign",
                "wallet",
                "sessionmanager",
                "authority",
                "symbol",
                "side",
                "price",
                "size",
                "reduceonly",
                "leverage",
            ]
        )

        distance = (
            abs(
                d[
                    "offset"
                ]
                -
                caller_offset
            )
            if caller_offset is not None
            else
            10**12
        )

        return (
            semantic,
            -distance,
            d[
                "length"
            ]
        )

    return max(
        defs,
        key=rank
    )

isolated_call_graph = []

for target, rows in isolated_details.items():

    for row in rows[:5]:

        caller_offset = row[
            "offset"
        ]

        for callee in row[
            "calls"
        ]:

            definition = best_definition(
                callee,
                caller_offset
            )

            if not definition:
                continue

            code = definition[
                "code"
            ]

            low = code.lower()

            isolated_call_graph.append({

                "caller":
                    target,

                "callerOffset":
                    caller_offset,

                "callee":
                    callee,

                "calleeOffset":
                    definition[
                        "offset"
                    ],

                "calleeLength":
                    definition[
                        "length"
                    ],

                "order":
                    [
                        x
                        for x in [
                            "order",
                            "orders",
                            "limit",
                            "market",
                            "isolated",
                            "perp",
                            "position",
                            "symbol",
                            "side",
                            "price",
                            "size",
                            "reduceOnly",
                            "leverage"
                        ]
                        if x.lower() in low
                    ],

                "state":
                    [
                        x
                        for x in [
                            "collateral",
                            "marginInputs",
                            "ordersBySymbol",
                            "ordersBySequence",
                            "positionsBySymbol",
                            "subaccountsByIndex",
                            "sequence",
                            "slot",
                            "version"
                        ]
                        if x.lower() in low
                    ],

                "auth":
                    [
                        x
                        for x in [
                            "sessionManager",
                            "knownAuthToken",
                            "wallet",
                            "sign",
                            "transaction",
                            "sendTransaction",
                            "signAndSend"
                        ]
                        if x.lower() in low
                    ],

                "network":
                    [
                        x
                        for x in [
                            "fetch",
                            "request",
                            "rpc",
                            "send",
                            "submit",
                            "execute",
                            "mutate"
                        ]
                        if x.lower() in low
                    ],

                "code":
                    code
            })

# ============================================================
# 11. EXACT PARAMETER DATAFLOW IN R
# ============================================================

parameter_fields = [
    "symbol",
    "side",
    "price",
    "priceUsd",
    "baseUnits",
    "quantity",
    "numBaseLots",
    "orderFlags",
    "reduceOnly",
    "leverage",
    "orderType",
    "subaccountIndex",
]

parameter_flow = []

for target, rows in r_calls.items():

    if not rows:
        continue

    for call in rows:

        args = call[
            "args"
        ]

        for field in parameter_fields:

            for m in re.finditer(
                rf"\b{re.escape(field)}\s*:\s*([^,}}]+)",
                args,
                flags=re.I
            ):

                expression = compact(
                    m.group(1)
                )

                refs_state = [
                    x
                    for x in [
                        "collateral",
                        "marginInputs",
                        "ordersBySymbol",
                        "ordersBySequence",
                        "positionsBySymbol",
                        "subaccountsByIndex",
                        "sequence",
                        "slot",
                        "version"
                    ]
                    if re.search(
                        rf"\b{re.escape(x)}\b",
                        expression,
                        flags=re.I
                    )
                ]

                parameter_flow.append({

                    "target":
                        target,

                    "offset":
                        call[
                            "offset"
                        ],

                    "field":
                        field,

                    "expression":
                        expression,

                    "stateRefs":
                        refs_state,

                    "arguments":
                        args
                })

# ============================================================
# 12. STATIC CORE
# ============================================================

process_identity = (
    "e.authority!==t"
    in text
    and
    "e.traderPdaIndex!==r"
    in text
)

process_sequence_guard = bool(
    re.search(
        r"processMessage:"
        r".{0,7000}"
        r"e\.sequence\s*"
        r"(?:!==|!=|===|==|<|>|<=|>=)",
        text
    )
)

delta_sequence_guard = bool(
    re.search(
        r"t\.deltas"
        r".{0,15000}"
        r"(?:e|t)\.sequence\s*"
        r"(?:!==|!=|===|==|<|>|<=|>=)",
        text
    )
)

order_sequence_guard = bool(
    re.search(
        r"pF=\(e,t\)=>"
        r".{0,15000}"
        r"orderSequenceNumber\s*"
        r"(?:!==|!=|===|==|<|>|<=|>=)",
        text
    )
)

# ============================================================
# 13. HARD BOUNDARY
# ============================================================

isolated_limit_resolved = (
    bool(
        isolated_resolution[
            "placeIsolatedLimitOrder"
        ][
            "binding"
        ]
    )
    and
    len(
        isolated_details[
            "placeIsolatedLimitOrder"
        ]
    )
    >
    0
)

isolated_market_resolved = (
    bool(
        isolated_resolution[
            "placeIsolatedMarketOrder"
        ][
            "binding"
        ]
    )
    and
    len(
        isolated_details[
            "placeIsolatedMarketOrder"
        ]
    )
    >
    0
)

isolated_network = any(
    x[
        "network"
    ]
    for x in isolated_call_graph
)

isolated_auth = any(
    x[
        "auth"
    ]
    for x in isolated_call_graph
)

isolated_state = any(
    x[
        "state"
    ]
    for x in isolated_call_graph
)

isolated_order = any(
    x[
        "order"
    ]
    for x in isolated_call_graph
)

# ============================================================
# 14. CLASSIFICATION
# ============================================================

if (
    isolated_limit_resolved
    and
    isolated_market_resolved
    and
    isolated_order
    and
    isolated_network
    and
    isolated_auth
):

    classification = (
        "EXACT_ISOLATED_ORDER_NETWORK_AUTH_PATH"
    )

elif (
    (isolated_limit_resolved
     or
     isolated_market_resolved)
    and
    isolated_order
    and
    isolated_network
):

    classification = (
        "EXACT_ISOLATED_ORDER_NETWORK_PATH"
    )

elif (
    isolated_limit_resolved
    or
    isolated_market_resolved
):

    classification = (
        "EXACT_ISOLATED_ORDER_FUNCTION_PATH"
    )

else:

    classification = (
        "ISOLATED_ORDER_ALIAS_UNRESOLVED"
    )

# ============================================================
# 15. REPORT
# ============================================================

report = {

    "bundle": {
        "path":
            str(BUNDLE),

        "bytes":
            len(
                text.encode(
                    "utf-8"
                )
            )
    },

    "placeOrder":
        {
            "binding":
                binding
                if "binding" in locals()
                else
                r_binding[
                    "binding"
                ],

            "property":
                "placeOrder",

            "propertyOffset":
                place_export.start(),

            "rBinding":
                r_binding,
        },

    "objects":
        objects,

    "bindings":
        bindings,

    "rDefinition":
        r_def,

    "rCalls":
        r_calls,

    "builderResolution":
        builder_resolution,

    "isolatedResolution":
        isolated_resolution,

    "isolatedDetails":
        isolated_details,

    "isolatedCallGraph":
        isolated_call_graph,

    "parameterFlow":
        parameter_flow,

    "static":
        {
            "processIdentityGuard":
                process_identity,

            "processSequenceGuard":
                process_sequence_guard,

            "deltaSequenceGuard":
                delta_sequence_guard,

            "orderSequenceGuard":
                order_sequence_guard,

            "orderReplacement":
                "a[t.orderSequenceNumber]=pE(t)"
                in text,

            "orderCloseDelete":
                "delete a[t.orderSequenceNumber]"
                in text,
        },

    "milestone":
        {
            "isolatedLimitResolved":
                isolated_limit_resolved,

            "isolatedMarketResolved":
                isolated_market_resolved,

            "isolatedOrder":
                isolated_order,

            "isolatedState":
                isolated_state,

            "isolatedNetwork":
                isolated_network,

            "isolatedAuth":
                isolated_auth,

            "classification":
                classification,

            "productionBugConfirmed":
                False,

            "backendBehaviorConfirmed":
                False,

            "runtimeImpactConfirmed":
                False,

            "transactionSent":
                False,

            "walletUsed":
                False
        }
}

report_path = (
    REPORTS /
    "ISOLATED_ORDER_EXACT_RUNTIME_BOUNDARY_v5_0.json"
)

with open(
    report_path,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        report,
        f,
        indent=2,
        ensure_ascii=False
    )

# ============================================================
# CORPUS
# ============================================================

exports = {

    "OBJECTS.json":
        objects,

    "BINDINGS.json":
        bindings,

    "R.json":
        r_def,

    "R_CALLS.json":
        r_calls,

    "BUILDERS.json":
        builder_resolution,

    "ISOLATED_RESOLUTION.json":
        isolated_resolution,

    "ISOLATED_DETAILS.json":
        isolated_details,

    "ISOLATED_CALLGRAPH.json":
        isolated_call_graph,

    "PARAMETER_FLOW.json":
        parameter_flow,

    "MILESTONE.json":
        report[
            "milestone"
        ],
}

for name, obj in exports.items():

    path = (
        CORPUS /
        f"ISOLATED_ORDER_{name}"
    )

    path.write_text(
        json.dumps(
            obj,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

# ============================================================
# PRINT
# ============================================================

print("=" * 115)
print("SANA FORENSICS — ISOLATED ORDER EXACT RUNTIME BOUNDARY v5.0")
print("=" * 115)

print()
print("EXPORT BINDINGS")

for name, item in bindings.items():

    print(
        name,
        "->",
        item[
            "binding"
        ]
    )

print()
print("R")

print(
    "offset:",
    r_def[
        "offset"
    ]
)

print(
    "length:",
    r_def[
        "length"
    ]
)

print()
print("R CALLS")

for target, rows in r_calls.items():

    print()
    print(
        target,
        "count=",
        len(rows)
    )

    for row in rows:

        print(
            "  @",
            row[
                "offset"
            ]
        )

        print(
            "  ",
            row[
                "args"
            ]
        )

print()
print("ISOLATED RESOLUTION")

for target, item in isolated_resolution.items():

    print()
    print(
        target
    )

    if item[
        "binding"
    ]:

        print(
            "  binding:",
            item[
                "binding"
            ][
                "binding"
            ]
        )

    print(
        "  definitions:",
        len(
            item[
                "definitions"
            ]
        )
    )

    for d in item[
        "definitions"
    ][:5]:

        print(
            "   DEF",
            d[
                "offset"
            ],
            "len=",
            d[
                "length"
            ],
            "score=",
            d[
                "semanticScore"
            ]
        )

print()
print("ISOLATED DETAILS")

for target, rows in isolated_details.items():

    print()
    print(
        target,
        "rows=",
        len(rows)
    )

    for row in rows[:10]:

        print(
            "  OFFSET:",
            row[
                "offset"
            ]
        )

        print(
            "  ORDER:",
            row[
                "orderFields"
            ]
        )

        print(
            "  STATE:",
            row[
                "stateFields"
            ]
        )

        print(
            "  AUTH:",
            row[
                "authFields"
            ]
        )

        print(
            "  CALLS:",
            row[
                "calls"
            ]
        )

print()
print("CALL GRAPH")

for row in isolated_call_graph[:100]:

    print()

    print(
        row[
            "caller"
        ],
        "->",
        row[
            "callee"
        ]
    )

    print(
        "  offset:",
        row[
            "calleeOffset"
        ]
    )

    print(
        "  ORDER:",
        row[
            "order"
        ]
    )

    print(
        "  STATE:",
        row[
            "state"
        ]
    )

    print(
        "  AUTH:",
        row[
            "auth"
        ]
    )

    print(
        "  NETWORK:",
        row[
            "network"
        ]
    )

print()
print("PARAMETER FLOW")

for row in parameter_flow[:100]:

    print()

    print(
        row[
            "target"
        ],
        row[
            "field"
        ],
        "<=",
        row[
            "expression"
        ]
    )

    print(
        "STATE:",
        row[
            "stateRefs"
        ]
    )

print()
print("STATIC")

for k,v in report[
    "static"
].items():

    print(
        f"{k:34s}:",
        v
    )

print()
print("MILESTONE")

for k,v in report[
    "milestone"
].items():

    print(
        f"{k:34s}:",
        v
    )

print()
print(
    "CLASSIFICATION:",
    classification
)

print(
    "REPORT:",
    report_path
)

print(
    "CORPUS:",
    CORPUS
)

print("=" * 115)

