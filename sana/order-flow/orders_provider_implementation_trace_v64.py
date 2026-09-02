import json
import re
from pathlib import Path

ROOT = Path(r"SANA_FORENSICS_ROOT")
BUNDLE = ROOT / "data" / "raw" / "sana_bundle.js"
REPORTS = ROOT / "data" / "reports"
CORPUS = ROOT / "data" / "corpus"

TEXT = BUNDLE.read_text(
    encoding="utf-8",
    errors="replace"
)

R_OFFSET = 452460

TARGETS = [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]

BUILDERS = [
    "buildLimitOrderPacket",
    "buildMarketOrderPacket",
    "buildPlaceLimitOrder",
    "buildPlaceMarketOrder",
]

SERVICE_METHOD_HINTS = [
    "placeOrder",
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
    "placeIsolated",
    "buildPlaceLimitOrder",
    "buildPlaceMarketOrder",
    "buildLimitOrderPacket",
    "buildMarketOrderPacket",
    "cancelOrder",
    "orders",
]

ORDER_FIELDS = [
    "authority",
    "symbol",
    "side",
    "price",
    "priceUsd",
    "size",
    "sizeUsd",
    "baseUnits",
    "quantity",
    "numBaseLots",
    "orderFlags",
    "reduceOnly",
    "leverage",
    "orderPacket",
    "orderType",
    "subaccountIndex",
    "orderSequenceNumber",
]

STATE_FIELDS = [
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
    "lastMessageSlot",
]

AUTH_FIELDS = [
    "sessionManager",
    "knownAuthToken",
    "wallet",
    "sign",
    "transaction",
    "signature",
    "sendTransaction",
    "signAndSend",
]

NETWORK_FIELDS = [
    "fetch",
    "request",
    "rpc",
    "send",
    "submit",
    "execute",
    "mutate",
]

def compact(s):
    return re.sub(r"\s+", " ", s).strip()

def context(pos, before=5000, after=9000):
    return compact(
        TEXT[
            max(0, pos-before):
            min(len(TEXT), pos+after)
        ]
    )

def balanced(source, start, opener="{", limit=300000):
    p = source.find(opener, start)

    if p < 0:
        return None

    pairs = {
        "{": "}",
        "(": ")",
        "[": "]",
    }

    reverse = {
        "}": "{",
        ")": "(",
        "]": "[",
    }

    stack = []
    quote = None
    escaped = False
    line_comment = False
    block_comment = False

    i = p
    end = min(len(source), start + limit)

    while i < end:

        ch = source[i]
        nx = source[i+1] if i + 1 < end else ""

        if line_comment:
            if ch in "\r\n":
                line_comment = False
            i += 1
            continue

        if block_comment:
            if ch == "*" and nx == "/":
                block_comment = False
                i += 2
            else:
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
                return source[start:i+1]

        i += 1

    return None

def find_defs(name, max_results=100):
    rows = []
    seen = set()

    patterns = [
        rf"\bfunction\s+{re.escape(name)}\s*\(",
        rf"\b(?:const|let|var)\s+{re.escape(name)}\s*=",
        rf"\b{re.escape(name)}\s*=",
        rf"\b{re.escape(name)}\s*:",
    ]

    for pattern in patterns:

        for m in re.finditer(
            pattern,
            TEXT
        ):

            p = m.start()

            if p in seen:
                continue

            seen.add(p)

            raw = balanced(
                TEXT,
                p,
                "{",
                220000
            )

            if not raw:
                continue

            rows.append({

                "offset":
                    p,

                "length":
                    len(raw),

                "declaration":
                    m.group(0),

                "code":
                    compact(raw)
            })

            if len(rows) >= max_results:
                return rows

    return rows

def find_call_args(
    source,
    call_offset
):
    open_pos = source.find(
        "(",
        call_offset
    )

    if open_pos < 0:
        return None

    raw = balanced(
        source,
        open_pos,
        "(",
        80000
    )

    if not raw:
        return None

    return compact(
        raw[1:-1]
    )

def token_hits(
    code,
    names
):
    return [
        x
        for x in names
        if re.search(
            rf"\b{re.escape(x)}\b",
            code,
            flags=re.I
        )
    ]

# ============================================================
# 1. EXACT R
# ============================================================

r_raw = balanced(
    TEXT,
    R_OFFSET,
    "{",
    15000
)

if not r_raw:
    raise RuntimeError(
        "R no encontrado"
    )

R_CODE = compact(
    r_raw
)

# ============================================================
# 2. EXACT .api.orders()
# ============================================================

orders_chain = []

for m in re.finditer(
    r"\b([A-Za-z_$][A-Za-z0-9_$]*)\.api\.orders\(\)",
    R_CODE
):

    root = m.group(1)

    orders_chain.append({

        "root":
            root,

        "offsetInR":
            m.start(),

        "absoluteOffset":
            R_OFFSET + m.start(),

        "suffix":
            compact(
                R_CODE[
                    m.start():
                    min(
                        len(R_CODE),
                        m.start()+3500
                    )
                ]
            ),

        "prefix":
            compact(
                R_CODE[
                    max(0,m.start()-3500):
                    m.start()
                ]
            )
    })

if not orders_chain:
    raise RuntimeError(
        "r.api.orders() no encontrado"
    )

# ============================================================
# 3. CAPTURAR LOS METODOS LLAMADOS SOBRE orders()
# ============================================================

orders_method_calls = []

for chain in orders_chain:

    start = chain[
        "offsetInR"
    ]

    region = R_CODE[
        start:
        min(
            len(R_CODE),
            start+9000
        )
    ]

    for m in re.finditer(
        r"\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
        region
    ):

        method = m.group(1)

        if method == "api":
            continue

        absolute = (
            R_OFFSET
            +
            start
            +
            m.start()
        )

        orders_method_calls.append({

            "root":
                chain[
                    "root"
                ],

            "method":
                method,

            "offsetInR":
                start + m.start(),

            "absoluteOffset":
                absolute,

            "arguments":
                find_call_args(
                    R_CODE,
                    start + m.start()
                ),

            "context":
                compact(
                    R_CODE[
                        max(0,start+m.start()-1500):
                        min(
                            len(R_CODE),
                            start+m.start()+4500
                        )
                    ]
                )
        })

# dedupe
uniq = {}

for row in orders_method_calls:

    key = (
        row["root"],
        row["method"],
        row["absoluteOffset"]
    )

    uniq[key] = row

orders_method_calls = list(
    uniq.values()
)

# ============================================================
# 4. RESOLVER DEL ROOT 
# ============================================================

root_assignments = []

for m in re.finditer(
    r"\b(?:const|let|var)\s+r\s*=",
    TEXT[
        max(0,R_OFFSET-100000):
        R_OFFSET
    ]
):

    p = (
        max(0,R_OFFSET-100000)
        +
        m.start()
    )

    tail = TEXT[
        p:
        min(
            len(TEXT),
            p+6000
        )
    ]

    root_assignments.append({

        "offset":
            p,

        "declaration":
            m.group(0),

        "context":
            compact(tail)
    })

# ============================================================
# 5. BUSCAR DEFINICIONES GLOBALES DE orders
# ============================================================

orders_defs = find_defs(
    "orders",
    200
)

orders_ranked = []

for d in orders_defs:

    code = d[
        "code"
    ]

    score = 0

    for term in [
        "placeIsolatedLimitOrder",
        "placeIsolatedMarketOrder",
        "buildLimitOrderPacket",
        "buildMarketOrderPacket",
        "orderPacket",
        "Transaction",
        "TransactionInstruction",
        "sendTransaction",
        "sessionManager",
        "wallet",
        "sign",
        "collateral",
        "sequence",
        "slot",
        "version",
    ]:

        if term.lower() in code.lower():
            score += 1

    # proximity to known orders definitions
    proximity = min(
        [
            abs(
                d["offset"] - x
            )
            for x in [
                351888,
                359951,
                359998
            ]
        ],
        default=999999999
    )

    orders_ranked.append({

        **d,

        "score":
            score,

        "proximity":
            proximity
    })

orders_ranked.sort(
    key=lambda x: (
        x["score"],
        -x["proximity"],
        x["length"]
    ),
    reverse=True
)

orders_selected = orders_ranked[
    :30
]

# ============================================================
# 6. EXACT METHOD MEMBERS DENTRO DE CADA orders DEFINITION
# ============================================================

orders_methods = []

for definition in orders_selected:

    code = definition[
        "code"
    ]

    for target in TARGETS:

        for m in re.finditer(
            rf"\b{re.escape(target)}\b",
            code
        ):

            local = m.start()

            orders_methods.append({

                "ordersDefinitionOffset":
                    definition[
                        "offset"
                    ],

                "ordersDefinitionLength":
                    definition[
                        "length"
                    ],

                "target":
                    target,

                "offsetInOrders":
                    local,

                "context":
                    compact(
                        code[
                            max(
                                0,
                                local-3500
                            ):
                            min(
                                len(code),
                                local+9000
                            )
                        ]
                    )
            })

# ============================================================
# 7. BUSCAR TAMBIEN LAS CADENAS DE SERVICIO EN EL CONTEXTO
#    DE LOS ORDERS DEFINITIONS
# ============================================================

orders_service_calls = []

for definition in orders_selected:

    code = definition[
        "code"
    ]

    for m in re.finditer(
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
        code
    ):

        name = m.group(1)

        if (
            name in [
                "if",
                "for",
                "while",
                "switch",
                "catch",
                "return",
                "throw",
                "Error",
                "Object",
                "Array",
                "Number",
                "String",
                "Boolean",
                "Math",
                "JSON"
            ]
        ):
            continue

        around_call = compact(
            code[
                max(
                    0,
                    m.start()-1200
                ):
                min(
                    len(code),
                    m.start()+3500
                )
            ]
        )

        semantic_score = (
            len(
                token_hits(
                    around_call,
                    ORDER_FIELDS
                )
            )
            +
            len(
                token_hits(
                    around_call,
                    AUTH_FIELDS
                )
            )
            +
            len(
                token_hits(
                    around_call,
                    NETWORK_FIELDS
                )
            )
        )

        if semantic_score < 3:
            continue

        orders_service_calls.append({

            "ordersDefinitionOffset":
                definition[
                    "offset"
                ],

            "name":
                name,

            "offsetInOrders":
                m.start(),

            "score":
                semantic_score,

            "order":
                token_hits(
                    around_call,
                    ORDER_FIELDS
                ),

            "state":
                token_hits(
                    around_call,
                    STATE_FIELDS
                ),

            "auth":
                token_hits(
                    around_call,
                    AUTH_FIELDS
                ),

            "network":
                token_hits(
                    around_call,
                    NETWORK_FIELDS
                ),

            "context":
                around_call
        })

# ============================================================
# 8. DEFINICIONES DE LAS FUNCIONES QUE APARECEN CERCA
#    DE placeIsolated* EN orders
# ============================================================

candidate_names = sorted(
    set(
        [
            row[
                "name"
            ]
            for row in orders_service_calls
        ]
        +
        TARGETS
    )
)

candidate_definitions = {}

for name in candidate_names:

    defs = find_defs(
        name,
        100
    )

    ranked = []

    for d in defs:

        code = d[
            "code"
        ]

        semantic = (
            len(
                token_hits(
                    code,
                    ORDER_FIELDS
                )
            )
            +
            len(
                token_hits(
                    code,
                    STATE_FIELDS
                )
            )
            +
            len(
                token_hits(
                    code,
                    AUTH_FIELDS
                )
            )
            +
            len(
                token_hits(
                    code,
                    NETWORK_FIELDS
                )
            )
        )

        target_hits = sum(
            term.lower()
            in
            code.lower()
            for term in
            [
                "placeIsolatedLimitOrder",
                "placeIsolatedMarketOrder",
                "buildPlaceLimitOrder",
                "buildPlaceMarketOrder",
                "TransactionInstruction",
                "sendTransaction",
            ]
        )

        ranked.append({

            **d,

            "semantic":
                semantic,

            "targetHits":
                target_hits
        })

    ranked.sort(
        key=lambda x: (
            x[
                "targetHits"
            ],
            x[
                "semantic"
            ],
            x[
                "length"
            ]
        ),
        reverse=True
    )

    candidate_definitions[
        name
    ] = ranked[
        :20
    ]

# ============================================================
# 9. EXACT BUILDER DEFINITIONS
# ============================================================

builder_details = {}

for name in BUILDERS:

    rows = []

    for d in find_defs(
        name,
        100
    ):

        code = d[
            "code"
        ]

        rows.append({

            "offset":
                d["offset"],

            "length":
                d["length"],

            "order":
                token_hits(
                    code,
                    ORDER_FIELDS
                ),

            "state":
                token_hits(
                    code,
                    STATE_FIELDS
                ),

            "auth":
                token_hits(
                    code,
                    AUTH_FIELDS
                ),

            "network":
                token_hits(
                    code,
                    NETWORK_FIELDS
                ),

            "calls":
                sorted(
                    set(
                        m.group(1)
                        for m in re.finditer(
                            r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
                            code
                        )
                    )
                ),

            "code":
                code
        })

    builder_details[
        name
    ] = rows

# ============================================================
# 10. TRANSACTION SITES, BUT ONLY THOSE NEAR ORDER SERVICE
# ============================================================

tx_sites = []

for pattern in [
    r"\bTransactionInstruction\s*\(",
    r"\bTransaction\s*\(",
    r"\bsendTransaction\s*\(",
    r"\bsignAndSend\s*\(",
    r"\bsignTransaction\s*\(",
]:

    for m in re.finditer(
        pattern,
        TEXT,
        flags=re.I
    ):

        p = m.start()

        c = context(
            p,
            10000,
            12000
        )

        order_hits = token_hits(
            c,
            TARGETS
            +
            BUILDERS
            +
            ORDER_FIELDS
        )

        auth_hits = token_hits(
            c,
            AUTH_FIELDS
        )

        state_hits = token_hits(
            c,
            STATE_FIELDS
        )

        # We want concrete transaction/order contexts,
        # not every wallet transaction in the bundle.
        if (
            len(order_hits) >= 2
            or
            (
                len(order_hits) >= 1
                and
                len(auth_hits) >= 2
            )
        ):

            tx_sites.append({

                "offset":
                    p,

                "term":
                    m.group(0),

                "order":
                    order_hits,

                "state":
                    state_hits,

                "auth":
                    auth_hits,

                "context":
                    c
            })

# ============================================================
# 11. MATCH TRANSACTION SITES AGAINST ORDERS DEFINITIONS
# ============================================================

orders_to_tx_links = []

for od in orders_selected:

    od_start = od[
        "offset"
    ]

    od_end = (
        od_start
        +
        od[
            "length"
        ]
    )

    for tx in tx_sites:

        p = tx[
            "offset"
        ]

        if (
            od_start
            <=
            p
            <=
            od_end
        ):

            orders_to_tx_links.append({

                "ordersOffset":
                    od_start,

                "ordersLength":
                    od[
                        "length"
                    ],

                "transactionOffset":
                    p,

                "transaction":
                    tx
            })

# ============================================================
# 12. SEARCH FOR R PARAMETER EXPRESSIONS THAT ARE STATE-BACKED
# ============================================================

r_state_parameter_links = []

for method in TARGETS:

    for m in re.finditer(
        rf"\b{re.escape(method)}\s*\(",
        R_CODE
    ):

        args = find_call_args(
            R_CODE,
            m.start()
        )

        if not args:
            continue

        for field, expr in re.findall(
            r"(?:^|[,{])\s*"
            r"([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*:\s*"
            r"([^,}]+)",
            args
        ):

            state_refs = token_hits(
                expr,
                STATE_FIELDS
            )

            if state_refs:

                r_state_parameter_links.append({

                    "method":
                        method,

                    "field":
                        field,

                    "expression":
                        compact(expr),

                    "state":
                        state_refs,

                    "offsetInR":
                        m.start()
                })

# ============================================================
# 13. EXACT GLOBAL ORDER API REFERENCES
# ============================================================

all_order_api_refs = []

for target in TARGETS:

    for m in re.finditer(
        rf"\b{re.escape(target)}\b",
        TEXT
    ):

        p = m.start()

        all_order_api_refs.append({

            "target":
                target,

            "offset":
                p,

            "prefix":
                compact(
                    TEXT[
                        max(0,p-2500):
                        p
                    ]
                ),

            "suffix":
                compact(
                    TEXT[
                        p:
                        min(
                            len(TEXT),
                            p+3500
                        )
                    ]
                )
        })

# ============================================================
# 14. STATIC CORE
# ============================================================

static = {

    "processIdentityGuard":
        (
            "e.authority!==t"
            in TEXT
            and
            "e.traderPdaIndex!==r"
            in TEXT
        ),

    "processSequenceGuard":
        bool(
            re.search(
                r"processMessage:"
                r".{0,7000}"
                r"e\.sequence\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                TEXT
            )
        ),

    "deltaSequenceGuard":
        bool(
            re.search(
                r"t\.deltas"
                r".{0,15000}"
                r"(?:e|t)\.sequence\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                TEXT
            )
        ),

    "orderSequenceGuard":
        bool(
            re.search(
                r"pF=\(e,t\)=>"
                r".{0,15000}"
                r"orderSequenceNumber\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                TEXT
            )
        ),

    "orderWholeReplacement":
        (
            "a[t.orderSequenceNumber]=pE(t)"
            in TEXT
        ),

    "orderCloseDelete":
        (
            "delete a[t.orderSequenceNumber]"
            in TEXT
        )
}

# ============================================================
# 15. MILESTONE
# ============================================================

limit_chain = [
    x
    for x in orders_method_calls
    if x[
        "method"
    ]
    ==
    "placeIsolatedLimitOrder"
]

market_chain = [
    x
    for x in orders_method_calls
    if x[
        "method"
    ]
    ==
    "placeIsolatedMarketOrder"
]

orders_impl_limit = [
    x
    for x in orders_methods
    if x[
        "target"
    ]
    ==
    "placeIsolatedLimitOrder"
]

orders_impl_market = [
    x
    for x in orders_methods
    if x[
        "target"
    ]
    ==
    "placeIsolatedMarketOrder"
]

builder_found = any(
    builder_details[
        name
    ]
    for name in BUILDERS
)

if (
    limit_chain
    and
    market_chain
    and
    orders_impl_limit
    and
    orders_impl_market
    and
    builder_found
    and
    orders_to_tx_links
):

    classification = (
        "STATIC_ORDERS_PROVIDER_TO_BUILDER_TO_TRANSACTION"
    )

elif (
    limit_chain
    and
    market_chain
    and
    (
        orders_impl_limit
        or
        orders_impl_market
    )
):

    classification = (
        "STATIC_ORDERS_PROVIDER_IMPLEMENTATION_SURFACE"
    )

elif (
    limit_chain
    and
    market_chain
):

    classification = (
        "STATIC_ORDERS_PROVIDER_CALL_SURFACE"
    )

else:

    classification = (
        "STATIC_ORDERS_PROVIDER_PATH_INCOMPLETE"
    )

# ============================================================
# 16. REPORT
# ============================================================

report = {

    "bundle": {
        "path":
            str(BUNDLE),

        "bytes":
            len(
                TEXT.encode(
                    "utf-8"
                )
            )
    },

    "R": {
        "offset":
            R_OFFSET,

        "length":
            len(r_raw),

        "code":
            R_CODE
    },

    "ordersChain":
        orders_chain,

    "ordersMethodCalls":
        orders_method_calls,

    "rootAssignments":
        root_assignments,

    "ordersDefinitions":
        orders_selected,

    "ordersMethods":
        orders_methods,

    "ordersServiceCalls":
        orders_service_calls,

    "candidateDefinitions":
        candidate_definitions,

    "builderDetails":
        builder_details,

    "transactionSites":
        tx_sites,

    "ordersToTransactionLinks":
        orders_to_tx_links,

    "rStateParameterLinks":
        r_state_parameter_links,

    "allOrderApiReferences":
        all_order_api_refs,

    "static":
        static,

    "milestone": {

        "limitChain":
            len(limit_chain),

        "marketChain":
            len(market_chain),

        "limitImplementationRefs":
            len(orders_impl_limit),

        "marketImplementationRefs":
            len(orders_impl_market),

        "ordersServiceCalls":
            len(orders_service_calls),

        "builderFound":
            builder_found,

        "transactionSites":
            len(tx_sites),

        "ordersToTransactionLinks":
            len(orders_to_tx_links),

        "RStateParameterLinks":
            len(
                r_state_parameter_links
            ),

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
    "ORDERS_PROVIDER_IMPLEMENTATION_TRACE_v6_4.json"
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
# 17. CORPUS
# ============================================================

exports = {

    "R.json":
        report["R"],

    "ORDERS_CHAIN.json":
        orders_chain,

    "ORDERS_METHOD_CALLS.json":
        orders_method_calls,

    "ROOT_ASSIGNMENTS.json":
        root_assignments,

    "ORDERS_DEFINITIONS.json":
        orders_selected,

    "ORDERS_METHODS.json":
        orders_methods,

    "ORDERS_SERVICE_CALLS.json":
        orders_service_calls,

    "CANDIDATE_DEFINITIONS.json":
        candidate_definitions,

    "BUILDERS.json":
        builder_details,

    "TRANSACTIONS.json":
        tx_sites,

    "ORDERS_TO_TX.json":
        orders_to_tx_links,

    "R_STATE_PARAMETER_LINKS.json":
        r_state_parameter_links,

    "ORDER_API_REFS.json":
        all_order_api_refs,

    "STATIC.json":
        static,

    "MILESTONE.json":
        report[
            "milestone"
        ]
}

for name, obj in exports.items():

    (
        CORPUS /
        f"ORDERS_V64_{name}"
    ).write_text(
        json.dumps(
            obj,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

# ============================================================
# 18. PRINT
# ============================================================

print("=" * 115)
print(
    "SANA FORENSICS — ORDERS PROVIDER IMPLEMENTATION TRACE v6.4"
)
print("=" * 115)

print()
print("R -> api.orders()")

for row in orders_chain:

    print(
        "ROOT:",
        row[
            "root"
        ]
    )

    print(
        "OFFSET:",
        row[
            "absoluteOffset"
        ]
    )

    print(
        "SUFFIX:",
        row[
            "suffix"
        ]
    )

print()
print("ORDERS METHODS")

for row in orders_method_calls:

    print()
    print(
        row[
            "root"
        ],
        ".api.orders().",
        row[
            "method"
        ]
    )

    print(
        "OFFSET:",
        row[
            "absoluteOffset"
        ]
    )

    print(
        "ARGS:",
        row[
            "arguments"
        ]
    )

print()
print("ORDERS DEFINITIONS")

for row in orders_selected[:20]:

    print()
    print(
        "OFFSET:",
        row[
            "offset"
        ],
        "LEN:",
        row[
            "length"
        ],
        "SCORE:",
        row[
            "score"
        ]
    )

    print(
        "PROXIMITY:",
        row[
            "proximity"
        ]
    )

    print(
        "CALLS:",
        [
            x
            for x in calls_in(
                row[
                    "code"
                ]
            )
            if (
                x in
                SERVICE_METHOD_HINTS
                or
                x in
                TARGETS
            )
        ][:100]
    )

print()
print("TARGETS INSIDE ORDERS DEFINITIONS")

for row in orders_methods:

    print()
    print(
        row[
            "target"
        ],
        "@",
        row[
            "ordersDefinitionOffset"
        ]
    )

    print(
        row[
            "context"
        ]
    )

print()
print("SERVICE CALLS")

for row in orders_service_calls[:120]:

    print()
    print(
        row[
            "name"
        ],
        "@",
        row[
            "offsetInOrders"
        ],
        "score=",
        row[
            "score"
        ]
    )

    print(
        "ORDER:",
        row[
            "order"
        ]
    )

    print(
        "STATE:",
        row[
            "state"
        ]
    )

    print(
        "AUTH:",
        row[
            "auth"
        ]
    )

    print(
        "NETWORK:",
        row[
            "network"
        ]
    )

print()
print("CANDIDATE DEFINITIONS")

for name, rows in candidate_definitions.items():

    if not rows:
        continue

    print()
    print(
        name,
        "defs=",
        len(rows)
    )

    for row in rows[:5]:

        print(
            "  OFFSET:",
            row[
                "offset"
            ],
            "LEN:",
            row[
                "length"
            ],
            "TARGET:",
            row[
                "targetHits"
            ],
            "SEM:",
            row[
                "semantic"
            ]
        )

        print(
            "  ORDER:",
            token_hits(
                row[
                    "code"
                ],
                ORDER_FIELDS
            )
        )

        print(
            "  STATE:",
            token_hits(
                row[
                    "code"
                ],
                STATE_FIELDS
            )
        )

        print(
            "  AUTH:",
            token_hits(
                row[
                    "code"
                ],
                AUTH_FIELDS
            )
        )

        print(
            "  NETWORK:",
            token_hits(
                row[
                    "code"
                ],
                NETWORK_FIELDS
            )
        )

print()
print("BUILDERS")

for name, rows in builder_details.items():

    print()
    print(
        name,
        "defs=",
        len(rows)
    )

    for row in rows[:10]:

        print(
            "  OFFSET:",
            row[
                "offset"
            ],
            "LEN:",
            row[
                "length"
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
print(
    "ORDERS -> TRANSACTION LINKS:",
    len(
        orders_to_tx_links
    )
)

for row in orders_to_tx_links[:50]:

    print()
    print(
        "ORDERS @",
        row[
            "ordersOffset"
        ]
    )

    print(
        "TX @",
        row[
            "transactionOffset"
        ]
    )

    print(
        "TERM:",
        row[
            "transaction"
        ][
            "term"
        ]
    )

print()
print("R STATE -> PARAMETER")

for row in r_state_parameter_links:

    print(
        row[
            "method"
        ],
        row[
            "field"
        ],
        "<=",
        row[
            "expression"
        ],
        "STATE=",
        row[
            "state"
        ]
    )

print()
print("TRANSACTION SITES:",
      len(tx_sites))

for row in tx_sites[:80]:

    print()
    print(
        row[
            "term"
        ],
        "@",
        row[
            "offset"
        ]
    )

    print(
        "ORDER:",
        row[
            "order"
        ]
    )

    print(
        "STATE:",
        row[
            "state"
        ]
    )

    print(
        "AUTH:",
        row[
            "auth"
        ]
    )

print()
print("STATIC")

for k, v in static.items():

    print(
        f"{k:34s}:",
        v
    )

print()
print("MILESTONE")

for k, v in report[
    "milestone"
].items():

    print(
        f"{k:44s}:",
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

