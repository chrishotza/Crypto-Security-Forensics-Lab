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
S_OFFSET_HINT = 381088
TX_OFFSET_HINTS = [376992, 377033, 377326, 378482, 378523, 378626, 377682, 379113]

def compact(s):
    return re.sub(r"\s+", " ", s).strip()

def balanced(source, start, opener="{", limit=300000):
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
    end = min(len(source), start + limit)

    while i < end:
        ch = source[i]
        nx = source[i + 1] if i + 1 < end else ""

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
            if not stack or stack[-1] != reverse[ch]:
                return None
            stack.pop()
            if not stack:
                return source[start:i + 1]

        i += 1

    return None

def context(pos, before=5000, after=9000):
    return compact(
        TEXT[
            max(0, pos-before):
            min(len(TEXT), pos+after)
        ]
    )

def calls_in(code):
    out = []
    for m in re.finditer(
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
        code
    ):
        name = m.group(1)
        if name in {
            "if","else","for","while","do","switch","case",
            "return","throw","catch","finally","function",
            "new","typeof","void","delete","instanceof",
            "Error","Number","String","Boolean","Object",
            "Array","Promise","Date","Math","JSON"
        }:
            continue
        out.append(name)
    return sorted(set(out))

def extract_call_args(source, pos):
    op = source.find("(", pos)
    if op < 0:
        return None
    raw = balanced(source, op, "(", 80000)
    if not raw:
        return None
    return compact(raw[1:-1])

def all_definitions(name, max_results=100):
    rows = []
    seen = set()

    patterns = [
        rf"\bfunction\s+{re.escape(name)}\s*\(",
        rf"\b(?:const|let|var)\s+{re.escape(name)}\s*=",
        rf"\b{re.escape(name)}\s*=",
        rf"\b{re.escape(name)}\s*:",
    ]

    for pattern in patterns:
        for m in re.finditer(pattern, TEXT):
            p = m.start()

            if p in seen:
                continue

            seen.add(p)

            raw = balanced(
                TEXT,
                p,
                "{",
                250000
            )

            if not raw:
                continue

            rows.append({
                "offset": p,
                "length": len(raw),
                "declaration": m.group(0),
                "code": compact(raw)
            })

            if len(rows) >= max_results:
                return rows

    return rows

def score_code(code):
    low = code.lower()
    terms = [
        "orders",
        "placeisolatedlimitorder",
        "placeisolatedmarketorder",
        "orderpacket",
        "transaction",
        "transactioninstruction",
        "sendtransaction",
        "signtransaction",
        "wallet",
        "sessionmanager",
        "authority",
        "symbol",
        "side",
        "price",
        "size",
        "reduceonly",
        "leverage",
        "collateral",
        "ordersbysequence",
        "ordersbysymbol",
        "positionsbysymbol",
        "sequence",
        "slot",
        "version",
    ]
    return sum(t in low for t in terms)

def summarize_definition(d):
    code = d["code"]
    return {
        "offset": d["offset"],
        "length": d["length"],
        "declaration": d["declaration"],
        "score": score_code(code),
        "calls": calls_in(code),
        "order": [
            x for x in [
                "authority",
                "symbol",
                "side",
                "price",
                "priceUsd",
                "size",
                "baseUnits",
                "quantity",
                "numBaseLots",
                "orderFlags",
                "reduceOnly",
                "leverage",
                "orderPacket",
                "orders",
            ]
            if re.search(
                rf"\b{re.escape(x)}\b",
                code,
                flags=re.I
            )
        ],
        "state": [
            x for x in [
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
            if re.search(
                rf"\b{re.escape(x)}\b",
                code,
                flags=re.I
            )
        ],
        "auth": [
            x for x in [
                "sessionManager",
                "knownAuthToken",
                "wallet",
                "sign",
                "transaction",
                "signature",
                "sendTransaction",
                "signAndSend",
            ]
            if re.search(
                rf"\b{re.escape(x)}\b",
                code,
                flags=re.I
            )
        ],
        "network": [
            x for x in [
                "fetch",
                "request",
                "rpc",
                "send",
                "submit",
                "execute",
                "mutate",
            ]
            if re.search(
                rf"\b{re.escape(x)}\b",
                code,
                flags=re.I
            )
        ],
        "code": code
    }

# ============================================================
# 1. EXACT R
# ============================================================

r_raw = balanced(
    TEXT,
    R_OFFSET,
    "{",
    12000
)

if not r_raw:
    raise RuntimeError("R no encontrado")

R_CODE = compact(r_raw)

# ============================================================
# 2. R -> r.api.orders()
# ============================================================

api_calls = []

for m in re.finditer(
    r"\br\.api\.orders\(\)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
    R_CODE
):
    absolute = R_OFFSET + m.start()

    api_calls.append({
        "method": m.group(1),
        "offsetInR": m.start(),
        "absoluteOffset": absolute,
        "arguments": extract_call_args(
            R_CODE,
            m.start()
        ),
        "context": context(
            absolute,
            2500,
            6000
        )
    })

# ============================================================
# 3. IDENTIFICAR S() REAL USADO POR R
# ============================================================

s_calls = []

for m in re.finditer(
    r"\bS\s*\(",
    R_CODE
):
    s_calls.append({
        "offsetInR": m.start(),
        "absoluteOffset": R_OFFSET + m.start(),
        "arguments": extract_call_args(R_CODE, m.start())
    })

s_defs = all_definitions(
    "S",
    100
)

s_ranked = sorted(
    s_defs,
    key=lambda d: (
        score_code(d["code"]),
        d["length"]
    ),
    reverse=True
)

s_selected = s_ranked[:20]

# ============================================================
# 4. BUSCAR EXACTAMENTE "orders" DENTRO DE S
# ============================================================

orders_inside_s = []

for d in s_selected:

    code = d["code"]

    if "orders" not in code:
        continue

    for m in re.finditer(
        r"\borders\b",
        code
    ):

        orders_inside_s.append({

            "sOffset":
                d["offset"],

            "sLength":
                d["length"],

            "ordersOffsetInS":
                m.start(),

            "context":
                compact(
                    code[
                        max(0,m.start()-2500):
                        min(
                            len(code),
                            m.start()+6000
                        )
                    ]
                )
        })

# ============================================================
# 5. BUSCAR METODOS placeIsolated* DENTRO DE S
# ============================================================

isolated_method_hits = []

for d in s_selected:

    code = d["code"]

    for method in [
        "placeIsolatedLimitOrder",
        "placeIsolatedMarketOrder",
    ]:

        for m in re.finditer(
            rf"\b{re.escape(method)}\b",
            code
        ):

            isolated_method_hits.append({

                "sOffset":
                    d["offset"],

                "sLength":
                    d["length"],

                "method":
                    method,

                "offsetInS":
                    m.start(),

                "context":
                    compact(
                        code[
                            max(0,m.start()-3500):
                            min(
                                len(code),
                                m.start()+9000
                            )
                        ]
                    )
            })

# ============================================================
# 6. EXTRAER CUALQUIER PROPERTY ASSIGNMENT:
#    placeIsolatedLimitOrder: X
#    placeIsolatedMarketOrder: X
# ============================================================

provider_properties = []

for target in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]:

    for m in re.finditer(
        rf"\b{re.escape(target)}\s*:",
        TEXT
    ):

        p = m.start()

        tail = TEXT[
            p:
            min(len(TEXT), p+1200)
        ]

        value_match = re.match(
            rf"\b{re.escape(target)}\s*:\s*"
            r"([^,}}]+)",
            tail
        )

        provider_properties.append({

            "target":
                target,

            "offset":
                p,

            "value":
                compact(
                    value_match.group(1)
                )
                if value_match
                else None,

            "context":
                context(
                    p,
                    4000,
                    7000
                )
        })

# ============================================================
# 7. RESOLVER: CONVERTIR PROPERTY VALUE EN ALIAS REAL
# ============================================================

def resolve_value(value):
    if not value:
        return []

    value = compact(value)

    # solo identifier puro
    m = re.fullmatch(
        r"[A-Za-z_$][A-Za-z0-9_$]*",
        value
    )

    if m:
        return all_definitions(
            value,
            50
        )

    return []

resolved_properties = {}

for row in provider_properties:

    target = row[
        "target"
    ]

    value = row[
        "value"
    ]

    resolved_properties.setdefault(
        target,
        []
    ).append({

        "propertyOffset":
            row["offset"],

        "value":
            value,

        "definitions":
            [
                summarize_definition(d)
                for d in resolve_value(value)[:20]
            ]
    })

# ============================================================
# 8. MODULO / CONTEXTO EXACTO DE LAS PROPERTIES
# ============================================================

def enclosing_objects(pos, max_back=90000):
    start = max(
        0,
        pos-max_back
    )

    out = []

    for m in re.finditer(
        r"\{",
        TEXT[start:pos+1]
    ):

        absolute = start + m.start()

        raw = balanced(
            TEXT,
            absolute,
            "{",
            180000
        )

        if not raw:
            continue

        end = absolute + len(raw)

        if absolute <= pos <= end:

            out.append({

                "offset":
                    absolute,

                "length":
                    len(raw),

                "code":
                    compact(raw)
            })

    out.sort(
        key=lambda x: (
            x["length"],
            -x["offset"]
        )
    )

    return out[:15]

property_containers = {}

for target in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]:

    rows = []

    for row in provider_properties:

        if row[
            "target"
        ] != target:
            continue

        rows.append({

            "offset":
                row["offset"],

            "containers":
                enclosing_objects(
                    row["offset"]
                )
        })

    property_containers[
        target
    ] = rows

# ============================================================
# 9. SEARCH DIRECTLY FOR THE PATTERN SEEN IN R:
#    api.orders().placeIsolated...
#
#    and trace the preceding "orders()" object owner.
# ============================================================

order_chain_contexts = []

for row in api_calls:

    method = row[
        "method"
    ]

    p = row[
        "absoluteOffset"
    ]

    if method not in [
        "placeIsolatedLimitOrder",
        "placeIsolatedMarketOrder"
    ]:
        continue

    c = context(
        p,
        9000,
        14000
    )

    order_chain_contexts.append({

        "method":
            method,

        "offset":
            p,

        "context":
            c,

        "api":
            [
                x
                for x in [
                    "api",
                    "orders",
                    "placeIsolatedLimitOrder",
                    "placeIsolatedMarketOrder",
                    "buildLimitOrderPacket",
                    "buildPlaceLimitOrder",
                    "buildMarketOrderPacket",
                    "buildPlaceMarketOrder",
                ]
                if re.search(
                    rf"\b{re.escape(x)}\b",
                    c
                )
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
                    "version",
                ]
                if re.search(
                    rf"\b{re.escape(x)}\b",
                    c,
                    flags=re.I
                )
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
                    "signature",
                ]
                if re.search(
                    rf"\b{re.escape(x)}\b",
                    c,
                    flags=re.I
                )
            ]
    })

# ============================================================
# 10. EXACT DEFINITIONS AROUND THE TRANSACTION REGION
# ============================================================

tx_regions = []

for p in TX_OFFSET_HINTS:

    tx_regions.append({

        "offset":
            p,

        "context":
            context(
                p,
                7000,
                12000
            )
    })

# ============================================================
# 11. CONNECT R API METHOD -> ANY FUNCTION DEFINITION
#     THAT HANDLES THE SAME METHOD NAME THROUGH OBJECT/METHOD
# ============================================================

method_surface = {}

for method in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]:

    refs = []

    for m in re.finditer(
        rf"\b{re.escape(method)}\b",
        TEXT
    ):

        p = m.start()

        before = TEXT[
            max(0,p-500):
            p
        ]

        after = TEXT[
            p:
            min(len(TEXT),p+1500)
        ]

        ref_type = "reference"

        if re.match(
            rf"\b{re.escape(method)}\s*:",
            after
        ):
            ref_type = "property"

        elif re.match(
            rf"\b{re.escape(method)}\s*\(",
            after
        ):
            ref_type = "call"

        refs.append({

            "offset":
                p,

            "type":
                ref_type,

            "prefix":
                compact(before),

            "suffix":
                compact(after),

            "context":
                context(
                    p,
                    2500,
                    5000
                )
        })

    method_surface[
        method
    ] = refs

# ============================================================
# 12. EXACT STATE -> R PARAMETER SOURCES
# ============================================================

r_state_terms = [
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

r_state_refs = []

for term in r_state_terms:

    for m in re.finditer(
        rf"\b{re.escape(term)}\b",
        R_CODE,
        flags=re.I
    ):

        r_state_refs.append({

            "term":
                term,

            "offsetInR":
                m.start(),

            "context":
                compact(
                    R_CODE[
                        max(0,m.start()-1200):
                        min(
                            len(R_CODE),
                            m.start()+2500
                        )
                    ]
                )
        })

# ============================================================
# 13. STATIC GROUND TRUTH
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
# 14. MILESTONE
# ============================================================

limit_r_call = any(
    x[
        "method"
    ] == "placeIsolatedLimitOrder"
    for x in api_calls
)

market_r_call = any(
    x[
        "method"
    ] == "placeIsolatedMarketOrder"
    for x in api_calls
)

s_has_orders = bool(
    orders_inside_s
)

s_has_isolated_methods = bool(
    isolated_method_hits
)

export_limit_found = bool(
    resolved_properties[
        "placeIsolatedLimitOrder"
    ]
)

export_market_found = bool(
    resolved_properties[
        "placeIsolatedMarketOrder"
    }
)

tx_has_order = any(
    any(
        x in row[
            "context"
        ]
        for x in [
            "placeIsolatedLimitOrder",
            "placeIsolatedMarketOrder",
            "buildPlaceLimitOrder",
            "buildPlaceMarketOrder",
            "orderPacket"
        ]
    )
    for row in tx_regions
)

tx_has_auth = any(
    any(
        x in row[
            "context"
        ]
        for x in [
            "wallet",
            "sessionManager",
            "sign",
            "transaction"
        ]
    )
    for row in tx_regions
)

if (
    limit_r_call
    and
    market_r_call
    and
    s_has_orders
    and
    tx_has_order
    and
    tx_has_auth
):

    classification = (
        "ORDER_API_TO_TRANSACTION_BOUNDARY_CONFIRMED_STATIC"
    )

elif (
    limit_r_call
    and
    market_r_call
    and
    s_has_orders
):

    classification = (
        "ORDER_API_TO_ORDERS_PROVIDER_BOUNDARY_CONFIRMED"
    )

elif (
    limit_r_call
    and
    market_r_call
):

    classification = (
        "R_ORDER_API_BOUNDARY_CONFIRMED"
    )

else:

    classification = (
        "ORDER_API_BOUNDARY_INCOMPLETE"
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
                TEXT.encode(
                    "utf-8"
                )
            )
    },

    "r": {
        "offset":
            R_OFFSET,

        "length":
            len(r_raw),

        "code":
            R_CODE
    },

    "apiCalls":
        api_calls,

    "sCalls":
        s_calls,

    "sDefinitions":
        [
            summarize_definition(x)
            for x in s_selected
        ],

    "ordersInsideS":
        orders_inside_s,

    "isolatedMethodHits":
        isolated_method_hits,

    "providerProperties":
        provider_properties,

    "resolvedProperties":
        resolved_properties,

    "propertyContainers":
        property_containers,

    "orderChainContexts":
        order_chain_contexts,

    "transactionRegions":
        tx_regions,

    "methodSurface":
        method_surface,

    "rStateRefs":
        r_state_refs,

    "static":
        static,

    "milestone":
        {
            "limitRCall":
                limit_r_call,

            "marketRCall":
                market_r_call,

            "sHasOrders":
                s_has_orders,

            "sHasIsolatedMethods":
                s_has_isolated_methods,

            "limitExportResolved":
                export_limit_found,

            "marketExportResolved":
                export_market_found,

            "transactionHasOrder":
                tx_has_order,

            "transactionHasAuth":
                tx_has_auth,

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
                False,

            "next":
                "TRACE_EXACT_ORDERS_PROVIDER_IMPLEMENTATION_AND_TX_FIELDS"
        }
}

report_path = (
    REPORTS /
    "ORDER_EXACT_PROVIDER_TO_TX_v6_2.json"
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
# 16. CORPUS
# ============================================================

exports = {

    "R.json":
        report["r"],

    "API_CALLS.json":
        api_calls,

    "S_DEFINITIONS.json":
        report["sDefinitions"],

    "ORDERS_INSIDE_S.json":
        orders_inside_s,

    "ISOLATED_METHOD_HITS.json":
        isolated_method_hits,

    "PROVIDER_PROPERTIES.json":
        provider_properties,

    "RESOLVED_PROPERTIES.json":
        resolved_properties,

    "PROPERTY_CONTAINERS.json":
        property_containers,

    "ORDER_CHAIN_CONTEXTS.json":
        order_chain_contexts,

    "TRANSACTION_REGIONS.json":
        tx_regions,

    "METHOD_SURFACE.json":
        method_surface,

    "R_STATE.json":
        r_state_refs,

    "STATIC.json":
        static,

    "MILESTONE.json":
        report["milestone"]
}

for name, obj in exports.items():

    (
        CORPUS /
        f"ORDER_TX_V62_{name}"
    ).write_text(
        json.dumps(
            obj,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

# ============================================================
# 17. PRINT
# ============================================================

print("=" * 115)
print("SANA FORENSICS — ORDER EXACT PROVIDER -> TX v6.2")
print("=" * 115)

print()
print("R")
print(
    "OFFSET:",
    R_OFFSET
)
print(
    "LEN:",
    len(r_raw)
)

print()
print("API CALLS")

for row in api_calls:

    print()
    print(
        row["method"],
        "@",
        row["absoluteOffset"]
    )

    print(
        "ARGS:",
        row["arguments"]
    )

print()
print("S() DEFINITIONS")

for d in report[
    "sDefinitions"
][:10]:

    print()
    print(
        "OFFSET:",
        d["offset"],
        "LEN:",
        d["length"],
        "SCORE:",
        d["score"]
    )

    print(
        "CALLS:",
        d["calls"]
    )

    print(
        "ORDER:",
        d["order"]
    )

    print(
        "STATE:",
        d["state"]
    )

    print(
        "AUTH:",
        d["auth"]
    )

    print(
        "NETWORK:",
        d["network"]
    )

print()
print("ORDERS INSIDE S:",
      len(orders_inside_s))

for row in orders_inside_s[:50]:

    print()
    print(
        "S OFFSET:",
        row["sOffset"]
    )

    print(
        "ORDERS OFFSET:",
        row["ordersOffsetInS"]
    )

    print(
        row["context"]
    )

print()
print("ISOLATED METHOD HITS:",
      len(isolated_method_hits))

for row in isolated_method_hits[:50]:

    print()
    print(
        row["method"],
        "S@",
        row["sOffset"],
        "OFFSET",
        row["offsetInS"]
    )

    print(
        row["context"]
    )

print()
print("PROVIDER PROPERTIES")

for row in provider_properties:

    print()
    print(
        row["target"],
        "@",
        row["offset"],
        "VALUE=",
        row["value"]
    )

print()
print("RESOLVED PROPERTIES")

for target, rows in resolved_properties.items():

    print()
    print(
        target
    )

    for row in rows:

        print(
            "PROPERTY:",
            row["propertyOffset"]
        )

        print(
            "VALUE:",
            row["value"]
        )

        for d in row[
            "definitions"
        ][:10]:

            print(
                "  DEF:",
                d["offset"],
                "LEN:",
                d["length"],
                "SCORE:",
                d["score"]
            )

            print(
                "  ORDER:",
                d["order"]
            )

            print(
                "  STATE:",
                d["state"]
            )

            print(
                "  AUTH:",
                d["auth"]
            )

            print(
                "  NETWORK:",
                d["network"]
            )

print()
print("ORDER CHAIN CONTEXTS")

for row in order_chain_contexts:

    print()
    print(
        row["method"],
        "@",
        row["offset"]
    )

    print(
        "API:",
        row["api"]
    )

    print(
        "STATE:",
        row["state"]
    )

    print(
        "AUTH:",
        row["auth"]
    )

print()
print("TRANSACTION REGIONS")

for row in tx_regions:

    print()
    print(
        "OFFSET:",
        row["offset"]
    )

    c = row["context"]

    for term in [
        "placeIsolatedLimitOrder",
        "placeIsolatedMarketOrder",
        "buildPlaceLimitOrder",
        "buildPlaceMarketOrder",
        "orderPacket",
        "collateral",
        "wallet",
        "sessionManager",
        "sign",
        "transaction"
    ]:

        if re.search(
            rf"\b{re.escape(term)}\b",
            c,
            flags=re.I
        ):

            print(
                "  HIT:",
                term
            )

print()
print("R STATE REFS:",
      len(r_state_refs))

for row in r_state_refs[:100]:

    print(
        row["term"],
        "@",
        row["offsetInR"]
    )

print()
print("STATIC")

for k,v in static.items():

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
        f"{k:45s}:",
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

