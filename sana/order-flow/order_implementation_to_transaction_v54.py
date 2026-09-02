import json
import re
from pathlib import Path

ROOT = Path(r"SANA_FORENSICS_ROOT")
BUNDLE = ROOT / "data" / "raw" / "sana_bundle.js"
REPORTS = ROOT / "data" / "reports"
CORPUS = ROOT / "data" / "corpus"

text = BUNDLE.read_text(
    encoding="utf-8",
    errors="replace"
)

# ============================================================
# UTILIDADES
# ============================================================

def compact(s):
    return re.sub(r"\s+", " ", s).strip()

def window(pos, before=4000, after=7000):
    return compact(
        text[
            max(0, pos-before):
            min(len(text), pos+after)
        ]
    )

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
    end = min(
        len(source),
        start + limit
    )

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
                return source[start:i+1]

        i += 1

    return None

def exact(pattern, source=text, flags=0, limit=5000):
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
                m.group(0),

            "context":
                window(
                    m.start(),
                    3000,
                    5000
                )
        })

        if len(out) >= limit:
            break

    return out

# ============================================================
# 1. EXACT KNOWN OFFSETS
# ============================================================

KNOWN = {
    "limit_external": 183521,
    "market_external": 184170,
    "R": 452460,
    "limit_R_call": 453572,
    "market_R_call": 453798,
    "buildLimitPacket": 390673,
    "buildMarketPacket": 391258,
    "buildPlaceLimit": 429999,
    "buildPlaceMarket": 430022,
}

known_regions = {}

for name, pos in KNOWN.items():

    known_regions[name] = {

        "offset":
            pos,

        "context":
            window(
                pos,
                7000,
                12000
            )
    }

# ============================================================
# 2. EXACT FUNCTION ENCLOSURE AROUND EARLIER
#    placeIsolated* OCCURRENCES
# ============================================================

def nearest_enclosing_function(pos):
    candidates = []

    start = max(
        0,
        pos - 60000
    )

    region = text[
        start:
        pos
    ]

    patterns = [

        (
            "function",
            r"\bfunction\s+"
            r"[A-Za-z_$][A-Za-z0-9_$]*"
            r"\s*\([^)]*\)\s*\{"
        ),

        (
            "arrow",
            r"(?:const|let|var)\s+"
            r"[A-Za-z_$][A-Za-z0-9_$]*"
            r"\s*=\s*"
            r"(?:async\s*)?"
            r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*=>\s*\{"
        ),

        (
            "method",
            r"[A-Za-z_$][A-Za-z0-9_$]*"
            r"\s*:\s*"
            r"(?:async\s*)?"
            r"\([^)]*\)\s*\{"
        ),

        (
            "method2",
            r"[A-Za-z_$][A-Za-z0-9_$]*"
            r"\([^)]*\)\s*\{"
        ),
    ]

    for kind, pattern in patterns:

        for m in re.finditer(
            pattern,
            region
        ):

            abs_pos = (
                start
                +
                m.start()
            )

            raw = balanced(
                text,
                abs_pos,
                "{",
                180000
            )

            if not raw:
                continue

            end = (
                abs_pos
                +
                len(raw)
            )

            if (
                abs_pos <= pos
                and
                pos <= end
            ):

                candidates.append({

                    "kind":
                        kind,

                    "offset":
                        abs_pos,

                    "length":
                        len(raw),

                    "declaration":
                        m.group(0),

                    "code":
                        compact(raw)
                })

    candidates.sort(
        key=lambda x: (
            x["offset"],
            -x["length"]
        ),
        reverse=True
    )

    return candidates

external_impl = {}

for name, pos in [
    (
        "placeIsolatedLimitOrder",
        KNOWN[
            "limit_external"
        ]
    ),
    (
        "placeIsolatedMarketOrder",
        KNOWN[
            "market_external"
        ]
    ),
]:

    candidates = nearest_enclosing_function(
        pos
    )

    external_impl[
        name
    ] = candidates[:10]

# ============================================================
# 3. IDENTIFICAR EL CALLEE REAL DEL ORIGEN EXTERNO
# ============================================================

implementation_calls = {}

for name, rows in external_impl.items():

    output = []

    for row in rows[:5]:

        code = row[
            "code"
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
                    "if","for","while","switch",
                    "catch","return","throw",
                    "Error","Number","String",
                    "Object","Array","Math","JSON"
                }
            )
        )

        output.append({

            "offset":
                row[
                    "offset"
                ],

            "length":
                row[
                    "length"
                ],

            "declaration":
                row[
                    "declaration"
                ],

            "calls":
                calls,

            "orderTerms":
                [
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
                        "orderPacket",
                    ]
                    if re.search(
                        rf"\b{re.escape(x)}\b",
                        code,
                        flags=re.I
                    )
                ],

            "stateTerms":
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
                        "lastMessage",
                    ]
                    if re.search(
                        rf"\b{re.escape(x)}\b",
                        code,
                        flags=re.I
                    )
                ],

            "authTerms":
                [
                    x
                    for x in [
                        "sessionManager",
                        "knownAuthToken",
                        "wallet",
                        "sign",
                        "transaction",
                        "sendTransaction",
                        "signAndSend",
                    ]
                    if re.search(
                        rf"\b{re.escape(x)}\b",
                        code,
                        flags=re.I
                    )
                ],

            "networkTerms":
                [
                    x
                    for x in [
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

            "code":
                code
        })

    implementation_calls[
        name
    ] = output

# ============================================================
# 4. EXACT EXPORT/REFERENCE STRUCTURE AROUND 183521/184170
# ============================================================

reference_windows = {}

for name, pos in [
    (
        "placeIsolatedLimitOrder",
        KNOWN[
            "limit_external"
        ]
    ),
    (
        "placeIsolatedMarketOrder",
        KNOWN[
            "market_external"
        ]
    ),
]:

    c = window(
        pos,
        18000,
        22000
    )

    reference_windows[
        name
    ] = {

        "offset":
            pos,

        "context":
            c,

        "strings":
            [
                m.group(2)
                for m in re.finditer(
                    r"""(["'])(.{1,240}?)(\1)""",
                    c
                )
                if any(
                    x in m.group(2).lower()
                    for x in [
                        "order",
                        "isolated",
                        "perp",
                        "transaction",
                        "rpc",
                        "api"
                    ]
                )
            ],

        "calls":
            sorted(
                set(
                    m.group(1)
                    for m in re.finditer(
                        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
                        c
                    )
                    if m.group(1)
                    not in {
                        "if","for","while","switch",
                        "catch","return","throw",
                        "Error","Number","String",
                        "Object","Array","Math","JSON"
                    }
                )
            )
    }

# ============================================================
# 5. TRACE UNIQUE CALLEES FROM EXTERNAL IMPLEMENTATION
# ============================================================

all_external_callees = sorted(
    set(
        callee
        for rows in implementation_calls.values()
        for row in rows
        for callee in row[
            "calls"
        ]
    )
)

callee_defs = {}

for callee in all_external_callees:

    defs = []

    patterns = [

        rf"\bfunction\s+{re.escape(callee)}\s*\(",

        rf"\b{re.escape(callee)}\s*=\s*",

        rf"\b{re.escape(callee)}\s*:\s*",

        rf"\b(?:const|let|var)\s+"
        rf"{re.escape(callee)}\b",
    ]

    seen = set()

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
                150000
            )

            if not raw:
                continue

            defs.append({

                "offset":
                    p,

                "length":
                    len(raw),

                "declaration":
                    m.group(0),

                "code":
                    compact(raw)
            })

    callee_defs[
        callee
    ] = defs[:20]

# ============================================================
# 6. EXPLICIT TARGETS KNOWN FROM THE BUNDLE
# ============================================================

TARGETS = [

    "resolvePlaceOrderContext",
    "resolveExchangeInstructionAccounts",
    "resolveTraderAccount",
    "resolveTraderTokenAccounts",
    "maybeWrapOrderIx",
    "buildLimitOrderPacket",
    "buildMarketOrderPacket",
    "buildPlaceLimitOrder",
    "buildPlaceMarketOrder",
    "mp",
    "mf",
    "mt",
    "pY",
    "p7",
    "i1",
]

target_details = {}

for target in TARGETS:

    defs = []

    patterns = [

        rf"\bfunction\s+{re.escape(target)}\s*\(",

        rf"\b{re.escape(target)}\s*=\s*",

        rf"\b{re.escape(target)}\s*:\s*",

        rf"\b(?:const|let|var)\s+"
        rf"{re.escape(target)}\b",
    ]

    seen = set()

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

            code = compact(
                raw
            )

            target_details.setdefault(
                target,
                []
            ).append({

                "offset":
                    p,

                "length":
                    len(raw),

                "declaration":
                    m.group(0),

                "code":
                    code,

                "calls":
                    sorted(
                        set(
                            m.group(1)
                            for m in re.finditer(
                                r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
                                code
                            )
                            if m.group(1)
                            not in {
                                "if","for","while",
                                "switch","catch",
                                "return","throw",
                                "Error","Number",
                                "String","Object",
                                "Array","Math","JSON"
                            }
                        )
                    ),

                "orderFields":
                    [
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
                            "orderPacket",
                            "subaccountIndex",
                        ]
                        if re.search(
                            rf"\b{re.escape(x)}\b",
                            code,
                            flags=re.I
                        )
                    ],

                "stateFields":
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
                            "lastMessage",
                        ]
                        if re.search(
                            rf"\b{re.escape(x)}\b",
                            code,
                            flags=re.I
                        )
                    ],

                "authFields":
                    [
                        x
                        for x in [
                            "sessionManager",
                            "knownAuthToken",
                            "wallet",
                            "sign",
                            "transaction",
                            "sendTransaction",
                            "signAndSend",
                        ]
                        if re.search(
                            rf"\b{re.escape(x)}\b",
                            code,
                            flags=re.I
                        )
                    ],

                "networkFields":
                    [
                        x
                        for x in [
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
                    ]
            })

    # dedupe
    unique = []
    seen_offsets = set()

    for item in target_details.get(
        target,
        []
    ):

        if item[
            "offset"
        ] in seen_offsets:
            continue

        seen_offsets.add(
            item[
                "offset"
            ]
        )

        unique.append(
            item
        )

    target_details[
        target
    ] = unique[:30]

# ============================================================
# 7. DIRECT RELATIONSHIP:
#    EXTERNAL IMPLEMENTATION -> TARGET DEFINITIONS
# ============================================================

direct_target_edges = []

for source_name, rows in implementation_calls.items():

    for row in rows:

        for call in row[
            "calls"
        ]:

            if call not in TARGETS:
                continue

            for target_def in target_details.get(
                call,
                []
            )[:5]:

                direct_target_edges.append({

                    "source":
                        source_name,

                    "sourceOffset":
                        row[
                            "offset"
                        ],

                    "target":
                        call,

                    "targetOffset":
                        target_def[
                            "offset"
                        ],

                    "targetLength":
                        target_def[
                            "length"
                        ],

                    "targetOrder":
                        target_def[
                            "orderFields"
                        ],

                    "targetState":
                        target_def[
                            "stateFields"
                        ],

                    "targetAuth":
                        target_def[
                            "authFields"
                        ],

                    "targetNetwork":
                        target_def[
                            "networkFields"
                        ],
                })

# ============================================================
# 8. SEARCH FOR ACTUAL TRANSACTION CONSTRUCTION
# ============================================================

TRANSACTION_TERMS = [
    "Transaction(",
    "TransactionInstruction(",
    "sendTransaction(",
    "signAndSend(",
    "confirmTransaction(",
    "getLatestBlockhash(",
    "serialize(",
    "wallet.sign",
    ".sign(",
]

transaction_refs = []

for term in TRANSACTION_TERMS:

    for m in re.finditer(
        re.escape(term),
        text,
        flags=re.I
    ):

        p = m.start()

        c = window(
            p,
            5000,
            8000
        )

        order_hits = [
            x
            for x in [
                "order",
                "placeOrder",
                "buildPlaceLimitOrder",
                "buildPlaceMarketOrder",
                "reduceOnly",
                "leverage",
                "price",
                "size",
                "symbol",
                "side",
                "authority",
            ]
            if re.search(
                rf"\b{re.escape(x)}\b",
                c,
                flags=re.I
            )
        ]

        state_hits = [
            x
            for x in [
                "collateral",
                "marginInputs",
                "ordersBySequence",
                "ordersBySymbol",
                "positionsBySymbol",
                "sequence",
                "slot",
                "version",
            ]
            if re.search(
                rf"\b{re.escape(x)}\b",
                c,
                flags=re.I
            )
        ]

        auth_hits = [
            x
            for x in [
                "wallet",
                "sessionManager",
                "knownAuthToken",
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

        if (
            len(order_hits) >= 2
            or
            len(auth_hits) >= 2
        ):

            transaction_refs.append({

                "term":
                    term,

                "offset":
                    p,

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
# 9. CRITICAL STATIC STATE
# ============================================================

static = {

    "processIdentityGuard":
        (
            "e.authority!==t"
            in text
            and
            "e.traderPdaIndex!==r"
            in text
        ),

    "processSequenceGuard":
        bool(
            re.search(
                r"processMessage:"
                r".{0,7000}"
                r"e\.sequence\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                text
            )
        ),

    "deltaSequenceGuard":
        bool(
            re.search(
                r"t\.deltas"
                r".{0,15000}"
                r"(?:e|t)\.sequence\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                text
            )
        ),

    "orderSequenceGuard":
        bool(
            re.search(
                r"pF=\(e,t\)=>"
                r".{0,15000}"
                r"orderSequenceNumber\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                text
            )
        ),

    "orderWholeReplacement":
        (
            "a[t.orderSequenceNumber]=pE(t)"
            in text
        ),

    "orderCloseDelete":
        (
            "delete a[t.orderSequenceNumber]"
            in text
        )
}

# ============================================================
# 10. MILESTONE
# ============================================================

limit_impl = bool(
    external_impl[
        "placeIsolatedLimitOrder"
    ]
)

market_impl = bool(
    external_impl[
        "placeIsolatedMarketOrder"
    ]
)

target_builder_edges = [
    x
    for x in direct_target_edges
    if x[
        "target"
    ] in [
        "buildLimitOrderPacket",
        "buildMarketOrderPacket",
        "buildPlaceLimitOrder",
        "buildPlaceMarketOrder",
    ]
]

order_transaction_links = [
    x
    for x in transaction_refs
    if (
        len(x["order"]) >= 2
        and
        (
            len(x["auth"]) >= 1
            or
            len(x["state"]) >= 1
        )
    )
]

# ============================================================
# 11. CLASSIFICATION
# ============================================================

if (
    limit_impl
    and
    market_impl
    and
    target_builder_edges
    and
    order_transaction_links
):

    classification = (
        "STATIC_ORDER_IMPLEMENTATION_TO_TRANSACTION_SURFACE"
    )

elif (
    limit_impl
    and
    market_impl
    and
    target_builder_edges
):

    classification = (
        "STATIC_ORDER_IMPLEMENTATION_TO_BUILDER_SURFACE"
    )

elif (
    limit_impl
    or
    market_impl
):

    classification = (
        "STATIC_ISOLATED_ORDER_IMPLEMENTATION_SURFACE"
    )

else:

    classification = (
        "ISOLATED_ORDER_IMPLEMENTATION_UNRESOLVED"
    )

# ============================================================
# 12. REPORT
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

    "knownRegions":
        known_regions,

    "externalImplementations":
        external_impl,

    "implementationCalls":
        implementation_calls,

    "referenceWindows":
        reference_windows,

    "calleeNames":
        all_external_callees,

    "calleeDefinitions":
        callee_defs,

    "targetDetails":
        target_details,

    "directTargetEdges":
        direct_target_edges,

    "transactionRefs":
        transaction_refs,

    "static":
        static,

    "milestone": {

        "limitImplementationFound":
            limit_impl,

        "marketImplementationFound":
            market_impl,

        "builderEdges":
            len(
                target_builder_edges
            ),

        "orderTransactionLinks":
            len(
                order_transaction_links
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
    "ORDER_IMPLEMENTATION_TO_TRANSACTION_v5_4.json"
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
# 13. CORPUS
# ============================================================

exports = {

    "KNOWN_REGIONS.json":
        known_regions,

    "EXTERNAL_IMPLEMENTATIONS.json":
        external_impl,

    "IMPLEMENTATION_CALLS.json":
        implementation_calls,

    "REFERENCE_WINDOWS.json":
        reference_windows,

    "CALLEE_DEFINITIONS.json":
        callee_defs,

    "TARGET_DETAILS.json":
        target_details,

    "DIRECT_TARGET_EDGES.json":
        direct_target_edges,

    "TRANSACTION_REFS.json":
        transaction_refs,

    "STATIC.json":
        static,

    "MILESTONE.json":
        report[
            "milestone"
        ],
}

for name, obj in exports.items():

    (
        CORPUS /
        f"ORDER_TX_{name}"
    ).write_text(
        json.dumps(
            obj,
            indent=2,
            ensure_ascii=False
        ),
        encoding="utf-8"
    )

# ============================================================
# 14. PRINT
# ============================================================

print("=" * 115)
print(
    "SANA FORENSICS — ORDER IMPLEMENTATION TO TRANSACTION v5.4"
)
print("=" * 115)

print()
print("EXTERNAL IMPLEMENTATIONS")

for name, rows in external_impl.items():

    print()
    print(
        name,
        "candidates=",
        len(rows)
    )

    for row in rows[:5]:

        print(
            "  OFFSET:",
            row[
                "offset"
            ]
        )

        print(
            "  LEN:",
            row[
                "length"
            ]
        )

        print(
            "  DECL:",
            row[
                "declaration"
            ]
        )

        impl = implementation_calls[
            name
        ]

        for x in impl:

            if x[
                "offset"
            ] == row[
                "offset"
            ]:

                print(
                    "  CALLS:",
                    x[
                        "calls"
                    ]
                )

                print(
                    "  ORDER:",
                    x[
                        "orderTerms"
                    ]
                )

                print(
                    "  STATE:",
                    x[
                        "stateTerms"
                    ]
                )

                print(
                    "  AUTH:",
                    x[
                        "authTerms"
                    ]
                )

                print(
                    "  NETWORK:",
                    x[
                        "networkTerms"
                    ]
                )

print()
print("BUILDER / CONTEXT EDGES")

for x in target_builder_edges[:100]:

    print()

    print(
        x[
            "source"
        ],
        "->",
        x[
            "target"
        ]
    )

    print(
        "  source:",
        x[
            "sourceOffset"
        ]
    )

    print(
        "  target:",
        x[
            "targetOffset"
        ]
    )

    print(
        "  ORDER:",
        x[
            "targetOrder"
        ]
    )

    print(
        "  STATE:",
        x[
            "targetState"
        ]
    )

    print(
        "  AUTH:",
        x[
            "targetAuth"
        ]
    )

    print(
        "  NETWORK:",
        x[
            "targetNetwork"
        ]
    )

print()
print("TRANSACTION LINKS")

for x in order_transaction_links[:100]:

    print()

    print(
        x[
            "term"
        ],
        "@",
        x[
            "offset"
        ]
    )

    print(
        "ORDER:",
        x[
            "order"
        ]
    )

    print(
        "STATE:",
        x[
            "state"
        ]
    )

    print(
        "AUTH:",
        x[
            "auth"
        ]
    )

    print(
        "CONTEXT:",
        x[
            "context"
        ]
    )

print()
print("STATIC")

for k,v in static.items():

    print(
        f"{k:36s}:",
        v
    )

print()
print("MILESTONE")

for k,v in report[
    "milestone"
].items():

    print(
        f"{k:40s}:",
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

