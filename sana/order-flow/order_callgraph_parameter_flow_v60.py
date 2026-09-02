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

# ============================================================
# KNOWN EXACT OFFSETS FROM PREVIOUS VERIFIED RUNS
# ============================================================

R_OFFSET = 452460

KNOWN_CALLS = {
    "placeIsolatedLimitOrder": 453572,
    "placeIsolatedMarketOrder": 453798,
    "buildLimitOrderPacket": 454134,
    "buildPlaceLimitOrder": 454246,
    "buildMarketOrderPacket": 454379,
    "buildPlaceMarketOrder": 454470,
}

TARGETS = [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
    "buildLimitOrderPacket",
    "buildMarketOrderPacket",
    "buildPlaceLimitOrder",
    "buildPlaceMarketOrder",
]

def compact(s):
    return re.sub(r"\s+", " ", s).strip()

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
                return source[
                    start:i+1
                ]

        i += 1

    return None

def context(pos, before=6000, after=12000):
    return compact(
        TEXT[
            max(0, pos-before):
            min(len(TEXT), pos+after)
        ]
    )

def line_col(pos):
    line = TEXT.count(
        "\n",
        0,
        pos
    ) + 1

    last = TEXT.rfind(
        "\n",
        0,
        pos
    )

    col = (
        pos + 1
        if last < 0
        else
        pos - last
    )

    return line, col

# ============================================================
# 1. FIND THE EXACT TEXT NEAR KNOWN OFFSETS
# ============================================================

known_regions = {}

for name, pos in {
    "R": R_OFFSET,
    **KNOWN_CALLS
}.items():

    known_regions[name] = {

        "offset":
            pos,

        "line":
            line_col(pos)[0],

        "column":
            line_col(pos)[1],

        "context":
            context(
                pos,
                5000,
                10000
            )
    }

# ============================================================
# 2. RESOLVE THE ACTUAL CALL TEXT AT EACH OFFSET
# ============================================================

call_sites = {}

for target, expected in KNOWN_CALLS.items():

    start = max(
        0,
        expected - 80
    )

    end = min(
        len(TEXT),
        expected + 5000
    )

    region = TEXT[
        start:end
    ]

    m = re.search(
        rf"\b{re.escape(target)}\s*\(",
        region
    )

    if not m:
        call_sites[
            target
        ] = {
            "expectedOffset":
                expected,

            "found":
                False
        }

        continue

    absolute = (
        start
        +
        m.start()
    )

    raw = balanced(
        TEXT,
        absolute,
        "(",
        50000
    )

    call_sites[
        target
    ] = {

        "expectedOffset":
            expected,

        "found":
            True,

        "actualOffset":
            absolute,

        "distance":
            absolute - expected,

        "arguments":
            compact(
                raw[1:-1]
            )
            if raw
            else None,

        "callText":
            compact(
                TEXT[
                    absolute:
                    min(
                        len(TEXT),
                        absolute + (
                            len(raw)
                            if raw
                            else 2500
                        )
                    )
                ]
            )
    }

# ============================================================
# 3. LOCATE THE FUNCTION ENCLOSING EACH REAL CALL
#
# IMPORTANT:
# We do NOT assume that the call name itself is the
# implementation. We reconstruct the enclosing arrow/function
# from the actual source around the call.
# ============================================================

def enclosing_function(pos):
    start = max(
        0,
        pos - 180000
    )

    region = TEXT[
        start:
        pos
    ]

    candidates = []

    patterns = [

        (
            "function",
            r"\bfunction\s+"
            r"([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*\([^)]*\)\s*\{"
        ),

        (
            "async_function",
            r"\basync\s+function\s+"
            r"([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*\([^)]*\)\s*\{"
        ),

        (
            "arrow_single",
            r"\b(?:const|let|var)\s+"
            r"([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*=\s*"
            r"(?:async\s+)?"
            r"[A-Za-z_$][A-Za-z0-9_$]*"
            r"\s*=>\s*\{"
        ),

        (
            "arrow_paren",
            r"\b(?:const|let|var)\s+"
            r"([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*=\s*"
            r"(?:async\s+)?"
            r"\([^)]*\)"
            r"\s*=>\s*\{"
        ),

        (
            "anonymous_arrow",
            r"\b(?:async\s+)?"
            r"\([^)]*\)"
            r"\s*=>\s*\{"
        ),

        (
            "compact_async_arrow",
            r"\b(?:async\s+)?"
            r"[A-Za-z_$][A-Za-z0-9_$]*"
            r"\s*=>\s*\{"
        ),

        (
            "method",
            r"\b"
            r"([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*:"
            r"\s*(?:async\s+)?"
            r"\([^)]*\)"
            r"\s*\{"
        ),
    ]

    for kind, pattern in patterns:

        for m in re.finditer(
            pattern,
            region
        ):

            absolute = (
                start
                +
                m.start()
            )

            raw = balanced(
                TEXT,
                absolute,
                "{",
                220000
            )

            if not raw:
                continue

            end = (
                absolute
                +
                len(raw)
            )

            if (
                absolute <= pos
                and
                pos <= end
            ):

                name = (
                    m.group(1)
                    if m.lastindex
                    else None
                )

                candidates.append({

                    "kind":
                        kind,

                    "name":
                        name,

                    "offset":
                        absolute,

                    "length":
                        len(raw),

                    "declaration":
                        m.group(0),

                    "code":
                        compact(raw)
                })

    candidates.sort(
        key=lambda x: (
            x["length"],
            -x["offset"]
        )
    )

    return candidates

enclosing = {}

for target, row in call_sites.items():

    if not row.get(
        "found",
        False
    ):
        enclosing[
            target
        ] = []
        continue

    enclosing[
        target
    ] = enclosing_function(
        row[
            "actualOffset"
        ]
    )

# ============================================================
# 4. EXTRACT THE EXACT FUNCTION BODY FOR R
# ============================================================

r_function_candidates = enclosing_function(
    R_OFFSET
)

# Prefer one containing the known order calls
r_ranked = []

for candidate in r_function_candidates:

    code = candidate[
        "code"
    ]

    hits = sum(
        bool(
            re.search(
                rf"\b{re.escape(target)}\s*\(",
                code
            )
        )
        for target in TARGETS
    )

    r_ranked.append(
        (
            hits,
            candidate[
                "length"
            ],
            candidate
        )
    )

r_ranked.sort(
    reverse=True,
    key=lambda x: (
        x[0],
        x[1]
    )
)

r_function = (
    r_ranked[0][2]
    if r_ranked
    else None
)

# ============================================================
# 5. EXACT PARAMETER FLOW FROM THE R CALLS
# ============================================================

parameter_flow = []

ORDER_FIELDS = [
    "authority",
    "symbol",
    "side",
    "numBaseLots",
    "quantity",
    "price",
    "priceUsd",
    "baseUnits",
    "orderFlags",
    "skipTransferToParent",
    "reduceOnly",
    "leverage",
    "orderType",
    "subaccountIndex",
    "orderPacket",
]

for target, row in call_sites.items():

    if not row.get(
        "found",
        False
    ):
        continue

    args = row[
        "arguments"
    ]

    if not args:
        continue

    # Match object properties but preserve expressions.
    for m in re.finditer(
        r"(?:^|[,{])\s*"
        r"([A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*:\s*"
        r"([^,}]+)",
        args
    ):

        field = m.group(1)
        expr = compact(
            m.group(2)
        )

        if (
            field not in ORDER_FIELDS
            and
            not any(
                x in expr
                for x in [
                    "collateral",
                    "marginInputs",
                    "sequence",
                    "slot",
                    "version",
                    "ordersBySequence",
                    "ordersBySymbol",
                    "positionsBySymbol",
                ]
            )
        ):
            continue

        parameter_flow.append({

            "target":
                target,

            "field":
                field,

            "expression":
                expr,

            "offset":
                row[
                    "actualOffset"
                ],

            "stateReferences":
                [
                    x
                    for x in [
                        "collateral",
                        "marginInputs",
                        "sequence",
                        "slot",
                        "version",
                        "ordersBySequence",
                        "ordersBySymbol",
                        "positionsBySymbol",
                        "subaccountsByIndex",
                    ]
                    if re.search(
                        rf"\b{re.escape(x)}\b",
                        expr,
                        flags=re.I
                    )
                ]
        })

# ============================================================
# 6. TRACE VARIABLES USED AS ARGUMENTS BACKWARD IN R
# ============================================================

R_CODE = (
    r_function[
        "code"
    ]
    if r_function
    else
    context(
        R_OFFSET,
        0,
        5000
    )
)

variable_trace = []

for row in parameter_flow:

    expr = row[
        "expression"
    ]

    identifiers = sorted(
        set(
            m.group(1)
            for m in re.finditer(
                r"\b([A-Za-z_$][A-Za-z0-9_$]*)\b",
                expr
            )
        )
    )

    for name in identifiers:

        # Skip literals/property names/general keywords.
        if name in {
            "true",
            "false",
            "null",
            "undefined",
            "void",
            "long",
            "buy",
            "sell",
        }:
            continue

        # Search backward within R.
        matches = list(
            re.finditer(
                rf"\b(?:const|let|var)\s+"
                rf"{re.escape(name)}\s*=\s*"
                r"([^;]+)",
                R_CODE
            )
        )

        if not matches:

            matches = list(
                re.finditer(
                    rf"\b{re.escape(name)}\s*=\s*"
                    r"([^;]+)",
                    R_CODE
                )
            )

        for m in matches[-5:]:

            variable_trace.append({

                "target":
                    row[
                        "target"
                    ],

                "field":
                    row[
                        "field"
                    ],

                "variable":
                    name,

                "initializer":
                    compact(
                        m.group(1)
                    ),

                "offsetInR":
                    m.start()
            })

# ============================================================
# 7. INSPECT FUNCTIONS ENCLOSING THE TWO EARLY REFERENCES
# ============================================================

early_analysis = {}

for target, pos in [
    (
        "placeIsolatedLimitOrder",
        183521
    ),
    (
        "placeIsolatedMarketOrder",
        184170
    ),
]:

    funcs = enclosing_function(
        pos
    )

    selected = funcs[
        :8
    ]

    rows = []

    for f in selected:

        code = f[
            "code"
        ]

        rows.append({

            "offset":
                f[
                    "offset"
                ],

            "length":
                f[
                    "length"
                ],

            "kind":
                f[
                    "kind"
                ],

            "name":
                f[
                    "name"
                ],

            "declaration":
                f[
                    "declaration"
                ],

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
                ),

            "orderFields":
                [
                    x
                    for x in ORDER_FIELDS
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
                        "signature",
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
                        "ordersBySequence",
                        "ordersBySymbol",
                        "positionsBySymbol",
                        "subaccountsByIndex",
                        "sequence",
                        "slot",
                        "version",
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

    early_analysis[
        target
    ] = rows

# ============================================================
# 8. SEARCH ALL DEFINITIONS OF FUNCTION NAMES DISCOVERED
# ============================================================

def definitions(name):
    rows = []
    seen = set()

    patterns = [

        rf"\bfunction\s+{re.escape(name)}\s*\(",

        rf"\b(?:const|let|var)\s+"
        rf"{re.escape(name)}\s*=",

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

            seen.add(
                p
            )

            raw = balanced(
                TEXT,
                p,
                "{",
                180000
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

    return rows

# ============================================================
# 9. SECOND-HOP CALLEES FROM EARLY IMPLEMENTATION
# ============================================================

secondary = {}

for target, rows in early_analysis.items():

    names = set()

    for row in rows:

        for call in row[
            "calls"
        ]:

            names.add(
                call
            )

    result = []

    for name in sorted(names):

        defs = definitions(
            name
        )

        if defs:

            for d in defs[:10]:

                code = d[
                    "code"
                ]

                result.append({

                    "callee":
                        name,

                    "offset":
                        d[
                            "offset"
                        ],

                    "length":
                        d[
                            "length"
                        ],

                    "orderFields":
                        [
                            x
                            for x in ORDER_FIELDS
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
                                "ordersBySequence",
                                "ordersBySymbol",
                                "positionsBySymbol",
                                "subaccountsByIndex",
                                "sequence",
                                "slot",
                                "version",
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
                                "signature",
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

    secondary[
        target
    ] = result

# ============================================================
# 10. STATIC STATE GROUND TRUTH
# ============================================================

static = {

    "placeOrder_R":
        bool(
            re.search(
                r"\bplaceOrder\s*:\s*R\b",
                TEXT
            )
        ),

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
# 11. MILESTONE
# ============================================================

limit_call_found = call_sites[
    "placeIsolatedLimitOrder"
].get(
    "found",
    False
)

market_call_found = call_sites[
    "placeIsolatedMarketOrder"
].get(
    "found",
    False
)

r_contains_order_calls = (
    r_function is not None
    and
    any(
        target
        in
        r_function[
            "code"
        ]
        for target in [
            "placeIsolatedLimitOrder",
            "placeIsolatedMarketOrder",
        ]
    )
)

early_limit_found = bool(
    early_analysis[
        "placeIsolatedLimitOrder"
    ]
)

early_market_found = bool(
    early_analysis[
        "placeIsolatedMarketOrder"
    ]

)

order_parameter_surface = (
    len(
        parameter_flow
    )
    >
    0
)

secondary_surface = any(
    secondary.get(
        target
    )
    for target
    in TARGETS
    if target
    in secondary
)

if (
    r_contains_order_calls
    and
    early_limit_found
    and
    early_market_found
    and
    order_parameter_surface
):

    classification = (
        "ORDER_CALL_GRAPH_AND_PARAMETER_FLOW_RECONSTRUCTED"
    )

elif (
    r_contains_order_calls
    and
    (
        early_limit_found
        or
        early_market_found
    )
):

    classification = (
        "ORDER_IMPLEMENTATION_BOUNDARY_PARTIALLY_RECONSTRUCTED"
    )

elif (
    r_contains_order_calls
):

    classification = (
        "R_ORDER_CALLS_RECONSTRUCTED"
    )

else:

    classification = (
        "ORDER_PATH_REQUIRES_FURTHER_STATIC_RESOLUTION"
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
                TEXT.encode(
                    "utf-8"
                )
            )
    },

    "knownOffsets":
        KNOWN_CALLS,

    "knownRegions":
        known_regions,

    "callSites":
        call_sites,

    "R":
        {
            "offset":
                R_OFFSET,

            "function":
                r_function,

            "candidates":
                r_function_candidates
        },

    "earlyAnalysis":
        early_analysis,

    "parameterFlow":
        parameter_flow,

    "variableTrace":
        variable_trace,

    "secondary":
        secondary,

    "static":
        static,

    "milestone":
        {

            "limitCallFound":
                limit_call_found,

            "marketCallFound":
                market_call_found,

            "RContainsOrderCalls":
                r_contains_order_calls,

            "earlyLimitFunction":
                early_limit_found,

            "earlyMarketFunction":
                early_market_found,

            "orderParameterSurface":
                order_parameter_surface,

            "secondarySurface":
                secondary_surface,

            "parameterFlowCount":
                len(
                    parameter_flow
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
    "ORDER_CALLGRAPH_PARAMETER_FLOW_v6_0.json"
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

    "CALL_SITES.json":
        call_sites,

    "R.json":
        r_function,

    "R_CANDIDATES.json":
        r_function_candidates,

    "EARLY_LIMIT.json":
        early_analysis[
            "placeIsolatedLimitOrder"
        ],

    "EARLY_MARKET.json":
        early_analysis[
            "placeIsolatedMarketOrder"
        ],

    "PARAMETER_FLOW.json":
        parameter_flow,

    "VARIABLE_TRACE.json":
        variable_trace,

    "SECONDARY.json":
        secondary,

    "STATIC.json":
        static,

    "MILESTONE.json":
        report[
            "milestone"
        ]
}

for name,obj in exports.items():

    (
        CORPUS /
        f"ORDER_V6_{name}"
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
print("SANA FORENSICS — ORDER CALLGRAPH + PARAMETER FLOW v6.0")
print("=" * 115)

print()
print("KNOWN CALLS")

for target,row in call_sites.items():

    print()
    print(
        target
    )

    print(
        "  FOUND:",
        row.get(
            "found",
            False
        )
    )

    if row.get(
        "found",
        False
    ):

        print(
            "  ACTUAL OFFSET:",
            row[
                "actualOffset"
            ]
        )

        print(
            "  ARGS:",
            row[
                "arguments"
            ]
        )

print()
print("R")

if r_function:

    print(
        "  OFFSET:",
        r_function[
            "offset"
        ]
    )

    print(
        "  LENGTH:",
        r_function[
            "length"
        ]
    )

    print(
        "  KIND:",
        r_function[
            "kind"
        ]
    )

    print(
        "  NAME:",
        r_function[
            "name"
        ]
    )

    print(
        "  DECL:",
        r_function[
            "declaration"
        ]
    )

else:

    print(
        "  NONE"
    )

print()
print("R ORDER CALLS")

if r_function:

    for target in TARGETS:

        hits = list(
            re.finditer(
                rf"\b{re.escape(target)}\s*\(",
                r_function[
                    "code"
                ]
            )
        )

        if not hits:
            continue

        print()
        print(
            target,
            "count=",
            len(hits)
        )

        for m in hits:

            raw = balanced(
                r_function[
                    "code"
                ],
                m.start(),
                "(",
                50000
            )

            print(
                "  OFFSET:",
                m.start()
            )

            print(
                "  ARGS:",
                compact(
                    raw[1:-1]
                )
                if raw
                else
                None
            )

print()
print("EARLY LIMIT")

for row in early_analysis[
    "placeIsolatedLimitOrder"
]:

    print()
    print(
        "OFFSET:",
        row[
            "offset"
        ]
    )

    print(
        "NAME:",
        row[
            "name"
        ]
    )

    print(
        "KIND:",
        row[
            "kind"
        ]
    )

    print(
        "ORDER:",
        row[
            "orderFields"
        ]
    )

    print(
        "STATE:",
        row[
            "stateFields"
        ]
    )

    print(
        "AUTH:",
        row[
            "authFields"
        ]
    )

    print(
        "NETWORK:",
        row[
            "networkFields"
        ]
    )

print()
print("EARLY MARKET")

for row in early_analysis[
    "placeIsolatedMarketOrder"
]:

    print()
    print(
        "OFFSET:",
        row[
            "offset"
        ]
    )

    print(
        "NAME:",
        row[
            "name"
        ]
    )

    print(
        "KIND:",
        row[
            "kind"
        ]
    )

    print(
        "ORDER:",
        row[
            "orderFields"
        ]
    )

    print(
        "STATE:",
        row[
            "stateFields"
        ]
    )

    print(
        "AUTH:",
        row[
            "authFields"
        ]
    )

    print(
        "NETWORK:",
        row[
            "networkFields"
        ]
    )

print()
print("PARAMETER FLOW")

for row in parameter_flow:

    print(
        row[
            "target"
        ],
        ":",
        row[
            "field"
        ],
        "<=",
        row[
            "expression"
        ],
        "STATE=",
        row[
            "stateReferences"
        ]
    )

print()
print("VARIABLE TRACE")

for row in variable_trace:

    print(
        row[
            "target"
        ],
        row[
            "field"
        ],
        "->",
        row[
            "variable"
        ],
        "=",
        row[
            "initializer"
        ]
    )

print()
print("SECONDARY CALLEES")

for target, rows in secondary.items():

    if not rows:
        continue

    print()
    print(
        target
    )

    for row in rows[:80]:

        print(
            "  ",
            row[
                "callee"
            ],
            "@",
            row[
                "offset"
            ]
        )

        print(
            "    ORDER:",
            row[
                "orderFields"
            ]
        )

        print(
            "    STATE:",
            row[
                "stateFields"
            ]
        )

        print(
            "    AUTH:",
            row[
                "authFields"
            ]
        )

        print(
            "    NETWORK:",
            row[
                "networkFields"
            ]
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
        f"{k:42s}:",
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

