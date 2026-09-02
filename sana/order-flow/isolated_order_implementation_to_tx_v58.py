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

R_START = 452460
LIMIT_REF = 183521
MARKET_REF = 184170

def compact(s):
    return re.sub(r"\s+", " ", s).strip()

def ctx(pos, before=9000, after=12000):
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

def function_candidates_containing(pos):
    start = max(0, pos - 180000)
    region = TEXT[start:pos]

    patterns = [

        (
            "named",
            r"\bfunction\s+"
            r"([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*\([^)]*\)\s*\{"
        ),

        (
            "arrow",
            r"\b(?:const|let|var)\s+"
            r"([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*=\s*"
            r"(?:async\s*)?"
            r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*=>\s*\{"
        ),

        (
            "method",
            r"\b"
            r"([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*:\s*"
            r"(?:async\s*)?"
            r"\([^)]*\)\s*\{"
        ),

        (
            "compact_method",
            r"\b"
            r"([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*\([^)]*\)\s*\{"
        ),
    ]

    candidates = []

    for kind, pattern in patterns:

        for m in re.finditer(
            pattern,
            region
        ):

            absolute = start + m.start()

            raw = balanced(
                TEXT,
                absolute,
                "{",
                220000
            )

            if not raw:
                continue

            end = absolute + len(raw)

            if absolute <= pos <= end:

                candidates.append({

                    "kind":
                        kind,

                    "name":
                        m.group(1),

                    "offset":
                        absolute,

                    "length":
                        len(raw),

                    "declaration":
                        m.group(0),

                    "code":
                        compact(raw)
                })

    # smallest enclosing first
    candidates.sort(
        key=lambda x: (
            x["length"],
            -x["offset"]
        )
    )

    return candidates

def call_names(code):
    return sorted(
        set(
            m.group(1)
            for m in re.finditer(
                r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
                code
            )
            if m.group(1)
            not in {
                "if","else","for","while","do","switch",
                "case","return","throw","catch","finally",
                "function","new","typeof","void","delete",
                "instanceof","await","async"
            }
        )
    )

# ============================================================
# 1. EXACT R
# ============================================================

r_raw = balanced(
    TEXT,
    R_START,
    "{",
    15000
)

if not r_raw:
    raise RuntimeError("No se pudo extraer R")

R_CODE = compact(r_raw)

# ============================================================
# 2. ANALIZAR LAS REFERENCIAS TEMPRANAS
# ============================================================

def analyze_reference(
    name,
    pos
):
    candidates = function_candidates_containing(
        pos
    )

    # sólo candidatos cuya región realmente contiene el target
    containing = []

    for candidate in candidates:

        if re.search(
            rf"\b{re.escape(name)}\b",
            candidate["code"]
        ):
            containing.append(
                candidate
            )

    return {

        "name":
            name,

        "offset":
            pos,

        "context":
            ctx(
                pos,
                15000,
                18000
            ),

        "containingFunctions":
            containing[:12]
    }

limit_analysis = analyze_reference(
    "placeIsolatedLimitOrder",
    LIMIT_REF
)

market_analysis = analyze_reference(
    "placeIsolatedMarketOrder",
    MARKET_REF
)

# ============================================================
# 3. ELEGIR EL CONTENEDOR MÁS PEQUEÑO
# ============================================================

limit_container = (
    limit_analysis[
        "containingFunctions"
    ][0]
    if limit_analysis[
        "containingFunctions"
    ]
    else None
)

market_container = (
    market_analysis[
        "containingFunctions"
    ][0]
    if market_analysis[
        "containingFunctions"
    ]
    else None
)

# ============================================================
# 4. EXTRAER LAS LLAMADAS DENTRO DEL CONTENEDOR
# ============================================================

def detailed_calls(
    definition
):
    if not definition:
        return []

    code = definition[
        "code"
    ]

    rows = []

    for m in re.finditer(
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
        code
    ):

        name = m.group(1)

        if name in {
            "if","else","for","while","do","switch",
            "case","return","throw","catch","finally",
            "function","new","typeof","void","delete",
            "instanceof","await","async",
            "Error","Number","String","Boolean",
            "Object","Array","Promise","Math","JSON",
        }:
            continue

        rows.append({

            "name":
                name,

            "offset":
                m.start(),

            "near":
                compact(
                    code[
                        max(0,m.start()-1200):
                        min(len(code),m.start()+3500)
                    ]
                )
        })

    return rows

limit_calls = detailed_calls(
    limit_container
)

market_calls = detailed_calls(
    market_container
)

# ============================================================
# 5. EXTRAER OBJECT LITERALS QUE ENVUELVEN LAS LLAMADAS
# ============================================================

def object_literals_for_call(
    definition,
    target
):
    if not definition:
        return []

    code = definition[
        "code"
    ]

    rows = []

    for m in re.finditer(
        rf"\b{re.escape(target)}\s*\(",
        code
    ):

        p = m.start()

        paren = balanced(
            code,
            p,
            "(",
            60000
        )

        if not paren:
            continue

        args = compact(
            paren[1:-1]
        )

        rows.append({

            "offset":
                p,

            "arguments":
                args,

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
                        "orderType",
                        "subaccountIndex",
                    ]
                    if re.search(
                        rf"\b{re.escape(x)}\s*:",
                        args,
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
                    ]
                    if re.search(
                        rf"\b{re.escape(x)}\b",
                        args,
                        flags=re.I
                    )
                ]
        })

    return rows

limit_target_calls = object_literals_for_call(
    limit_container,
    "placeIsolatedLimitOrder"
)

market_target_calls = object_literals_for_call(
    market_container,
    "placeIsolatedMarketOrder"
)

# ============================================================
# 6. BUSCAR EXPORT TABLE / MODULE REGISTRATION CERCANA
# ============================================================

def nearby_text(
    pos,
    radius=120000
):
    return TEXT[
        max(0,pos-radius):
        min(len(TEXT),pos+radius)
    ]

def module_export_candidates(
    target,
    pos
):

    region = nearby_text(
        pos,
        100000
    )

    rows = []

    patterns = [

        rf"""\["{re.escape(target)}"\s*,[^]]{{0,5000}}\]""",

        rf"""{re.escape(target)}\s*,\s*\d+\s*,\s*[A-Za-z_$][A-Za-z0-9_$]*""",

        rf"""["']{re.escape(target)}["']\s*,\s*0\s*,\s*[A-Za-z_$][A-Za-z0-9_$]*""",

        rf"""{re.escape(target)}\s*:\s*[A-Za-z_$][A-Za-z0-9_$]*""",
    ]

    for pattern in patterns:

        for m in re.finditer(
            pattern,
            region,
            flags=re.I
        ):

            absolute = (
                max(0,pos-100000)
                +
                m.start()
            )

            rows.append({

                "offset":
                    absolute,

                "match":
                    m.group(0),

                "context":
                    compact(
                        region[
                            max(0,m.start()-2500):
                            min(
                                len(region),
                                m.start()+5000
                            )
                        ]
                    )
            })

    # dedupe
    unique = {}
    for row in rows:
        unique[
            (
                row["offset"],
                row["match"]
            )
        ] = row

    return list(
        unique.values()
    )

limit_exports = module_export_candidates(
    "placeIsolatedLimitOrder",
    LIMIT_REF
)

market_exports = module_export_candidates(
    "placeIsolatedMarketOrder",
    MARKET_REF
)

# ============================================================
# 7. RESOLVER DE ALIAS SIMPLE
# ============================================================

def resolve_aliases(
    target,
    rows
):

    bindings = []

    patterns = [

        rf"""{re.escape(target)}\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)""",

        rf"""{re.escape(target)}\s*=\s*([A-Za-z_$][A-Za-z0-9_$]*)""",

        rf"""([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*{re.escape(target)}\b""",

        rf"""([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*{re.escape(target)}\b""",
    ]

    for row in rows:

        for pattern in patterns:

            m = re.search(
                pattern,
                row["context"],
                flags=re.I
            )

            if not m:
                continue

            groups = [
                g
                for g in m.groups()
                if g
            ]

            bindings.append({

                "target":
                    target,

                "binding":
                    groups[0]
                    if groups
                    else None,

                "match":
                    m.group(0),

                "offset":
                    row[
                        "offset"
                    ]
            })

    unique = {}

    for row in bindings:

        unique[
            (
                row["offset"],
                row["binding"]
            )
        ] = row

    return list(
        unique.values()
    )

limit_aliases = resolve_aliases(
    "placeIsolatedLimitOrder",
    limit_exports
)

market_aliases = resolve_aliases(
    "placeIsolatedMarketOrder",
    market_exports
)

# ============================================================
# 8. EXACT BINDING DEFINITIONS
# ============================================================

def binding_defs(
    name
):
    rows = []
    seen = set()

    patterns = [

        rf"\bfunction\s+{re.escape(name)}\s*\(",

        rf"\b{re.escape(name)}\s*=",

        rf"\b{re.escape(name)}\s*:",

        rf"\b(?:const|let|var)\s+{re.escape(name)}\b",
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

limit_binding_defs = {}

for alias in sorted(
    set(
        x[
            "binding"
        ]
        for x in limit_aliases
        if x[
            "binding"
        ]
    )
):

    limit_binding_defs[
        alias
    ] = binding_defs(
        alias
    )[:20]

market_binding_defs = {}

for alias in sorted(
    set(
        x[
            "binding"
        ]
        for x in market_aliases
        if x[
            "binding"
        ]
    )
):

    market_binding_defs[
        alias
    ] = binding_defs(
        alias
    )[:20]

# ============================================================
# 9. IDENTIFICAR IMPLEMENTACION VIA EXPORT:
#    alias -> definition -> calls/network/auth
# ============================================================

def summarize_defs(
    defs
):

    output = []

    for d in defs:

        code = d[
            "code"
        ]

        output.append({

            "offset":
                d[
                    "offset"
                ],

            "length":
                d[
                    "length"
                ],

            "declaration":
                d[
                    "declaration"
                ],

            "calls":
                call_names(
                    code
                ),

            "order":
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
                        code,
                        flags=re.I
                    )
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
                        "mutate",
                    ]
                    if re.search(
                        rf"\b{re.escape(x)}\b",
                        code,
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
                        "sendTransaction",
                        "signAndSend",
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

    return output

limit_impl = {
    alias:
        summarize_defs(
            defs
        )
    for alias, defs
    in limit_binding_defs.items()
}

market_impl = {
    alias:
        summarize_defs(
            defs
        )
    for alias, defs
    in market_binding_defs.items()
}

# ============================================================
# 10. BUSCAR CONSTRUCCION DE INSTRUCCIONES ALREDEDOR
#     DE LAS IMPLEMENTACIONES
# ============================================================

def transaction_contexts(
    definitions
):

    rows = []

    for alias, defs in definitions.items():

        for d in defs:

            code = d[
                "code"
            ]

            if not (
                re.search(
                    r"\b(?:Transaction|TransactionInstruction|"
                    r"sendTransaction|signAndSend|"
                    r"getLatestBlockhash)\b",
                    code,
                    flags=re.I
                )
            ):
                continue

            rows.append({

                "alias":
                    alias,

                "offset":
                    d[
                        "offset"
                    ],

                "length":
                    d[
                        "length"
                    ],

                "transaction":
                    [
                        x
                        for x in [
                            "Transaction",
                            "TransactionInstruction",
                            "sendTransaction",
                            "signAndSend",
                            "getLatestBlockhash",
                            "confirmTransaction",
                        ]
                        if re.search(
                            rf"\b{re.escape(x)}\b",
                            code,
                            flags=re.I
                        )
                    ],

                "order":
                    [
                        x
                        for x in [
                            "symbol",
                            "side",
                            "price",
                            "priceUsd",
                            "size",
                            "baseUnits",
                            "quantity",
                            "reduceOnly",
                            "leverage",
                            "orderPacket",
                            "authority",
                        ]
                        if re.search(
                            rf"\b{re.escape(x)}\b",
                            code,
                            flags=re.I
                        )
                    ],

                "state":
                    [
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
                            code,
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
                            code,
                            flags=re.I
                        )
                    ],

                "code":
                    code
            })

    return rows

limit_tx = transaction_contexts(
    limit_binding_defs
)

market_tx = transaction_contexts(
    market_binding_defs
)

# ============================================================
# 11. EXACT STATIC STATE
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
# 12. MILESTONE REAL
# ============================================================

limit_earlier_function = bool(
    limit_container
)

market_earlier_function = bool(
    market_container
)

limit_call_reconstructed = (
    bool(
        limit_target_calls
    )
    and
    limit_earlier_function
)

market_call_reconstructed = (
    bool(
        market_target_calls
    )
    and
    market_earlier_function
)

alias_surface = bool(
    limit_aliases
    or
    market_aliases
)

implementation_surface = bool(
    limit_impl
    or
    market_impl
)

transaction_surface = bool(
    limit_tx
    or
    market_tx
)

if (
    limit_call_reconstructed
    and
    market_call_reconstructed
    and
    transaction_surface
):

    classification = (
        "EXACT_ISOLATED_ORDER_TO_TRANSACTION_SURFACE"
    )

elif (
    limit_call_reconstructed
    and
    market_call_reconstructed
    and
    implementation_surface
):

    classification = (
        "EXACT_ISOLATED_ORDER_IMPLEMENTATION_SURFACE"
    )

elif (
    limit_call_reconstructed
    or
    market_call_reconstructed
    or
    alias_surface
):

    classification = (
        "ISOLATED_ORDER_IMPLEMENTATION_PATH_PARTIALLY_RECONSTRUCTED"
    )

else:

    classification = (
        "ISOLATED_ORDER_IMPLEMENTATION_NOT_RECONSTRUCTED"
    )

# ============================================================
# 13. REPORT
# ============================================================

report = {

    "bundle":
        {
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
        {
            "R":
                R_START,

            "limit":
                LIMIT_REF,

            "market":
                MARKET_REF
        },

    "R":
        {
            "offset":
                R_START,

            "length":
                len(r_raw),

            "code":
                R_CODE
        },

    "limitAnalysis":
        limit_analysis,

    "marketAnalysis":
        market_analysis,

    "limitCalls":
        limit_calls,

    "marketCalls":
        market_calls,

    "limitTargetCalls":
        limit_target_calls,

    "marketTargetCalls":
        market_target_calls,

    "limitExports":
        limit_exports,

    "marketExports":
        market_exports,

    "limitAliases":
        limit_aliases,

    "marketAliases":
        market_aliases,

    "limitBindingDefinitions":
        limit_binding_defs,

    "marketBindingDefinitions":
        market_binding_defs,

    "limitImplementation":
        limit_impl,

    "marketImplementation":
        market_impl,

    "limitTransactions":
        limit_tx,

    "marketTransactions":
        market_tx,

    "static":
        static,

    "milestone":
        {
            "limitEarlierFunction":
                limit_earlier_function,

            "marketEarlierFunction":
                market_earlier_function,

            "limitCallReconstructed":
                limit_call_reconstructed,

            "marketCallReconstructed":
                market_call_reconstructed,

            "aliasSurface":
                alias_surface,

            "implementationSurface":
                implementation_surface,

            "transactionSurface":
                transaction_surface,

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
    "ISOLATED_ORDER_IMPLEMENTATION_TO_TX_v5_8.json"
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

    "R.txt":
        R_CODE,

    "LIMIT_ANALYSIS.json":
        limit_analysis,

    "MARKET_ANALYSIS.json":
        market_analysis,

    "LIMIT_CALLS.json":
        limit_calls,

    "MARKET_CALLS.json":
        market_calls,

    "LIMIT_TARGET_CALLS.json":
        limit_target_calls,

    "MARKET_TARGET_CALLS.json":
        market_target_calls,

    "LIMIT_EXPORTS.json":
        limit_exports,

    "MARKET_EXPORTS.json":
        market_exports,

    "LIMIT_ALIASES.json":
        limit_aliases,

    "MARKET_ALIASES.json":
        market_aliases,

    "LIMIT_IMPLEMENTATION.json":
        limit_impl,

    "MARKET_IMPLEMENTATION.json":
        market_impl,

    "LIMIT_TX.json":
        limit_tx,

    "MARKET_TX.json":
        market_tx,

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
        f"ISOLATED_TX_{name}"
    ).write_text(
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
print("SANA FORENSICS — ISOLATED ORDER IMPLEMENTATION TO TX v5.8")
print("=" * 115)

print()
print("R")
print(
    "OFFSET:",
    R_START
)
print(
    "LEN:",
    len(r_raw)
)

print()
print("EARLY LIMIT CONTAINER")

if limit_container:

    print(
        "NAME:",
        limit_container[
            "name"
        ]
    )

    print(
        "OFFSET:",
        limit_container[
            "offset"
        ]
    )

    print(
        "LEN:",
        limit_container[
            "length"
        ]
    )

    print(
        "DECL:",
        limit_container[
            "declaration"
        ]
    )

else:

    print(
        "NONE"
    )

print()
print("EARLY MARKET CONTAINER")

if market_container:

    print(
        "NAME:",
        market_container[
            "name"
        ]
    )

    print(
        "OFFSET:",
        market_container[
            "offset"
        ]
    )

    print(
        "LEN:",
        market_container[
            "length"
        ]
    )

    print(
        "DECL:",
        market_container[
            "declaration"
        ]
    )

else:

    print(
        "NONE"
    )

print()
print("R ORDER CALLS")

for target, rows in [
    (
        "placeIsolatedLimitOrder",
        limit_target_calls
    ),
    (
        "placeIsolatedMarketOrder",
        market_target_calls
    ),
]:

    print()
    print(
        target,
        "count=",
        len(rows)
    )

    for row in rows:

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
            "  ARGS:",
            row[
                "arguments"
            ]
        )

print()
print("ALIASES")

print(
    "LIMIT:",
    limit_aliases
)

print(
    "MARKET:",
    market_aliases
)

print()
print("IMPLEMENTATION DEFINITIONS")

for title, data in [
    (
        "LIMIT",
        limit_impl
    ),
    (
        "MARKET",
        market_impl
    )
]:

    print()
    print(title)

    for alias, rows in data.items():

        print(
            "ALIAS:",
            alias,
            "DEFS:",
            len(rows)
        )

        for row in rows[:8]:

            print(
                "  OFFSET:",
                row[
                    "offset"
                ]
            )

            print(
                "  CALLS:",
                row[
                    "calls"
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
                "  NETWORK:",
                row[
                    "network"
                ]
            )

            print(
                "  AUTH:",
                row[
                    "auth"
                ]
            )

print()
print("TRANSACTION SURFACE")

for row in (
    limit_tx +
    market_tx
)[:100]:

    print()
    print(
        row[
            "alias"
        ],
        "@",
        row[
            "offset"
        ]
    )

    print(
        "TX:",
        row[
            "transaction"
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

