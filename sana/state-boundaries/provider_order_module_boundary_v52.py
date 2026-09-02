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
# UTIL
# ============================================================

def compact(s):
    return re.sub(r"\s+", " ", s).strip()

def snippet(pos, before=2500, after=5000):
    return compact(
        text[
            max(0, pos-before):
            min(len(text), pos+after)
        ]
    )

def balanced(source, start, opener="{", limit=250000):
    p = source.find(
        opener,
        start
    )

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

# ============================================================
# 1. EXACT TARGET OCCURRENCES
# ============================================================

targets = [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
    "buildLimitOrderPacket",
    "buildMarketOrderPacket",
    "buildPlaceLimitOrder",
    "buildPlaceMarketOrder",
]

occurrences = {}

for target in targets:

    rows = []

    for m in re.finditer(
        rf"\b{re.escape(target)}\b",
        text
    ):

        rows.append({

            "offset":
                m.start(),

            "match":
                m.group(0),

            "prefix":
                compact(
                    text[
                        max(0, m.start()-900):
                        m.start()
                    ]
                ),

            "suffix":
                compact(
                    text[
                        m.start():
                        min(
                            len(text),
                            m.start()+1800
                        )
                    ]
                ),

            "context":
                snippet(
                    m.start(),
                    5000,
                    8000
                )
        })

    occurrences[
        target
    ] = rows

# ============================================================
# 2. IDENTIFICAR LA OCURRENCIA QUE REALMENTE ES USADA POR R
# ============================================================

r_start = 452460
r_raw = balanced(
    text,
    r_start,
    "{",
    10000
)

if not r_raw:
    raise RuntimeError(
        "R no encontrado"
    )

r_code = compact(
    r_raw
)

r_calls = {}

for target in targets:

    rows = []

    for m in re.finditer(
        rf"\b{re.escape(target)}\s*\(",
        r_code
    ):

        rows.append({

            "offsetInR":
                m.start(),

            "absoluteApprox":
                r_start + m.start(),

            "callText":
                compact(
                    r_code[
                        m.start():
                        min(
                            len(r_code),
                            m.start()+2500
                        )
                    ]
                ),

            "context":
                compact(
                    r_code[
                        max(0, m.start()-1200):
                        min(
                            len(r_code),
                            m.start()+5000
                        )
                    )
        })

    r_calls[
        target
    ] = rows

# ============================================================
# 3. EXTRAER ARGUMENTOS CORRECTAMENTE
# ============================================================

def extract_paren_call(
    source,
    offset
):

    p = source.find(
        "(",
        offset
    )

    if p < 0:
        return None

    raw = balanced(
        source,
        p,
        "(",
        60000
    )

    if not raw:
        return None

    return compact(
        raw[1:-1]
    )

r_arguments = {}

for target in targets:

    vals = []

    for row in r_calls[
        target
    ]:

        args = extract_paren_call(
            r_code,
            row[
                "offsetInR"
            ]
        )

        vals.append({

            "offsetInR":
                row[
                    "offsetInR"
                ],

            "arguments":
                args
        })

    r_arguments[
        target
    ] = vals

# ============================================================
# 4. ENCONTRAR LA FUNCIÓN "PADRE" DE CADA REFERENCIA REAL
#    SIN CONFUNDIRLA CON DEFINICIONES ALIAS.
# ============================================================

def function_candidates_before(
    pos,
    search_back=120000
):

    start = max(
        0,
        pos-search_back
    )

    region = text[
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
            "arrow",
            r"\b"
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
            r"\s*\([^)]*\)\s*\{"
        ),

        (
            "object_method",
            r"\b"
            r"([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s*:\s*"
            r"(?:async\s*)?"
            r"\([^)]*\)\s*\{"
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
                text,
                absolute,
                "{",
                150000
            )

            if not raw:
                continue

            end = (
                absolute
                +
                len(raw)
            )

            if (
                absolute <= pos <= end
            ):

                candidates.append({

                    "name":
                        m.group(1),

                    "kind":
                        kind,

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
        key=lambda x:
            (
                x["offset"],
                -x["length"]
            ),
        reverse=True
    )

    return candidates

# ============================================================
# 5. RESOLVE DIRECT R CALL TARGET BY OCCURRENCE
# ============================================================

direct_occurrence_resolution = {}

for target in targets:

    rows = []

    for occ in occurrences[
        target
    ]:

        pos = occ[
            "offset"
        ]

        parents = function_candidates_before(
            pos
        )

        # distance from R use
        parent = None

        for candidate in parents:

            # Prefer a candidate whose body contains the exact
            # target invocation rather than a giant outer scope.
            if re.search(
                rf"\b{re.escape(target)}\s*\(",
                candidate[
                    "code"
                ]
            ):

                parent = candidate
                break

        rows.append({

            "occurrenceOffset":
                pos,

            "parent":
                parent,

            "context":
                occ[
                    "context"
                ]
        })

    direct_occurrence_resolution[
        target
    ] = rows

# ============================================================
# 6. IDENTIFICAR SI LAS OCURRENCIAS 183521 / 184170
#    SON IMPLEMENTACIONES REALES
# ============================================================

implementation_candidates = {}

for target in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]:

    rows = []

    for occ in occurrences[
        target
    ]:

        p = occ[
            "offset"
        ]

        before = compact(
            text[
                max(0,p-180):
                p
            ]
        )

        after = compact(
            text[
                p:
                min(
                    len(text),
                    p+1200
                )
            ]
        )

        patterns = [

            rf"{re.escape(target)}\s*=\s*",

            rf"{re.escape(target)}\s*:\s*",

            rf"function\s+{re.escape(target)}\s*\(",

            rf"([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
            rf".{{0,100}}{re.escape(target)}",

            rf"([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*"
            rf".{{0,100}}{re.escape(target)}",
        ]

        local_def = None

        for pattern in patterns:

            m = re.search(
                pattern,
                before + after,
                flags=re.I
            )

            if m:

                local_def = {
                    "pattern":
                        pattern,

                    "match":
                        m.group(0)
                }

                break

        rows.append({

            "offset":
                p,

            "before":
                before,

            "after":
                after,

            "localDefinitionSignal":
                local_def,

            "parent":
                function_candidates_before(
                    p
                )[:20],

            "context":
                occ[
                    "context"
                ]
        })

    implementation_candidates[
        target
    ] = rows

# ============================================================
# 7. RESOLVER DE REFERENCIA POR EXPORT/IMPORT
# ============================================================

module_reference_patterns = [

    r"(?:from\s+)(?:\"[^\"]+\"|'[^']+')",

    r"(?:import|export)[^;]{0,2000}",

    r"\b(?:exports|module\.exports)\b[^;]{0,3000}",
]

module_refs = []

for target in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]:

    for m in re.finditer(
        rf".{{0,1200}}\b{re.escape(target)}\b.{{0,1800}}",
        text,
        flags=re.I
    ):

        c = compact(
            m.group(0)
        )

        if (
            "from" in c.lower()
            or
            "export" in c.lower()
            or
            "import" in c.lower()
            or
            "exports" in c.lower()
            or
            "module.exports" in c.lower()
        ):

            module_refs.append({

                "target":
                    target,

                "offset":
                    m.start(),

                "context":
                    c
            })

# ============================================================
# 8. EXACT OBJECT/MODULE REGIONS AROUND REAL REFERENCES
# ============================================================

regions = {}

for target in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]:

    out = []

    for occ in occurrences[
        target
    ]:

        p = occ[
            "offset"
        ]

        # recoger varios niveles del texto hacia atrás
        # hasta una llave que cierre después de la ocurrencia
        candidates = []

        start_search = max(
            0,
            p-30000
        )

        for m in re.finditer(
            r"\{",
            text[
                start_search:
                p+1
            ]
        ):

            abs_start = (
                start_search
                +
                m.start()
            )

            raw = balanced(
                text,
                abs_start,
                "{",
                100000
            )

            if not raw:
                continue

            abs_end = (
                abs_start
                +
                len(raw)
            )

            if (
                abs_start
                <= p
                <= abs_end
            ):

                candidates.append({

                    "offset":
                        abs_start,

                    "length":
                        len(raw),

                    "code":
                        compact(raw)
                })

        candidates.sort(
            key=lambda x:
                (
                    x["length"],
                    abs(p-x["offset"])
                )
        )

        out.append({

            "target":
                target,

            "occurrence":
                p,

            "containingObjects":
                candidates[:8]
        })

    regions[
        target
    ] = out

# ============================================================
# 9. IMPORTANT DISCOVERY:
#    BUSCAR "async" / FUNCTION ANONIMA DENTRO DE LOS
#    CONTEXTOS DE 183521 / 184170
# ============================================================

anonymous_function_contexts = {}

for target in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]:

    rows = []

    for occ in occurrences[
        target
    ]:

        p = occ[
            "offset"
        ]

        c = snippet(
            p,
            12000,
            18000
        )

        patterns = [

            r"\basync\s*\(",

            r"\basync\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\(",

            r"\bfunction\s*\(",

            r"\([^)]*\)\s*=>",

            r"[A-Za-z_$][A-Za-z0-9_$]*\s*:\s*(?:async\s*)?\(",
        ]

        hits = []

        for pattern in patterns:

            for m in re.finditer(
                pattern,
                c,
                flags=re.I
            ):

                hits.append({

                    "pattern":
                        pattern,

                    "offsetInContext":
                        m.start(),

                    "text":
                        m.group(0),

                    "near":
                        compact(
                            c[
                                max(
                                    0,
                                    m.start()-800
                                ):
                                min(
                                    len(c),
                                    m.start()+1800
                                )
                            ]
                        )
                })

        rows.append({

            "offset":
                p,

            "hits":
                hits[:100],

            "context":
                c
        })

    anonymous_function_contexts[
        target
    ] = rows

# ============================================================
# 10. STATIC STATE GROUND TRUTH
# ============================================================

static = {

    "placeOrderBindingR":
        bool(
            re.search(
                r"\bplaceOrder\s*:\s*R\b",
                text
            )
        ),

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
        ),
}

# ============================================================
# 11. MILESTONE
# ============================================================

limit_occ = occurrences[
    "placeIsolatedLimitOrder"
]

market_occ = occurrences[
    "placeIsolatedMarketOrder"
]

limit_has_r_call = bool(
    r_calls[
        "placeIsolatedLimitOrder"
    ]
)

market_has_r_call = bool(
    r_calls[
        "placeIsolatedMarketOrder"
    ]
)

limit_secondary_occurrence = any(
    x["offset"] < r_start
    for x in limit_occ
)

market_secondary_occurrence = any(
    x["offset"] < r_start
    for x in market_occ
)

# The important point now is not "definition found".
# It is whether the implementation/module behind the
# provider-exported function can be reconstructed.

second_module_limit = (
    limit_secondary_occurrence
    and
    len(
        implementation_candidates[
            "placeIsolatedLimitOrder"
        ]
    ) > 0
)

second_module_market = (
    market_secondary_occurrence
    and
    len(
        implementation_candidates[
            "placeIsolatedMarketOrder"
        ]
    ) > 0
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

    "rDefinition": {
        "offset":
            r_start,

        "length":
            len(r_raw),

        "code":
            r_code
    },

    "rCalls":
        r_calls,

    "rArguments":
        r_arguments,

    "occurrences":
        occurrences,

    "directOccurrenceResolution":
        direct_occurrence_resolution,

    "implementationCandidates":
        implementation_candidates,

    "moduleRefs":
        module_refs,

    "regions":
        regions,

    "anonymousFunctionContexts":
        anonymous_function_contexts,

    "static":
        static,

    "milestone": {

        "RResolved":
            True,

        "limitCallInR":
            limit_has_r_call,

        "marketCallInR":
            market_has_r_call,

        "limitHasEarlierImplementationReference":
            second_module_limit,

        "marketHasEarlierImplementationReference":
            second_module_market,

        "limitOccurrences":
            len(limit_occ),

        "marketOccurrences":
            len(market_occ),

        "nextStep":
            "RECONSTRUCT_MODULE_OR_EXPORT_BOUNDARY_AT_183521_184170"
    },

    "finding": {

        "classification":
            (
                "PROVIDER_EXPORT_TARGETS_CONFIRMED_MODULE_BOUNDARY_TRACE_REQUIRED"
                if (
                    limit_has_r_call
                    and
                    market_has_r_call
                    and
                    (
                        second_module_limit
                        or
                        second_module_market
                    )
                )
                else
                "PROVIDER_EXPORT_TARGETS_CONFIRMED"
            ),

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
    "PROVIDER_ORDER_MODULE_BOUNDARY_v5_2.json"
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

    "R_EXACT.txt":
        r_code,

    "R_CALLS.json":
        r_calls,

    "R_ARGUMENTS.json":
        r_arguments,

    "OCCURRENCES.json":
        occurrences,

    "DIRECT_RESOLUTION.json":
        direct_occurrence_resolution,

    "IMPLEMENTATION_CANDIDATES.json":
        implementation_candidates,

    "MODULE_REFS.json":
        module_refs,

    "REGIONS.json":
        regions,

    "ANONYMOUS_CONTEXTS.json":
        anonymous_function_contexts,

    "STATIC.json":
        static,

    "MILESTONE.json":
        report[
            "milestone"
        ]
}

for name,obj in exports.items():

    out = (
        CORPUS /
        f"PROVIDER_ORDER_{name}"
    )

    if isinstance(
        obj,
        str
    ):

        out.write_text(
            obj,
            encoding="utf-8"
        )

    else:

        out.write_text(
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
print("SANA FORENSICS — PROVIDER ORDER MODULE BOUNDARY v5.2")
print("=" * 115)

print()
print("R")
print(
    "offset:",
    r_start
)
print(
    "length:",
    len(r_raw)
)

print()
print("R CALLS")

for target in targets:

    print()
    print(
        target,
        "count=",
        len(
            r_calls[
                target
            ]
        )
    )

    for row in r_arguments[
        target
    ]:

        print(
            "OFFSET:",
            row[
                "offsetInR"
            ]
        )

        print(
            "ARGS:",
            row[
                "arguments"
            ]
        )

print()
print("GLOBAL OCCURRENCES")

for target in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]:

    print()
    print(
        target,
        "count=",
        len(
            occurrences[
                target
            ]
        )
    )

    for row in occurrences[
        target
    ]:

        print(
            "OFFSET:",
            row[
                "offset"
            ]
        )

        print(
            "SUFFIX:",
            row[
                "suffix"
            ]
        )

print()
print("IMPLEMENTATION SIGNALS")

for target in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]:

    print()
    print(
        target
    )

    for row in implementation_candidates[
        target
    ]:

        print(
            "OFFSET:",
            row[
                "offset"
            ]
        )

        print(
            "LOCAL DEF:",
            row[
                "localDefinitionSignal"
            ]
        )

        parents = row[
            "parent"
        ]

        for parent in parents[:3]:

            print(
                "  PARENT:",
                parent[
                    "name"
                ],
                "@",
                parent[
                    "offset"
                ],
                "len=",
                parent[
                    "length"
                ]
            )

print()
print("MODULE REFERENCES:",
      len(module_refs))

for row in module_refs[:50]:

    print()
    print(
        row[
            "target"
        ],
        "@",
        row[
            "offset"
        ]
    )

print(
    row[
        "context"
    ]
)

print()
print("OBJECT REGIONS")

for target in [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]:

    print()
    print(
        target
    )

    for row in regions[
        target
    ]:

        print(
            "OCCURRENCE:",
            row[
                "occurrence"
            ]
        )

        for obj in row[
            "containingObjects"
        ][:5]:

            print(
                "  OBJECT",
                obj[
                    "offset"
                ],
                "len=",
                obj[
                    "length"
                ]
            )

print()
print("STATIC")

for k,v in static.items():

    print(
        f"{k:38s}:",
        v
    )

print()
print("MILESTONE")

for k,v in report[
    "milestone"
].items():

    print(
        f"{k:48s}:",
        v
    )

print()
print(
    "CLASSIFICATION:",
    report[
        "finding"
    ][
        "classification"
    ]
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

