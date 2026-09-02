import json
import re
from pathlib import Path

ROOT = Path(r"SANA_FORENSICS_ROOT")
BUNDLE = ROOT / "data" / "raw" / "sana_bundle.js"
REPORTS = ROOT / "data" / "reports"
CORPUS = ROOT / "data" / "corpus"

if not BUNDLE.exists():
    raise RuntimeError("Bundle no encontrado")

text = BUNDLE.read_text(
    encoding="utf-8",
    errors="replace"
)

# ============================================================
# UTILIDADES
# ============================================================

def compact(s):
    return re.sub(r"\s+", " ", s).strip()

def context(source, pos, before=3000, after=6000):
    return compact(
        source[
            max(0, pos-before):
            min(len(source), pos+after)
        ]
    )

def balanced(source, start, opener="{", limit=300000):
    p = source.find(
        opener,
        start
    )

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

    end = min(
        len(source),
        start + limit
    )

    i = p

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

def occurrences(
    source,
    pattern,
    flags=0,
    limit=1000
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
                m.group(0),

            "context":
                context(
                    source,
                    m.start()
                )
        })

        if len(out) >= limit:
            break

    return out

def nearest_block_start(
    source,
    pos
):
    """
    Busca retrospectivamente un comienzo probable
    de función/bloque sin intentar ejecutar JS.
    """
    region = source[
        max(0, pos-30000):
        pos
    ]

    candidates = []

    patterns = [
        r"\bfunction\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\([^)]*\)\s*\{",
        r"\b(?:async\s+)?[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*\{",
        r"\b(?:async\s+)?[A-Za-z_$][A-Za-z0-9_$]*\s*:\s*(?:async\s*)?(?:function\s*)?\([^)]*\)\s*\{",
        r"\b(?:async\s+)?[A-Za-z_$][A-Za-z0-9_$]*\s*\([^)]*\)\s*\{",
    ]

    for pattern in patterns:

        for m in re.finditer(
            pattern,
            region
        ):

            candidates.append({
                "offset":
                    max(0, pos-30000) + m.start(),

                "text":
                    m.group(0)
            })

    if not candidates:
        return None

    candidates.sort(
        key=lambda x:
            x["offset"]
    )

    return candidates[-1]

def enclosing_function(
    source,
    pos
):
    owner = nearest_block_start(
        source,
        pos
    )

    if not owner:
        return None

    raw = balanced(
        source,
        owner["offset"],
        "{",
        100000
    )

    if not raw:
        return {
            "owner":
                owner["text"],

            "offset":
                owner["offset"],

            "code":
                context(
                    source,
                    pos,
                    6000,
                    9000
                )
        }

    return {
        "owner":
            owner["text"],

        "offset":
            owner["offset"],

        "length":
            len(raw),

        "code":
            compact(raw)
    }

# ============================================================
# EXACT CORE
# ============================================================

pm = re.search(
    r"processMessage:\(e,\[t,r\]\)=>",
    text
)

if not pm:
    raise RuntimeError(
        "processMessage no encontrado"
    )

pm_tail = text[
    pm.start():
    min(
        len(text),
        pm.start()+6000
    )
]

pm_end = re.search(
    r"deltas:e\.deltas\?\?\[\]",
    pm_tail
)

if not pm_end:
    raise RuntimeError(
        "processMessage no delimitado"
    )

process_code = compact(
    pm_tail[
        :pm_end.end()
    ]
)

am = re.search(
    r"applyMessage\(e,t\)\{",
    text
)

if not am:
    raise RuntimeError(
        "applyMessage no encontrado"
    )

apply_raw = balanced(
    text,
    am.start(),
    "{",
    350000
)

if not apply_raw:
    raise RuntimeError(
        "applyMessage no extraido"
    )

apply_code = compact(
    apply_raw
)

pf = re.search(
    r"pF=\(e,t\)=>",
    text
)

if not pf:
    raise RuntimeError(
        "pF no encontrado"
    )

pf_raw = balanced(
    text,
    pf.start(),
    "{",
    150000
)

if not pf_raw:
    raise RuntimeError(
        "pF no extraido"
    )

pf_code = compact(
    pf_raw
)

# ============================================================
# DELTA
# ============================================================

delta_candidates = []

for m in re.finditer(
    r":\(\(e,t,r,a\)=>\{",
    apply_code
):

    raw = balanced(
        apply_code,
        m.start(),
        "{",
        150000
    )

    if not raw:
        continue

    code = compact(
        raw
    )

    score = sum(
        token in code
        for token in [
            "t.deltas??[]",
            "pF(",
            "subaccountsByIndex",
            "lastMessage:t",
            "lastMessageSlot:t.slot",
            "marginInputs:",
        ]
    )

    delta_candidates.append({
        "offset":
            m.start(),

        "score":
            score,

        "length":
            len(code),

        "code":
            code
    })

if not delta_candidates:
    raise RuntimeError(
        "delta no encontrado"
    )

delta_candidates.sort(
    key=lambda x: (
        x["score"],
        x["length"]
    ),
    reverse=True
)

delta_code = (
    delta_candidates[0]["code"]
)

# ============================================================
# 1. EXACT PLACEORDER OCCURRENCES
# ============================================================

PLACE_PATTERNS = [
    r"\bplaceOrder\b",
    r"\bsubmitOrder\b",
    r"\bcreateOrder\b",
    r"\bsendOrder\b",
]

place_occurrences = []

for pattern in PLACE_PATTERNS:

    for m in re.finditer(
        pattern,
        text,
        flags=re.I
    ):

        p = m.start()

        owner = enclosing_function(
            text,
            p
        )

        place_occurrences.append({
            "term":
                m.group(0),

            "offset":
                p,

            "owner":
                owner[
                    "owner"
                ]
                if owner
                else
                None,

            "ownerOffset":
                owner[
                    "offset"
                ]
                if owner
                else
                None,

            "ownerLength":
                owner.get(
                    "length"
                )
                if owner
                else
                None,

            "context":
                context(
                    text,
                    p,
                    7000,
                    10000
                ),

            "ownerCode":
                owner[
                    "code"
                ]
                if owner
                else
                None,
        })

# deduplicate
seen = set()
dedup = []

for item in place_occurrences:

    key = (
        item["offset"],
        item["term"]
    )

    if key not in seen:

        seen.add(key)
        dedup.append(item)

place_occurrences = dedup

# ============================================================
# 2. IDENTIFY REAL CALL-SITE CANDIDATES
# ============================================================

call_sites = []

for item in place_occurrences:

    c = item["context"]

    # calls commonly have "(" immediately after identifier
    call_like = bool(
        re.search(
            r"\b(?:placeOrder|submitOrder|createOrder|sendOrder)\s*\(",
            c,
            flags=re.I
        )
    )

    # declaration-like patterns
    declaration_like = bool(
        re.search(
            r"(?:function\s+"
            r"|[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*"
            r"|[A-Za-z_$][A-Za-z0-9_$]*\s*:\s*)"
            r"(?:placeOrder|submitOrder|createOrder|sendOrder)\b",
            c,
            flags=re.I
        )
    )

    item[
        "callLike"
    ] = call_like

    item[
        "declarationLike"
    ] = declaration_like

    if call_like and not declaration_like:
        call_sites.append(
            item
        )

# ============================================================
# 3. EXACT ORDER-REQUEST BUILDERS NEAR CALLS
# ============================================================

ORDER_FIELDS = [
    "symbol",
    "side",
    "price",
    "priceTicks",
    "priceUsd",
    "size",
    "sizeRemainingLots",
    "initialSizeLots",
    "reduceOnly",
    "orderType",
    "limit",
    "market",
    "leverage",
    "collateral",
    "margin",
    "maxLeverage",
]

builder_candidates = []

for item in call_sites:

    c = item[
        "context"
    ]

    present = [
        field
        for field in ORDER_FIELDS
        if re.search(
            rf"\b{re.escape(field)}\b",
            c,
            flags=re.I
        )
    ]

    assignments = []

    for field in ORDER_FIELDS:

        for m in re.finditer(
            rf"{re.escape(field)}\s*:",
            c,
            flags=re.I
        ):

            assignments.append({
                "field":
                    field,

                "offset":
                    m.start(),

                "context":
                    compact(
                        c[
                            max(
                                0,
                                m.start()-500
                            ):
                            min(
                                len(c),
                                m.end()+900
                            )
                        ]
                    )
            })

    builder_candidates.append({

        "action":
            item[
                "term"
            ],

        "offset":
            item[
                "offset"
            ],

        "owner":
            item[
                "owner"
            ],

        "fieldsPresent":
            present,

        "assignments":
            assignments,

        "context":
            c,
    })

# ============================================================
# 4. DATAFLOW TOKENS IN CALL-SITE WINDOWS
# ============================================================

STATE_TOKENS = [
    "marginInputs",
    "collateral",
    "freeCollateral",
    "availableMargin",
    "maintenanceMargin",
    "initialMargin",
    "marginRequirement",
    "withdrawableCollateral",
    "ordersBySymbol",
    "positionsBySymbol",
    "ordersBySequence",
    "subaccountsByIndex",
    "sequence",
    "slot",
    "version",
    "lastMessage",
    "lastMessageSlot",
]

state_links = []

for item in builder_candidates:

    c = item[
        "context"
    ]

    links = []

    for token in STATE_TOKENS:

        if re.search(
            rf"\b{re.escape(token)}\b",
            c,
            flags=re.I
        ):

            links.append(
                token
            )

    if links:

        state_links.append({

            "action":
                item[
                    "action"
                ],

            "offset":
                item[
                    "offset"
                ],

            "owner":
                item[
                    "owner"
                ],

            "stateTokens":
                links,

            "fieldsPresent":
                item[
                    "fieldsPresent"
                ],

            "assignments":
                item[
                    "assignments"
                ],

            "context":
                c,
        })

# ============================================================
# 5. FOCUS: sequence / collateral / order state
# ============================================================

critical_state_links = []

for item in state_links:

    tokens = set(
        item[
            "stateTokens"
        ]
    )

    critical = (
        tokens
        &
        {
            "sequence",
            "collateral",
            "marginInputs",
            "ordersBySymbol",
            "ordersBySequence",
            "positionsBySymbol",
            "subaccountsByIndex",
        }
    )

    if critical:

        critical_state_links.append({

            **item,

            "criticalTokens":
                sorted(
                    critical
                ),

            "hasSequence":
                "sequence"
                in tokens,

            "hasCollateral":
                "collateral"
                in tokens
                or
                "marginInputs"
                in tokens,

            "hasOrderState":
                (
                    "ordersBySymbol"
                    in tokens
                    or
                    "ordersBySequence"
                    in tokens
                ),

            "hasPositionState":
                "positionsBySymbol"
                in tokens,

        })

# ============================================================
# 6. LOOK FOR DIRECT ASSIGNMENTS FROM STATE INTO ORDER ARGS
# ============================================================

direct_assignments = []

for item in critical_state_links:

    c = item[
        "context"
    ]

    patterns = [

        (
            r"([A-Za-z_$][A-Za-z0-9_$]*)\s*:"
            r"\s*(?:[^,}\]]*\.)?"
            r"(?:collateral|marginInputs|sequence)"
        ),

        (
            r"([A-Za-z_$][A-Za-z0-9_$]*)\s*:"
            r"\s*(?:[^,}\]]*\.)?"
            r"(?:orders|positions|subaccountsByIndex)"
        ),

        (
            r"([A-Za-z_$][A-Za-z0-9_$]*)\s*:"
            r"\s*[^,}\]]*\bsequence\b"
        ),

        (
            r"([A-Za-z_$][A-Za-z0-9_$]*)\s*:"
            r"\s*[^,}\]]*\bmarginInputs\b"
        ),

    ]

    for pattern in patterns:

        for m in re.finditer(
            pattern,
            c,
            flags=re.I
        ):

            direct_assignments.append({

                "action":
                    item[
                        "action"
                    ],

                "offset":
                    item[
                        "offset"
                    ],

                "lhs":
                    m.group(1),

                "expression":
                    m.group(0),

                "context":
                    item[
                        "context"
                    ],
            })

# ============================================================
# 7. CLIENT-SIDE GUARD / VALIDATION NEAR PLACE ORDER
# ============================================================

VALIDATORS = [
    "validateOrder",
    "validateMargin",
    "checkMargin",
    "checkRisk",
    "riskCheck",
    "marginCheck",
    "canPlaceOrder",
    "maxOrder",
    "maxLeverage",
    "ensureMargin",
    "assertMargin",
]

validator_links = []

for item in call_sites:

    c = item[
        "context"
    ]

    found = []

    for validator in VALIDATORS:

        if re.search(
            rf"\b{re.escape(validator)}\b",
            c,
            flags=re.I
        ):
            found.append(
                validator
            )

    if found:

        validator_links.append({

            "action":
                item[
                    "term"
                ],

            "offset":
                item[
                    "offset"
                ],

            "owner":
                item[
                    "owner"
                ],

            "validators":
                found,

            "context":
                c,
        })

# ============================================================
# 8. AUTH / SIGN BOUNDARY NEAR PLACE ORDER
# ============================================================

AUTH = [
    "sign",
    "signAndSend",
    "sendTransaction",
    "transaction",
    "wallet",
    "sessionManager",
    "knownAuthToken",
]

auth_links = []

for item in call_sites:

    c = item[
        "context"
    ]

    found = []

    for token in AUTH:

        if re.search(
            rf"\b{re.escape(token)}\b",
            c,
            flags=re.I
        ):
            found.append(
                token
            )

    if found:

        auth_links.append({

            "action":
                item[
                    "term"
                ],

            "offset":
                item[
                    "offset"
                ],

            "owner":
                item[
                    "owner"
                ],

            "authTokens":
                found,

            "context":
                c,
        })

# ============================================================
# 9. SNAPSHOT / SEQUENCE GAP
# ============================================================

sequence_gap = occurrences(
    text,
    r"\bsequenceGap\b",
    limit=100
)

snapshot_refs = occurrences(
    text,
    r"getTraderStateSnapshot",
    limit=100
)

# ============================================================
# 10. STATIC DATAFLOW RESULT
# ============================================================

surface = {

    "process_identity":
        (
            "e.authority!==t"
            in process_code
            and
            "e.traderPdaIndex!==r"
            in process_code
        ),

    "delta_pipeline":
        (
            "t.deltas??[]"
            in delta_code
            and
            "pF("
            in delta_code
        ),

    "sequence_persisted":
        "sequence:t.sequence"
        in pf_code,

    "sequence_guard_process":
        bool(
            re.search(
                r"e\.sequence\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                process_code
            )
        ),

    "sequence_guard_delta":
        bool(
            re.search(
                r"(?:e|t)\.sequence\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                delta_code
            )
        ),

    "order_sequence_guard":
        bool(
            re.search(
                r"orderSequenceNumber\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                pf_code
            )
        ),

    "order_whole_replacement":
        "a[t.orderSequenceNumber]=pE(t)"
        in pf_code,

    "order_close_delete":
        "delete a[t.orderSequenceNumber]"
        in pf_code,

    "place_order_callsite_found":
        len(
            call_sites
        ) > 0,

    "place_order_state_link":
        any(
            x[
                "action"
            ].lower()
            ==
            "placeorder"
            for x in
            critical_state_links
        ),

    "place_order_auth_link":
        any(
            x[
                "action"
            ].lower()
            ==
            "placeorder"
            for x in
            auth_links
        ),

    "place_order_validator_link":
        any(
            x[
                "action"
            ].lower()
            ==
            "placeorder"
            for x in
            validator_links
        ),

    "direct_state_to_order_assignment":
        len(
            direct_assignments
        ) > 0,
}

# ============================================================
# 11. IMPORTANT SEPARATION:
#     exact evidence vs proximity
# ============================================================

proximity_only = {

    "stateActionContexts":
        len(
            state_links
        ),

    "criticalStateActionContexts":
        len(
            critical_state_links
        ),

    "authContexts":
        len(
            auth_links
        ),

    "validatorContexts":
        len(
            validator_links
        ),

    "directAssignments":
        len(
            direct_assignments
        ),

    "sequenceGapRefs":
        len(
            sequence_gap
        ),

    "snapshotRefs":
        len(
            snapshot_refs
        ),
}

# ============================================================
# 12. CLASSIFICATION
# ============================================================

if (
    surface[
        "place_order_callsite_found"
    ]
    and
    surface[
        "place_order_state_link"
    ]
    and
    surface[
        "place_order_auth_link"
    ]
    and
    surface[
        "direct_state_to_order_assignment"
    ]
):

    classification = (
        "STATIC_PLACEORDER_DATAFLOW_WITH_STATE_INPUT"
    )

elif (
    surface[
        "place_order_callsite_found"
    ]
    and
    surface[
        "place_order_state_link"
    ]
):

    classification = (
        "PLACEORDER_STATE_PROXIMITY_ONLY"
    )

else:

    classification = (
        "PLACEORDER_STATE_PATH_NOT_ESTABLISHED"
    )

# ============================================================
# 13. REPORT
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
            ),
    },

    "exact": {

        "processMessage":
            process_code,

        "applyMessage":
            apply_code,

        "delta":
            delta_code,

        "pF":
            pf_code,
    },

    "placeOrderOccurrences":
        place_occurrences,

    "callSites":
        call_sites,

    "builderCandidates":
        builder_candidates,

    "stateLinks":
        state_links,

    "criticalStateLinks":
        critical_state_links,

    "directAssignments":
        direct_assignments,

    "validatorLinks":
        validator_links,

    "authLinks":
        auth_links,

    "sequenceGap":
        sequence_gap,

    "snapshotRefs":
        snapshot_refs,

    "surface":
        surface,

    "proximityOnly":
        proximity_only,

    "finding": {

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
    },
}

path = (
    REPORTS /
    "PLACEORDER_EXACT_DATAFLOW_v3_4.json"
)

with open(
    path,
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
# CORPUS EXPORTS
# ============================================================

exports = {

    "PLACEORDER_CALLS":
        json.dumps(
            call_sites,
            indent=2,
            ensure_ascii=False
        ),

    "PLACEORDER_STATE_LINKS":
        json.dumps(
            critical_state_links,
            indent=2,
            ensure_ascii=False
        ),

    "DIRECT_ASSIGNMENTS":
        json.dumps(
            direct_assignments,
            indent=2,
            ensure_ascii=False
        ),

    "VALIDATORS":
        json.dumps(
            validator_links,
            indent=2,
            ensure_ascii=False
        ),

    "AUTH":
        json.dumps(
            auth_links,
            indent=2,
            ensure_ascii=False
        ),

    "SURFACE":
        json.dumps(
            surface,
            indent=2,
            ensure_ascii=False
        ),
}

for name, content in exports.items():

    (
        CORPUS /
        f"PLACEORDER_{name}_v3_4.txt"
    ).write_text(
        content,
        encoding="utf-8"
    )

# ============================================================
# PRINT
# ============================================================

print("=" * 115)
print("SANA FORENSICS — PLACEORDER EXACT DATAFLOW v3.4")
print("=" * 115)

print()
print("STATIC CORE")

for k,v in surface.items():

    print(
        f"{k:45s}:",
        v
    )

print()
print("PLACEORDER OCCURRENCES:",
      len(place_occurrences))

print(
    "CALL-SITE CANDIDATES:",
    len(call_sites)
)

print(
    "STATE-LINKED CALL SITES:",
    len(critical_state_links)
)

print(
    "DIRECT STATE->ORDER ASSIGNMENTS:",
    len(direct_assignments)
)

print(
    "VALIDATOR LINKS:",
    len(validator_links)
)

print(
    "AUTH LINKS:",
    len(auth_links)
)

print()
print("CALL-SITE DETAIL")

for item in call_sites[:40]:

    print()
    print(
        "ACTION:",
        item[
            "term"
        ]
    )

    print(
        "OWNER:",
        item[
            "owner"
        ]
    )

    print(
        "OFFSET:",
        item[
            "offset"
        ]
    )

    print(
        "FIELDS:",
        [
            x
            for x in ORDER_FIELDS
            if re.search(
                rf"\b{re.escape(x)}\b",
                item[
                    "context"
                ],
                flags=re.I
            )
        ]
    )

print()
print("STATE-LINKED PLACEORDER")

for item in critical_state_links:

    if (
        item[
            "action"
        ].lower()
        ==
        "placeorder"
    ):

        print()

        print(
            "OWNER:",
            item[
                "owner"
            ]
        )

        print(
            "STATE:",
            item[
                "criticalTokens"
            ]
        )

        print(
            "FIELDS:",
            item[
                "fieldsPresent"
            ]
        )

        print(
            "ASSIGNMENTS:",
            len(
                item[
                    "assignments"
                ]
            )
        )

print()
print("DIRECT ASSIGNMENTS")

for item in direct_assignments[:80]:

    if (
        item[
            "action"
        ].lower()
        ==
        "placeorder"
    ):

        print(
            item[
                "lhs"
            ],
            "<=",
            item[
                "expression"
            ]
        )

print()
print("VALIDATORS")

for item in validator_links:

    if (
        item[
            "action"
        ].lower()
        ==
        "placeorder"
    ):

        print(
            item[
                "validators"
            ]
        )

print()
print("AUTH")

for item in auth_links:

    if (
        item[
            "action"
        ].lower()
        ==
        "placeorder"
    ):

        print(
            item[
                "authTokens"
            ]
        )

print()
print("SEQUENCE GAP:",
      len(sequence_gap))

print(
    "SNAPSHOT:",
    len(snapshot_refs)
)

print()
print(
    "CLASSIFICATION:",
    classification
)

print()
print(
    "REPORT:",
    path
)

print(
    "CORPUS:",
    CORPUS
)

print("=" * 115)

