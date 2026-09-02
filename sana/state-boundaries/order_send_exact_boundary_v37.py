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

def compact(s):
    return re.sub(r"\s+", " ", s).strip()

def ctx(pos, before=3000, after=7000):
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

def all_matches(
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
                compact(
                    source[
                        max(
                            0,
                            m.start()-2500
                        ):
                        min(
                            len(source),
                            m.start()+6500
                        )
                    ]
                )
        })

        if len(out) >= limit:
            break

    return out

def exact_definition(
    pattern,
    limit=300000
):
    m = re.search(
        pattern,
        text
    )

    if not m:
        return None

    raw = balanced(
        text,
        m.start(),
        "{",
        limit
    )

    if not raw:
        return None

    return {
        "offset":
            m.start(),

        "length":
            len(raw),

        "code":
            compact(raw)
    }

def owner_before(pos):
    start = max(
        0,
        pos - 60000
    )

    region = text[
        start:
        pos
    ]

    patterns = [

        r"\bfunction\s+"
        r"([A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*\([^)]*\)\s*\{",

        r"\b"
        r"([A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*=\s*"
        r"(?:async\s*)?"
        r"(?:function\s*)?"
        r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*=>\s*\{",

        r"\b"
        r"([A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*:"
        r"\s*(?:async\s*)?"
        r"(?:function\s*)?"
        r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*=>\s*\{",

        r"\b"
        r"([A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*\([^)]*\)\s*\{",
    ]

    candidates = []

    for pattern in patterns:

        for m in re.finditer(
            pattern,
            region
        ):

            candidates.append({
                "name":
                    m.group(1),

                "offset":
                    start + m.start(),

                "declaration":
                    m.group(0)
            })

    if not candidates:
        return None

    candidates.sort(
        key=lambda x:
            x["offset"]
    )

    return candidates[-1]

def owner_info(pos):
    owner = owner_before(
        pos
    )

    if not owner:
        return None

    raw = balanced(
        text,
        owner["offset"],
        "{",
        180000
    )

    return {
        "name":
            owner["name"],

        "offset":
            owner["offset"],

        "declaration":
            owner["declaration"],

        "length":
            len(raw)
            if raw
            else
            None,

        "code":
            compact(raw)
            if raw
            else
            ctx(pos, 8000, 10000)
    }

# ============================================================
# 1. RECUPERAR COMPONENTES YA ESTABLECIDOS
# ============================================================

process = exact_definition(
    r"processMessage:\(e,\[t,r\]\)=>",
    10000
)

apply = exact_definition(
    r"applyMessage\(e,t\)\{",
    350000
)

pf = exact_definition(
    r"pF=\(e,t\)=>",
    150000
)

if not process:
    raise RuntimeError(
        "processMessage no encontrado"
    )

if not apply:
    raise RuntimeError(
        "applyMessage no encontrado"
    )

if not pf:
    raise RuntimeError(
        "pF no encontrado"
    )

process_code = process["code"]
apply_code = apply["code"]
pf_code = pf["code"]

# ============================================================
# 2. DELTA EXACTA
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
        160000
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

delta_code = delta_candidates[0][
    "code"
]

# ============================================================
# 3. NO BUSCAR MÁS placeOrder POR NOMBRE.
#    BUSCAR LA PRIMITIVA REAL DE ENVÍO.
# ============================================================

SEND_TERMS = [
    "sendTransaction",
    "signAndSend",
    "send",
    "submit",
    "request",
    "rpc",
    "fetch",
    "post",
    "mutate",
    "execute",
    "commit",
    "enqueue",
    "dispatch",
    "broadcast",
]

SEND_REFS = []

for term in SEND_TERMS:

    refs = all_matches(
        text,
        rf"\b{re.escape(term)}\b",
        flags=re.I,
        limit=1000
    )

    for item in refs:

        c = item[
            "context"
        ]

        trade_terms = [
            "order",
            "orders",
            "position",
            "perp",
            "perpetual",
            "market",
            "limit",
            "reduceOnly",
            "leverage",
            "price",
            "size",
            "side",
            "cancel",
            "modify",
        ]

        score = sum(
            re.search(
                rf"\b{re.escape(x)}\b",
                c,
                flags=re.I
            ) is not None
            for x in trade_terms
        )

        if score >= 2:

            owner = owner_info(
                item[
                    "offset"
                ]
            )

            SEND_REFS.append({

                "term":
                    term,

                "offset":
                    item[
                        "offset"
                    ],

                "tradeScore":
                    score,

                "owner":
                    owner[
                        "name"
                    ]
                    if owner
                    else
                    None,

                "ownerCode":
                    owner[
                        "code"
                    ]
                    if owner
                    else
                    None,

                "context":
                    c,
            })

# ============================================================
# 4. IDENTIFICAR OBJETOS DE ORDEN
# ============================================================

ORDER_FIELD_PATTERNS = {

    "symbol":
        r"\bsymbol\s*[:=]",

    "side":
        r"\bside\s*[:=]",

    "price":
        r"\bprice(?:Ticks|Usd)?\s*[:=]",

    "size":
        r"\bsize(?:RemainingLots|Lots|Usd)?\s*[:=]",

    "reduceOnly":
        r"\breduceOnly\s*[:=]",

    "orderType":
        r"\borderType\s*[:=]",

    "leverage":
        r"\bleverage\s*[:=]",

    "margin":
        r"\bmargin\s*[:=]",

    "collateral":
        r"\bcollateral\s*[:=]",

    "orderSequenceNumber":
        r"\borderSequenceNumber\s*[:=]",
}

order_object_regions = []

for item in SEND_REFS:

    owner_code = item[
        "ownerCode"
    ]

    if not owner_code:
        continue

    for m in re.finditer(
        r"\{",
        owner_code
    ):

        raw = balanced(
            owner_code,
            m.start(),
            "{",
            30000
        )

        if not raw:
            continue

        code = compact(
            raw
        )

        fields = [
            name
            for name, pattern
            in ORDER_FIELD_PATTERNS.items()
            if re.search(
                pattern,
                code,
                flags=re.I
            )
        ]

        if len(fields) >= 2:

            order_object_regions.append({

                "sender":
                    item[
                        "term"
                    ],

                "owner":
                    item[
                        "owner"
                    ],

                "fields":
                    fields,

                "offset":
                    item[
                        "offset"
                    ],

                "object":
                    code,
            })

# ============================================================
# 5. BUSCAR CONSTRUCTORES DE REQUEST RPC / API
# ============================================================

REQUEST_TERMS = [
    "method",
    "params",
    "body",
    "json",
    "payload",
    "action",
    "type",
    "operation",
    "request",
]

request_regions = []

for term in REQUEST_TERMS:

    for item in all_matches(
        text,
        rf"\b{re.escape(term)}\b",
        flags=re.I,
        limit=1000
    ):

        c = item[
            "context"
        ]

        trade_score = sum(
            x.lower()
            in c.lower()
            for x in [
                "order",
                "cancel",
                "modify",
                "position",
                "perp",
                "side",
                "price",
                "size",
                "reduceOnly",
                "leverage",
            ]
        )

        if trade_score >= 3:

            request_regions.append({

                "term":
                    term,

                "offset":
                    item[
                        "offset"
                    ],

                "tradeScore":
                    trade_score,

                "context":
                    c
            })

# ============================================================
# 6. ACTION STRINGS / ENUMS
# ============================================================

action_strings = []

for pattern in [

    r'"[^"]{0,100}(?:order|cancel|modify|perp|position)[^"]{0,100}"',

    r"'[^']{0,100}(?:order|cancel|modify|perp|position)[^']{0,100}'",

]:

    for m in re.finditer(
        pattern,
        text,
        flags=re.I
    ):

        action_strings.append({

            "offset":
                m.start(),

            "string":
                m.group(0),

            "context":
                ctx(
                    m.start(),
                    2500,
                    4500
                )
        })

# ============================================================
# 7. SEARCH STRUCTURES THAT CONTAIN ORDER FIELDS + SEND
# ============================================================

send_order_structures = []

for item in SEND_REFS:

    c = item[
        "context"
    ]

    fields = [
        name
        for name, pattern
        in ORDER_FIELD_PATTERNS.items()
        if re.search(
            pattern,
            c,
            flags=re.I
        )
    ]

    if len(fields) >= 3:

        send_order_structures.append({

            "sendTerm":
                item[
                    "term"
                ],

            "owner":
                item[
                    "owner"
                ],

            "fields":
                fields,

            "offset":
                item[
                    "offset"
                ],

            "context":
                c
        })

# ============================================================
# 8. STATE TERMS AROUND REAL SEND CANDIDATES
# ============================================================

STATE_TERMS = [
    "marginInputs",
    "collateral",
    "freeCollateral",
    "availableMargin",
    "maintenanceMargin",
    "initialMargin",
    "marginRequirement",
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

for item in send_order_structures:

    c = item[
        "context"
    ]

    item[
        "state"
    ] = [
        x
        for x in STATE_TERMS
        if re.search(
            rf"\b{re.escape(x)}\b",
            c,
            flags=re.I
        )
    ]

# ============================================================
# 9. AUTH BOUNDARY AROUND REAL SEND CANDIDATES
# ============================================================

AUTH_TERMS = [
    "sign",
    "signAndSend",
    "sendTransaction",
    "transaction",
    "wallet",
    "sessionManager",
    "knownAuthToken",
]

for item in send_order_structures:

    c = item[
        "context"
    ]

    item[
        "auth"
    ] = [
        x
        for x in AUTH_TERMS
        if re.search(
            rf"\b{re.escape(x)}\b",
            c,
            flags=re.I
        )
    ]

# ============================================================
# 10. EXACT STATE PIPELINE
# ============================================================

pipeline = {

    "identity_guard":
        (
            "e.authority!==t"
            in process_code
            and
            "e.traderPdaIndex!==r"
            in process_code
        ),

    "process_sequence_guard":
        bool(
            re.search(
                r"e\.sequence\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                process_code
            )
        ),

    "delta_sequence_guard":
        bool(
            re.search(
                r"(?:e|t)\.sequence\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                delta_code
            )
        ),

    "delta_loop":
        "t.deltas??[]"
        in delta_code,

    "delta_pF":
        "pF("
        in delta_code,

    "pF_sequence":
        "sequence:t.sequence"
        in pf_code,

    "pF_order_write":
        "a[t.orderSequenceNumber]=pE(t)"
        in pf_code,

    "pF_order_delete":
        "delete a[t.orderSequenceNumber]"
        in pf_code,

    "pF_order_sequence_guard":
        bool(
            re.search(
                r"orderSequenceNumber\s*"
                r"(?:!==|!=|===|==|<|>|<=|>=)",
                pf_code
            )
        ),
}

# ============================================================
# 11. FIND UNIQUE ACTIVE SEND OWNERS
# ============================================================

unique_send_owners = {}

for item in SEND_REFS:

    key = (
        item[
            "owner"
        ],
        item[
            "offset"
        ]
    )

    unique_send_owners[
        key
    ] = item

SEND_REFS_UNIQUE = list(
    unique_send_owners.values()
)

# ============================================================
# 12. REAL ACTION CANDIDATE SCORE
# ============================================================

for item in SEND_ORDER_STRUCTURES if False else []:
    pass

for item in send_order_structures:

    score = 0

    if item[
        "sendTerm"
    ].lower() in [
        "send",
        "submit",
        "execute",
        "broadcast",
        "sendtransaction",
        "signandsend",
    ]:
        score += 3

    score += min(
        len(
            item[
                "fields"
            ]
        ),
        8
    )

    score += 2 * (
        "sequence"
        in item[
            "state"
        ]
    )

    score += 2 * (
        len(
            item[
                "auth"
            ]
        )
        > 0
    )

    score += (
        2
        *
        (
            "orderType"
            in item[
                "fields"
            ]
            or
            "reduceOnly"
            in item[
                "fields"
            ]
        )
    )

    item[
        "candidateScore"
    ] = score

send_order_structures.sort(
    key=lambda x:
        x[
            "candidateScore"
        ],
    reverse=True
)

# ============================================================
# 13. EXACT REFERENCE TO placeOrder
# ============================================================

place_refs = all_matches(
    text,
    r"\bplaceOrder\b",
    flags=re.I,
    limit=100
)

place_ref_detail = []

for item in place_refs:

    p = item[
        "offset"
    ]

    before = text[
        max(
            0,
            p-500
        ):
        p
    ]

    after = text[
        p:
        min(
            len(text),
            p+700
        )
    ]

    place_ref_detail.append({

        "offset":
            p,

        "prefix":
            compact(before),

        "suffix":
            compact(after),

        "isCall":
            bool(
                re.match(
                    r"placeOrder\s*\(",
                    after,
                    flags=re.I
                )
            ),

        "context":
            ctx(
                p,
                5000,
                8000
            )
    })

# ============================================================
# 14. CLASSIFICATION
# ============================================================

real_send_found = (
    len(
        send_order_structures
    )
    >
    0
)

send_with_sequence = any(
    "sequence"
    in x[
        "state"
    ]
    for x in
    send_order_structures
)

send_with_auth = any(
    len(
        x[
            "auth"
        ]
    )
    >
    0
    for x in
    send_order_structures
)

send_with_order_fields = any(
    len(
        x[
            "fields"
        ]
    )
    >=
    4
    for x in
    send_order_structures
)

# ============================================================
# 15. IMPORTANT: PLACEORDER NAME IS NOT REQUIRED
# ============================================================

boundary = {

    "literal_placeOrder_exists":
        len(
            place_refs
        ) > 0,

    "literal_placeOrder_is_call":
        any(
            x[
                "isCall"
            ]
            for x in
            place_ref_detail
        ),

    "real_send_candidate_found":
        real_send_found,

    "send_candidate_with_order_fields":
        send_with_order_fields,

    "send_candidate_with_sequence_state":
        send_with_sequence,

    "send_candidate_with_auth":
        send_with_auth,

    "send_candidate_count":
        len(
            send_order_structures
        ),

    "order_object_candidate_count":
        len(
            order_object_regions
        ),

    "request_region_count":
        len(
            request_regions
        ),

    "action_string_count":
        len(
            action_strings
        ),
}

# ============================================================
# 16. STATIC RESULT
# ============================================================

static_surface = (

    pipeline[
        "delta_loop"
    ]

    and

    pipeline[
        "delta_pF"
    ]

    and

    pipeline[
        "pF_sequence"
    ]

    and

    not pipeline[
        "delta_sequence_guard"
    ]

    and

    not pipeline[
        "pF_order_sequence_guard"
    ]

    and

    boundary[
        "real_send_candidate_found"
    ]

    and

    boundary[
        "send_candidate_with_order_fields"
    ]
)

if (
    static_surface
    and
    boundary[
        "send_candidate_with_sequence_state"
    ]
    and
    boundary[
        "send_candidate_with_auth"
    ]
):

    classification = (
        "STATIC_STALE_STATE_TO_ORDER_SEND_BOUNDARY"
    )

elif static_surface:

    classification = (
        "STATIC_STALE_STATE_TO_ORDER_SEND_CANDIDATE"
    )

elif boundary[
    "real_send_candidate_found"
]:

    classification = (
        "ORDER_SEND_PATH_FOUND_STATE_LINK_UNRESOLVED"
    )

else:

    classification = (
        "ORDER_SEND_PATH_NOT_ESTABLISHED"
    )

# ============================================================
# 17. REPORT
# ============================================================

report = {

    "bundle":
        {
            "path":
                str(BUNDLE),

            "bytes":
                len(
                    text.encode(
                        "utf-8"
                    )
                ),
        },

    "pipeline":
        pipeline,

    "placeOrder":
        place_ref_detail,

    "sendRefs":
        SEND_REFS_UNIQUE,

    "orderObjectRegions":
        order_object_regions,

    "requestRegions":
        request_regions,

    "actionStrings":
        action_strings[:1000],

    "sendOrderStructures":
        send_order_structures[:300],

    "boundary":
        boundary,

    "finding":
        {
            "staticSurface":
                static_surface,

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
    "ORDER_SEND_EXACT_BOUNDARY_v3_7.json"
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
# 18. EXPORTS
# ============================================================

exports = {

    "SEND_REFS":
        json.dumps(
            SEND_REFS_UNIQUE,
            indent=2,
            ensure_ascii=False
        ),

    "ORDER_OBJECTS":
        json.dumps(
            order_object_regions,
            indent=2,
            ensure_ascii=False
        ),

    "SEND_ORDER_STRUCTURES":
        json.dumps(
            send_order_structures,
            indent=2,
            ensure_ascii=False
        ),

    "REQUEST_REGIONS":
        json.dumps(
            request_regions,
            indent=2,
            ensure_ascii=False
        ),

    "PLACEORDER_REFS":
        json.dumps(
            place_ref_detail,
            indent=2,
            ensure_ascii=False
        ),

    "BOUNDARY":
        json.dumps(
            boundary,
            indent=2,
            ensure_ascii=False
        ),
}

for name, content in exports.items():

    (
        CORPUS /
        f"ORDER_SEND_{name}_v3_7.txt"
    ).write_text(
        content,
        encoding="utf-8"
    )

# ============================================================
# 19. PRINT
# ============================================================

print("=" * 115)
print("SANA FORENSICS — ORDER SEND EXACT BOUNDARY v3.7")
print("=" * 115)

print()
print("PIPELINE")

for k,v in pipeline.items():

    print(
        f"{k:38s}:",
        v
    )

print()
print("LITERAL placeOrder")

print(
    "references:",
    len(place_refs)
)

for x in place_ref_detail:

    print()
    print(
        "OFFSET:",
        x[
            "offset"
        ]
    )

    print(
        "CALL:",
        x[
            "isCall"
        ]
    )

    print(
        "SUFFIX:",
        x[
            "suffix"
        ]
    )

print()
print("SEND CANDIDATES")

print(
    "count:",
    len(
        send_order_structures
    )
)

for item in send_order_structures[:40]:

    print()
    print(
        "TERM:",
        item[
            "sendTerm"
        ]
    )

    print(
        "OWNER:",
        item[
            "owner"
        ]
    )

    print(
        "SCORE:",
        item[
            "candidateScore"
        ]
    )

    print(
        "FIELDS:",
        item[
            "fields"
        ]
    )

    print(
        "STATE:",
        item[
            "state"
        ]
    )

    print(
        "AUTH:",
        item[
            "auth"
        ]
    )

print()
print("ORDER OBJECTS:",
      len(order_object_regions))

for item in order_object_regions[:30]:

    print()
    print(
        "OWNER:",
        item[
            "owner"
        ]
    )

    print(
        "FIELDS:",
        item[
            "fields"
        ]
    )

    print(
        "OBJECT:",
        item[
            "object"
        ]
    )

print()
print("REQUEST REGIONS:",
      len(request_regions))

print(
    "ACTION STRINGS:",
    len(action_strings)
)

print()
print("BOUNDARY")

for k,v in boundary.items():

    print(
        f"{k:42s}:",
        v
    )

print()
print(
    "STATIC SURFACE:",
    static_surface
)

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

