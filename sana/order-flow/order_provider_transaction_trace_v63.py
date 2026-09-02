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

ORDER_METHODS = [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
]

BUILDER_METHODS = [
    "buildLimitOrderPacket",
    "buildMarketOrderPacket",
    "buildPlaceLimitOrder",
    "buildPlaceMarketOrder",
]

def compact(s):
    return re.sub(r"\s+", " ", s).strip()

def context(pos, before=5000, after=8000):
    return compact(
        TEXT[
            max(0, pos-before):
            min(len(TEXT), pos+after)
        ]
    )

def balanced(source, start, opener="{", limit=250000):
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

def find_calls(source, name):
    rows = []

    for m in re.finditer(
        rf"\b{re.escape(name)}\s*\(",
        source
    ):
        raw = balanced(
            source,
            m.start(),
            "(",
            80000
        )

        rows.append({
            "offset": m.start(),
            "arguments": compact(raw[1:-1]) if raw else None,
            "text": compact(
                source[
                    m.start():
                    min(
                        len(source),
                        m.start() + (len(raw) if raw else 1500)
                    )
                ]
            )
        })

    return rows

def definitions(name, limit=100):
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
                180000
            )

            if not raw:
                continue

            rows.append({
                "offset": p,
                "length": len(raw),
                "declaration": m.group(0),
                "code": compact(raw)
            })

            if len(rows) >= limit:
                return rows

    return rows

def tokens(code, names):
    return [
        name
        for name in names
        if re.search(
            rf"\b{re.escape(name)}\b",
            code,
            flags=re.I
        )
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

# ============================================================
# R EXACTO
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

r_calls = {}

for name in ORDER_METHODS + BUILDER_METHODS:
    r_calls[name] = find_calls(
        R_CODE,
        name
    )

# ============================================================
# CHAINS EXACTAS
# ============================================================

api_chains = []

for m in re.finditer(
    r"\b([A-Za-z_$][A-Za-z0-9_$]*)\.api\.orders\(\)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
    R_CODE
):
    raw = balanced(
        R_CODE,
        m.start(),
        "(",
        80000
    )

    api_chains.append({
        "root": m.group(1),
        "method": m.group(2),
        "offsetInR": m.start(),
        "absoluteOffset": R_OFFSET + m.start(),
        "arguments": compact(raw[1:-1]) if raw else None
    })

# ============================================================
# EXACTAS REFERENCIAS GLOBALES
# ============================================================

global_occurrences = {}

for name in ORDER_METHODS + BUILDER_METHODS:

    rows = []

    for m in re.finditer(
        rf"\b{re.escape(name)}\b",
        TEXT
    ):
        p = m.start()

        before = TEXT[
            max(0, p-900):
            p
        ]

        after = TEXT[
            p:
            min(len(TEXT), p+1400)
        ]

        classes = []

        if re.match(
            rf"{re.escape(name)}\s*\(",
            after
        ):
            classes.append("CALL")

        if re.match(
            rf"{re.escape(name)}\s*:",
            after
        ):
            classes.append("PROPERTY")

        if not classes:
            classes.append("REFERENCE")

        rows.append({
            "offset": p,
            "classes": classes,
            "before": compact(before),
            "after": compact(after),
            "context": context(p)
        })

    global_occurrences[name] = rows

# ============================================================
# DEFINICIONES DE BUILDERS
# ============================================================

builder_definitions = {}

for name in BUILDER_METHODS:

    rows = definitions(
        name
    )

    builder_definitions[name] = []

    for d in rows:

        code = d["code"]

        builder_definitions[name].append({
            "offset": d["offset"],
            "length": d["length"],
            "declaration": d["declaration"],
            "order": tokens(
                code,
                ORDER_FIELDS
            ),
            "state": tokens(
                code,
                STATE_FIELDS
            ),
            "auth": tokens(
                code,
                AUTH_FIELDS
            ),
            "network": tokens(
                code,
                NETWORK_FIELDS
            ),
            "calls": sorted(
                set(
                    m.group(1)
                    for m in re.finditer(
                        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
                        code
                    )
                )
            ),
            "code": code
        })

# ============================================================
# DEFINICIONES AUXILIARES REALES OBSERVADAS ANTES
# ============================================================

KNOWN_HELPERS = [
    "mp",
    "mf",
    "mt",
    "pY",
    "p7",
    "i1",
    "S",
    "M",
    "B",
    "O",
    "w",
    "v",
    "A",
    "D",
]

helper_definitions = {}

for name in KNOWN_HELPERS:

    helper_definitions[name] = []

    for d in definitions(name, 50):

        code = d["code"]

        helper_definitions[name].append({
            "offset": d["offset"],
            "length": d["length"],
            "declaration": d["declaration"],
            "order": tokens(code, ORDER_FIELDS),
            "state": tokens(code, STATE_FIELDS),
            "auth": tokens(code, AUTH_FIELDS),
            "network": tokens(code, NETWORK_FIELDS),
            "calls": sorted(
                set(
                    m.group(1)
                    for m in re.finditer(
                        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
                        code
                    )
                )
            ),
            "code": code
        })

# ============================================================
# BUSCAR EL PROVIDER/API OBJECT "orders"
# ============================================================

orders_object_candidates = []

for m in re.finditer(
    r"\borders\b",
    TEXT
):

    p = m.start()

    local = TEXT[
        max(0,p-3000):
        min(len(TEXT),p+7000)
    ]

    if (
        "placeIsolatedLimitOrder"
        not in local
        and
        "placeIsolatedMarketOrder"
        not in local
    ):
        continue

    orders_object_candidates.append({
        "offset": p,
        "context": compact(local),
        "hasLimit": "placeIsolatedLimitOrder" in local,
        "hasMarket": "placeIsolatedMarketOrder" in local,
    })

# ============================================================
# EXACT CONTEXTOS DE LOS CALLS DE R
# ============================================================

r_order_call_contexts = []

for row in api_chains:

    if row["method"] not in ORDER_METHODS:
        continue

    p = row["absoluteOffset"]

    c = context(
        p,
        12000,
        16000
    )

    r_order_call_contexts.append({

        "method":
            row["method"],

        "offset":
            p,

        "arguments":
            row["arguments"],

        "context":
            c,

        "orderFields":
            tokens(c, ORDER_FIELDS),

        "stateFields":
            tokens(c, STATE_FIELDS),

        "authFields":
            tokens(c, AUTH_FIELDS),

        "networkFields":
            tokens(c, NETWORK_FIELDS),
    })

# ============================================================
# TRANSACTION SITES
# ============================================================

TX_PATTERNS = [
    r"\bTransaction\s*\(",
    r"\bTransactionInstruction\s*\(",
    r"\bsendTransaction\s*\(",
    r"\bsignTransaction\s*\(",
    r"\bsignAndSend\s*\(",
    r"\bgetLatestBlockhash\s*\(",
    r"\bconfirmTransaction\s*\(",
]

transaction_sites = []

for pattern in TX_PATTERNS:

    for m in re.finditer(
        pattern,
        TEXT,
        flags=re.I
    ):

        p = m.start()

        c = context(
            p,
            7000,
            10000
        )

        order_hits = tokens(
            c,
            ORDER_FIELDS
            +
            [
                "placeIsolatedLimitOrder",
                "placeIsolatedMarketOrder",
                "buildPlaceLimitOrder",
                "buildPlaceMarketOrder",
            ]
        )

        state_hits = tokens(
            c,
            STATE_FIELDS
        )

        auth_hits = tokens(
            c,
            AUTH_FIELDS
        )

        if (
            len(order_hits) >= 1
            and
            (
                len(auth_hits) >= 1
                or
                len(state_hits) >= 1
            )
        ):

            transaction_sites.append({

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

# dedupe transaction sites
_tx_unique = {}

for row in transaction_sites:
    _tx_unique[
        (
            row["offset"],
            row["term"]
        )
    ] = row

transaction_sites = list(
    _tx_unique.values()
)

transaction_sites.sort(
    key=lambda x:
        x["offset"]
)

# ============================================================
# STATIC GROUND TRUTH
# ============================================================

static = {

    "placeOrderR":
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
        ),
}

# ============================================================
# MILESTONE
# ============================================================

limit_call_count = sum(
    1
    for x in api_chains
    if x["method"] == "placeIsolatedLimitOrder"
)

market_call_count = sum(
    1
    for x in api_chains
    if x["method"] == "placeIsolatedMarketOrder"
)

builder_call_count = sum(
    1
    for x in api_chains
    if x["method"] in BUILDER_METHODS
)

transaction_order_count = sum(
    1
    for x in transaction_sites
    if len(x["order"]) >= 1
)

transaction_auth_count = sum(
    1
    for x in transaction_sites
    if len(x["auth"]) >= 1
)

state_action_context = any(
    x["stateFields"]
    and
    x["authFields"]
    for x in r_order_call_contexts
)

if (
    limit_call_count > 0
    and
    market_call_count > 0
    and
    builder_call_count > 0
    and
    transaction_order_count > 0
):

    classification = (
        "STATIC_ORDER_API_BUILDER_TRANSACTION_SURFACE"
    )

elif (
    limit_call_count > 0
    and
    market_call_count > 0
    and
    state_action_context
):

    classification = (
        "STATIC_ORDER_API_STATE_AUTH_SURFACE"
    )

elif (
    limit_call_count > 0
    and
    market_call_count > 0
):

    classification = (
        "STATIC_ORDER_API_SURFACE"
    )

else:

    classification = (
        "ORDER_API_SURFACE_INCOMPLETE"
    )

# ============================================================
# REPORT
# ============================================================

report = {

    "bundle": {
        "path": str(BUNDLE),
        "bytes": len(
            TEXT.encode("utf-8")
        )
    },

    "R": {
        "offset": R_OFFSET,
        "length": len(r_raw),
        "calls": r_calls,
    },

    "apiChains":
        api_chains,

    "globalOccurrences":
        global_occurrences,

    "builderDefinitions":
        builder_definitions,

    "helperDefinitions":
        helper_definitions,

    "ordersObjectCandidates":
        orders_object_candidates,

    "rOrderCallContexts":
        r_order_call_contexts,

    "transactionSites":
        transaction_sites,

    "static":
        static,

    "milestone": {

        "limitCallCount":
            limit_call_count,

        "marketCallCount":
            market_call_count,

        "builderCallCount":
            builder_call_count,

        "transactionOrderCount":
            transaction_order_count,

        "transactionAuthCount":
            transaction_auth_count,

        "stateActionContext":
            state_action_context,

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
            "TRACE_ORDERS_PROVIDER_IMPLEMENTATION"
    }
}

report_path = (
    REPORTS /
    "ORDER_PROVIDER_TRANSACTION_TRACE_v6_3.json"
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
    "R.json":
        report["R"],

    "API_CHAINS.json":
        api_chains,

    "GLOBAL_OCCURRENCES.json":
        global_occurrences,

    "BUILDER_DEFINITIONS.json":
        builder_definitions,

    "HELPER_DEFINITIONS.json":
        helper_definitions,

    "ORDERS_OBJECT_CANDIDATES.json":
        orders_object_candidates,

    "R_ORDER_CONTEXTS.json":
        r_order_call_contexts,

    "TRANSACTION_SITES.json":
        transaction_sites,

    "STATIC.json":
        static,

    "MILESTONE.json":
        report["milestone"],
}

for name, obj in exports.items():

    (
        CORPUS /
        f"ORDER_V63_{name}"
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
print("SANA FORENSICS — ORDER PROVIDER TRANSACTION TRACE v6.3")
print("=" * 115)

print()
print("R")
print("OFFSET:", R_OFFSET)
print("LEN:", len(r_raw))

print()
print("API ORDER CHAINS:",
      len(api_chains))

for row in api_chains:

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
print("ORDERS PROVIDER CANDIDATES:",
      len(orders_object_candidates))

for row in orders_object_candidates[:60]:

    print()
    print(
        "OFFSET:",
        row["offset"]
    )

    print(
        "LIMIT:",
        row["hasLimit"],
        "MARKET:",
        row["hasMarket"]
    )

print()
print("R ORDER CONTEXTS:",
      len(r_order_call_contexts))

for row in r_order_call_contexts:

    print()
    print(
        row["method"],
        "@",
        row["offset"]
    )

    print(
        "ORDER:",
        row["orderFields"]
    )

    print(
        "STATE:",
        row["stateFields"]
    )

    print(
        "AUTH:",
        row["authFields"]
    )

    print(
        "NETWORK:",
        row["networkFields"]
    )

print()
print("BUILDERS")

for name, rows in builder_definitions.items():

    print()
    print(
        name,
        "defs=",
        len(rows)
    )

    for row in rows[:10]:

        print(
            "  OFFSET:",
            row["offset"],
            "LEN:",
            row["length"]
        )

        print(
            "  ORDER:",
            row["order"]
        )

        print(
            "  STATE:",
            row["state"]
        )

        print(
            "  AUTH:",
            row["auth"]
        )

        print(
            "  NETWORK:",
            row["network"]
        )

print()
print("HELPERS")

for name, rows in helper_definitions.items():

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
            row["offset"],
            "LEN:",
            row["length"]
        )

        print(
            "  ORDER:",
            row["order"]
        )

        print(
            "  STATE:",
            row["state"]
        )

        print(
            "  AUTH:",
            row["auth"]
        )

        print(
            "  NETWORK:",
            row["network"]
        )

print()
print(
    "TRANSACTION SITES:",
    len(transaction_sites)
)

for row in transaction_sites[:100]:

    print()
    print(
        row["term"],
        "@",
        row["offset"]
    )

    print(
        "ORDER:",
        row["order"]
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
print("STATIC")

for k, v in static.items():

    print(
        f"{k:36s}:",
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

