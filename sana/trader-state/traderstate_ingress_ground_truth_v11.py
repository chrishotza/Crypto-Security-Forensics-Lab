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

def norm(s):
    return re.sub(r"\s+", " ", s).strip()

def ctx(pos, before=3000, after=7000):
    return norm(
        text[
            max(0, pos-before):
            min(len(text), pos+after)
        ]
    )

def balanced(pos, opener="{", source=None, limit=300000):
    s = text if source is None else source
    p = s.find(opener, pos)

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
        len(s),
        pos + limit
    )

    i = p

    while i < end:

        ch = s[i]
        nx = s[i+1] if i + 1 < end else ""

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
                return s[
                    pos:i+1
                ]

        i += 1

    return None

# ============================================================
# 1. EXACT c1()
# ============================================================

c1_positions = [
    m.start()
    for m in re.finditer(
        r"c1\s*=\s*\(\)\s*=>\s*\(\{",
        text
    )
]

if not c1_positions:
    raise RuntimeError("c1() no encontrado")

c1_raw = balanced(
    c1_positions[0],
    "{",
    text,
    30000
)

c1_code = (
    norm(c1_raw)
    if c1_raw
    else ""
)

# ============================================================
# 2. EXACT u3()
# ============================================================

u3_positions = [
    m.start()
    for m in re.finditer(
        r"u3\s*=",
        text
    )
]

u3_code = ""

if u3_positions:
    raw = balanced(
        u3_positions[0],
        "{",
        text,
        50000
    )

    if raw:
        u3_code = norm(raw)

# ============================================================
# 3. EXACT dS()
# ============================================================

dS_positions = [
    m.start()
    for m in re.finditer(
        r"dS\s*=",
        text
    )
]

dS_candidates = []

for pos in dS_positions:
    raw = balanced(
        pos,
        "{",
        text,
        120000
    )

    if not raw:
        continue

    code = norm(raw)

    score = sum(
        token in code
        for token in [
            "subaccountIndex",
            "sequence",
            "orders",
            "positions",
            "collateral",
            "splines",
            "triggers",
        ]
    )

    dS_candidates.append({
        "offset": pos,
        "length": len(code),
        "score": score,
        "code": code,
    })

dS_candidates.sort(
    key=lambda x: (
        x["score"],
        x["length"]
    ),
    reverse=True
)

dS_code = (
    dS_candidates[0]["code"]
    if dS_candidates
    else ""
)

# ============================================================
# 4. EXACT df()
# ============================================================

df_positions = [
    m.start()
    for m in re.finditer(
        r"df\s*=",
        text
    )
]

df_candidates = []

for pos in df_positions:
    raw = balanced(
        pos,
        "{",
        text,
        120000
    )

    if not raw:
        continue

    code = norm(raw)

    score = sum(
        token in code
        for token in [
            "orderSequenceNumber",
            "change",
            "orders",
            "symbol",
        ]
    )

    df_candidates.append({
        "offset": pos,
        "length": len(code),
        "score": score,
        "code": code,
    })

df_candidates.sort(
    key=lambda x: (
        x["score"],
        x["length"]
    ),
    reverse=True
)

df_code = (
    df_candidates[0]["code"]
    if df_candidates
    else ""
)

# ============================================================
# 5. EXACT pE()
# ============================================================

pe_positions = [
    m.start()
    for m in re.finditer(
        r"pE\s*=",
        text
    )
]

pe_candidates = []

for pos in pe_positions:

    # pE is apparently an expression-return helper, so capture
    # the whole statement without inventing its body.
    end = text.find(
        ";",
        pos
    )

    if end < 0:
        end = min(
            len(text),
            pos + 5000
        )

    code = norm(
        text[
            pos:
            end+1
        ]
    )

    score = sum(
        token in code
        for token in [
            "orderSequenceNumber",
            "symbol",
            "change",
            "price",
            "size",
            "side",
        ]
    )

    pe_candidates.append({
        "offset": pos,
        "length": len(code),
        "score": score,
        "code": code,
    })

pe_candidates.sort(
    key=lambda x: (
        x["score"],
        x["length"]
    ),
    reverse=True
)

pe_code = (
    pe_candidates[0]["code"]
    if pe_candidates
    else ""
)

# ============================================================
# 6. EXACT pF()
# ============================================================

pf_positions = [
    m.start()
    for m in re.finditer(
        r"pF\s*=\s*\(",
        text
    )
]

if not pf_positions:
    raise RuntimeError("pF no encontrado")

pf_raw = balanced(
    pf_positions[0],
    "{",
    text,
    120000
)

if not pf_raw:
    raise RuntimeError("pF no extraído")

pf_code = norm(pf_raw)

# ============================================================
# 7. EXACT traderState CHANNEL OBJECT
# ============================================================

trader_channel_positions = [
    m.start()
    for m in re.finditer(
        r'channel\s*:\s*"traderState"',
        text
    )
]

trader_channels = []

for pos in trader_channel_positions:

    raw = balanced(
        max(0, pos - 250),
        "{",
        text,
        50000
    )

    trader_channels.append({
        "offset": pos,
        "context": ctx(
            pos,
            6000,
            16000
        ),
        "balancedCandidate":
            norm(raw)
            if raw
            else None
    })

# ============================================================
# 8. FIND EXACT SUBSCRIPTION HANDLER AROUND c1()
# ============================================================

c1_nearby = []

if c1_code:

    for token in [
        "processMessage",
        "handle",
        "validate",
        "getKey",
        "channel",
    ]:

        for m in re.finditer(
            re.escape(token),
            c1_code
        ):

            c1_nearby.append({
                "token": token,
                "offset": m.start(),
                "context":
                    c1_code[
                        max(0, m.start()-1800):
                        min(len(c1_code), m.end()+3000)
                    ]
            })

# ============================================================
# 9. FIND ALL REFERENCES TO c1()
# ============================================================

c1_refs = []

for m in re.finditer(
    r"\bc1\s*\(",
    text
):

    c1_refs.append({
        "offset": m.start(),
        "context": ctx(
            m.start(),
            3000,
            9000
        )
    })

# ============================================================
# 10. FIND TRADERSTATE REGISTRATION REFERENCES
# ============================================================

trader_registration = []

for pos in trader_channel_positions:

    trader_registration.append({
        "offset": pos,
        "context": ctx(
            pos,
            10000,
            22000
        )
    })

# ============================================================
# 11. FIND onMsg IMPLEMENTATION
# ============================================================

onmsg_positions = [
    m.start()
    for m in re.finditer(
        r"\bonMsg\s*:",
        text
    )
]

onmsg_objects = []

for pos in onmsg_positions:

    c = ctx(
        pos,
        2500,
        8000
    )

    # Keep all; do not classify without evidence.
    onmsg_objects.append({
        "offset": pos,
        "context": c
    })

# ============================================================
# 12. FIND ASYNC QUEUE DEFINITIONS
# ============================================================

queue_positions = [
    m.start()
    for m in re.finditer(
        r"AsyncQueue",
        text
    )
]

queue_objects = []

for pos in queue_positions:

    queue_objects.append({
        "offset": pos,
        "context": ctx(
            pos,
            5000,
            10000
        )
    })

# ============================================================
# 13. FIND sequenceGap DEFINITIONS + OWNERSHIP
# ============================================================

gap_positions = [
    m.start()
    for m in re.finditer(
        r"sequenceGap",
        text
    )
]

gap_objects = []

for pos in gap_positions:

    c = ctx(
        pos,
        6000,
        10000
    )

    gap_objects.append({
        "offset": pos,
        "context": c,
        "mentions_traderState":
            "traderState"
            in c,
        "mentions_cacheStore":
            "cacheStore"
            in c,
        "mentions_applyDelta":
            "applyDelta"
            in c,
        "mentions_exchange_api":
            "exchange.api"
            in c,
    })

# ============================================================
# 14. FIND fq
# ============================================================

fq_positions = [
    m.start()
    for m in re.finditer(
        r"\bfq\b",
        text
    )
]

fq_objects = []

for pos in fq_positions[:100]:

    fq_objects.append({
        "offset": pos,
        "context": ctx(
            pos,
            2500,
            5000
        )
    })

# ============================================================
# 15. FIND refresh() ASSOCIATED WITH TRADERSTATE
# ============================================================

refresh_positions = [
    m.start()
    for m in re.finditer(
        r"\.refresh\s*\(",
        text
    )
]

refresh_objects = []

for pos in refresh_positions:

    c = ctx(
        pos,
        3500,
        7000
    )

    if (
        "traderState"
        in c
        or
        "deltas"
        in c
        or
        "subscription"
        in c
        or
        "sequence"
        in c
    ):

        refresh_objects.append({
            "offset": pos,
            "context": c
        })

# ============================================================
# 16. FIND SNAPSHOT REFETCH ASSOCIATED WITH TRADERSTATE
# ============================================================

snapshot_positions = [
    m.start()
    for m in re.finditer(
        r"getTraderStateSnapshot",
        text
    )
]

snapshot_objects = []

for pos in snapshot_positions:

    c = ctx(
        pos,
        5000,
        10000
    )

    snapshot_objects.append({
        "offset": pos,
        "context": c
    })

# ============================================================
# 17. EXACT ORDER REDUCER SEMANTICS
# ============================================================

order_semantics = {

    "current_map":
        "t?.ordersBySequence??{}"
        in pf_code,

    "delete":
        "delete a[t.orderSequenceNumber]"
        in pf_code,

    "write":
        "a[t.orderSequenceNumber]=pE(t)"
        in pf_code,

    "closed":
        '"closed"===t.change'
        in pf_code,

    "pE":
        "pE(t)"
        in pf_code,

    "order_sequence_guard":
        bool(
            re.search(
                r"orderSequenceNumber\s*"
                r"(?:!==|!=|===|==|<|>)",
                pf_code
            )
        ),
}

# ============================================================
# 18. EXACT TRADER MESSAGE SHAPE
# ============================================================

trader_message = {

    "authority":
        "authority"
        in process_code
        if process_code
        else False,

    "traderPdaIndex":
        "traderPdaIndex"
        in process_code
        if process_code
        else False,

    "slot":
        "slot"
        in process_code
        if process_code
        else False,

    "version":
        "version"
        in process_code
        if process_code
        else False,

    "sequence":
        "sequence"
        in process_code
        if process_code
        else False,

    "deltas":
        "deltas"
        in process_code
        if process_code
        else False,
}

# ============================================================
# 19. IMPORTANT:
# PROCESSMESSAGE EXACT IDENTITY ONLY
# ============================================================

identity_guard = {

    "authority":
        "e.authority!==t"
        in process_code,

    "traderPdaIndex":
        "e.traderPdaIndex!==r"
        in process_code,

    "slot":
        bool(
            re.search(
                r"e\.slot\s*(?:!==|!=|===|==|<|>)",
                process_code
            )
        ),

    "version":
        bool(
            re.search(
                r"e\.version\s*(?:!==|!=|===|==|<|>)",
                process_code
            )
        ),

    "sequence":
        bool(
            re.search(
                r"e\.sequence\s*(?:!==|!=|===|==|<|>)",
                process_code
            )
        ),
}

# ============================================================
# 20. CRITICAL QUESTION:
# WHERE IS sequenceGap ACTUALLY USED?
# ============================================================

sequence_gap_usage = []

for pos in gap_positions:

    # inspect a tighter region and find the enclosing function-like
    # context by nearest braces heuristically.
    c = ctx(
        pos,
        8000,
        12000
    )

    usage = {
        "offset":
            pos,

        "mentions_traderState":
            "traderState"
            in c,

        "mentions_exchangeApi":
            "exchange.api"
            in c,

        "mentions_cacheStore":
            "cacheStore"
            in c,

        "mentions_refresh":
            ".refresh("
            in c,

        "mentions_applyDelta":
            ".applyDelta("
            in c,

        "mentions_applyMessage":
            "applyMessage"
            in c,

        "mentions_pF":
            "pF("
            in c,

        "context":
            c,
    }

    sequence_gap_usage.append(
        usage
    )

# ============================================================
# 21. CLASSIFICATION — EVIDENCE ONLY
# ============================================================

classification = {
    "trader_process_identity":
        (
            identity_guard["authority"]
            and
            identity_guard["traderPdaIndex"]
        ),

    "trader_process_continuity":
        (
            identity_guard["slot"]
            or
            identity_guard["version"]
            or
            identity_guard["sequence"]
        ),

    "trader_apply_has_direct_continuity":
        (
            bool(
                re.search(
                    r"(?:e|t)\.sequence\s*"
                    r"(?:!==|!=|===|==|<|>)",
                    apply_code
                )
            )
            or
            bool(
                re.search(
                    r"(?:e|t)\.slot\s*"
                    r"(?:!==|!=|===|==|<|>)",
                    apply_code
                )
            )
            or
            bool(
                re.search(
                    r"(?:e|t)\.version\s*"
                    r"(?:!==|!=|===|==|<|>)",
                    apply_code
                )
            )
        ),

    "order_sequence_guard":
        order_semantics[
            "order_sequence_guard"
        ],

    "sequenceGap_has_traderState_context":
        any(
            x["mentions_traderState"]
            and
            not x["mentions_exchangeApi"]
            for x in sequence_gap_usage
        ),

    "sequenceGap_has_exchange_context":
        any(
            x["mentions_exchangeApi"]
            or
            x["mentions_cacheStore"]
            for x in sequence_gap_usage
        ),

    "snapshot_api_exists":
        bool(
            snapshot_objects
        ),

    "refresh_paths_exist":
        bool(
            refresh_objects
        ),

    "queue_exists":
        bool(
            queue_objects
        ),
}

# ============================================================
# 22. REPORT
# ============================================================

report = {

    "bundle": {
        "path":
            str(BUNDLE),
        "bytes":
            len(
                text.encode("utf-8")
            ),
    },

    "c1": {
        "positions":
            c1_positions,
        "code":
            c1_code,
        "nearby":
            c1_nearby,
        "references":
            c1_refs,
    },

    "u3":
        u3_code,

    "dS": {
        "candidates":
            dS_candidates,
        "selected":
            dS_code,
    },

    "df": {
        "candidates":
            df_candidates,
        "selected":
            df_code,
    },

    "pE": {
        "candidates":
            pe_candidates,
        "selected":
            pe_code,
    },

    "pF":
        pf_code,

    "traderState":
        trader_channels,

    "processMessage": {
        "code":
            process_code,
        "identityGuard":
            identity_guard,
        "messageShape":
            trader_message,
    },

    "applyMessage": {
        "code":
            apply_code,
        "deltaInner":
            delta_inner["code"]
            if delta_inner
            else None,
        "deltaLoop":
            delta_loop,
        "pFCalls":
            pf_calls,
    },

    "orders": {
        "reducer":
            order_reducer
            if 'order_reducer' in globals()
            else "",
        "semantics":
            order_semantics,
    },

    "queue":
        queue_objects,

    "sequenceGap":
        sequence_gap_usage,

    "fq":
        fq_objects,

    "refresh":
        refresh_objects,

    "snapshot":
        snapshot_objects,

    "classification":
        classification,
}

path = (
    REPORTS /
    "TRADERSTATE_INGRESS_GROUND_TRUTH_v1_1.json"
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
# EXPORTAR SOLO EVIDENCIA CRITICA
# ============================================================

exports = {
    "c1":
        c1_code,

    "u3":
        u3_code,

    "dS":
        dS_code,

    "df":
        df_code,

    "pE":
        pe_code,

    "pF":
        pf_code,

    "processMessage":
        process_code,

    "applyMessage":
        apply_code,

    "deltaInner":
        delta_inner["code"]
        if delta_inner
        else "",

    "deltaLoop":
        delta_loop
        if delta_loop
        else "",

    "orderReducer":
        order_reducer
        if 'order_reducer' in globals()
        else "",
}

for name, code in exports.items():

    if not code:
        continue

    (
        CORPUS /
        f"GROUND_TRUTH_{name}_v1_1.txt"
    ).write_text(
        code,
        encoding="utf-8"
    )

# ============================================================
# PRINT
# ============================================================

print("=" * 115)
print("SANA FORENSICS — TRADERSTATE INGRESS GROUND TRUTH v1.1")
print("=" * 115)

print()
print("c1")
print(c1_code)

print()
print("u3")
print(u3_code)

print()
print("dS len:", len(dS_code))
print(dS_code)

print()
print("df len:", len(df_code))
print(df_code)

print()
print("pE")
print(pe_code)

print()
print("PROCESSMESSAGE")
print(process_code)

print()
print("IDENTITY")

for k,v in identity_guard.items():
    print(
        f"{k:20s}:",
        v
    )

print()
print("APPLYMESSAGE")

print(
    "exact:",
    bool(apply_code)
)

print(
    "delta inner:",
    bool(delta_inner)
)

print(
    "delta loop:",
    bool(delta_loop)
)

print(
    "pF calls:",
    len(pf_calls)
)

print()
print("ORDER")

for k,v in order_semantics.items():
    print(
        f"{k:28s}:",
        v
    )

print()
print("SEQUENCE GAP")

for x in sequence_gap_usage:

    print()
    print(
        "OFFSET:",
        x["offset"]
    )

    print(
        "TRADERSTATE:",
        x["mentions_traderState"]
    )

    print(
        "EXCHANGE API:",
        x["mentions_exchangeApi"]
    )

    print(
        "CACHE STORE:",
        x["mentions_cacheStore"]
    )

    print(
        "APPLY DELTA:",
        x["mentions_applyDelta"]
    )

    print(
        "REFRESH:",
        x["mentions_refresh"]
    )

print()
print("CLASSIFICATION")

for k,v in classification.items():
    print(
        f"{k:45s}:",
        v
    )

print()
print("REPORT:")
print(path)

print()
print("CORPUS:")
print(CORPUS)

print("=" * 115)

