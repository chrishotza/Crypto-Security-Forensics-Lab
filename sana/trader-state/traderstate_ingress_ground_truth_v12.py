import json
import re
from pathlib import Path

ROOT = Path(r"SANA_FORENSICS_ROOT")
BUNDLE = ROOT / "data" / "raw" / "sana_bundle.js"
REPORTS = ROOT / "data" / "reports"
CORPUS = ROOT / "data" / "corpus"

if not BUNDLE.exists():
    raise SystemExit("Bundle no encontrado")

text = BUNDLE.read_text(
    encoding="utf-8",
    errors="replace"
)

def norm(s):
    return re.sub(r"\s+", " ", s).strip()

def ctx(pos, before=2500, after=8000):
    return norm(
        text[
            max(0, pos-before):
            min(len(text), pos+after)
        ]
    )

def exact_process_message():
    patterns = [
        r"processMessage:\(e,\[t,r\]\)=>",
        r"processMessage\s*:\s*\(e,\s*\[t,\s*r\]\)\s*=>",
    ]

    for pattern in patterns:
        m = re.search(
            pattern,
            text
        )

        if not m:
            continue

        start = m.start()

        tail = text[
            start:
            min(
                len(text),
                start + 5000
            )
        ]

        # El processMessage observado es una expresión ternaria
        # que termina antes del siguiente miembro del objeto.
        end_candidates = [
            tail.find(
                "},"
            ),
            tail.find(
                "} }"
            ),
            tail.find(
                "}"
            ),
        ]

        valid = [
            x for x in end_candidates
            if x >= 0
        ]

        if valid:
            end = start + min(valid) + 1
        else:
            end = min(
                len(text),
                start + 4500
            )

        return norm(
            text[
                start:end
            ]
        )

    return ""

process_code = exact_process_message()

# ============================================================
# c1()
# ============================================================

c1_match = re.search(
    r"c1\s*=\s*\(\)\s*=>\s*\(\{",
    text
)

c1_code = ""

if c1_match:

    start = c1_match.start()
    pos = text.find(
        "{",
        start
    )

    depth = 0
    quote = None
    escaped = False

    i = pos

    while i < len(text):

        ch = text[i]

        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch in ("'", '"', ""):
            quote = ch
            i += 1
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                c1_code = norm(
                    text[
                        start:i+1
                    ]
                )
                break

        i += 1

# ============================================================
# u3()
# ============================================================

u3_code = ""

u3_match = re.search(
    r"u3\s*=",
    text
)

if u3_match:

    start = u3_match.start()

    # Capturamos una ventana grande porque u3 es un objeto
    # factory/configuracion y el output anterior ya establecio
    # que existe alrededor de este offset.
    u3_code = ctx(
        start,
        1000,
        12000
    )

# ============================================================
# dS
# ============================================================

dS_code = ""

for m in re.finditer(
    r"\bdS\s*=",
    text
):

    c = ctx(
        m.start(),
        1000,
        7000
    )

    score = sum(
        token in c
        for token in [
            "subaccountIndex",
            "sequence",
            "orders",
            "positions",
            "collateral",
        ]
    )

    if score >= 4:
        dS_code = c
        break

# ============================================================
# df
# ============================================================

df_code = ""

for m in re.finditer(
    r"\bdf\s*=",
    text
):

    c = ctx(
        m.start(),
        1000,
        7000
    )

    score = sum(
        token in c
        for token in [
            "orderSequenceNumber",
            "change",
            "orders",
        ]
    )

    if score >= 2:
        df_code = c
        break

# ============================================================
# pE
# ============================================================

pE_code = ""

for m in re.finditer(
    r"\bpE\s*=",
    text
):

    c = ctx(
        m.start(),
        800,
        6000
    )

    score = sum(
        token in c
        for token in [
            "orderSequenceNumber",
            "symbol",
            "change",
            "order",
        ]
    )

    if score >= 2:
        pE_code = c
        break

# ============================================================
# pF
# ============================================================

pF_code = ""

pf_match = re.search(
    r"pF\s*=\s*\(",
    text
)

if pf_match:

    start = pf_match.start()

    # Buscar el final de la funcion por el primer "=>" y luego
    # balancear el bloque principal.
    brace = text.find(
        "{",
        start
    )

    if brace >= 0:

        depth = 0
        quote = None
        escaped = False
        i = brace

        while i < len(text):

            ch = text[i]

            if quote:

                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None

                i += 1
                continue

            if ch in ("'", '"', ""):
                quote = ch
                i += 1
                continue

            if ch == "{":
                depth += 1

            elif ch == "}":

                depth -= 1

                if depth == 0:

                    pF_code = norm(
                        text[
                            start:
                            i+1
                        ]
                    )

                    break

            i += 1

# ============================================================
# pw
# ============================================================

pw_code = ""

for m in re.finditer(
    r"\bpw\s*=",
    text
):

    c = ctx(
        m.start(),
        800,
        8000
    )

    score = sum(
        token in c
        for token in [
            "currentBySymbol",
            "deltas",
            "applyDelta",
            "getSymbol",
        ]
    )

    if score >= 3:
        pw_code = c
        break

# ============================================================
# APPLYMESSAGE — ELEGIR LA APARICION QUE CONTIENE EL PIPELINE
# ============================================================

apply_candidates = []

for m in re.finditer(
    r"\bapplyMessage\s*\(",
    text
):

    c = ctx(
        m.start(),
        3000,
        15000
    )

    score = sum(
        token in c
        for token in [
            "t.deltas??[]",
            "pF(",
            "subaccountsByIndex",
            "messageType",
            "lastMessageSlot",
        ]
    )

    apply_candidates.append({
        "offset":
            m.start(),
        "score":
            score,
        "context":
            c
    })

apply_candidates.sort(
    key=lambda x: (
        x["score"],
        len(x["context"])
    ),
    reverse=True
)

apply_code = (
    apply_candidates[0]["context"]
    if apply_candidates
    else ""
)

# ============================================================
# DELTA INNER
# ============================================================

delta_inner = ""

if apply_code:

    candidates = re.findall(
        r":\(\(e,t,r,a\)=>\{.*?\}\}",
        apply_code
    )

    ranked = []

    for c in candidates:

        score = sum(
            token in c
            for token in [
                "t.deltas??[]",
                "pF(",
                "subaccountsByIndex",
                "subaccountIndex",
            ]
        )

        ranked.append(
            (
                score,
                len(c),
                c
            )
        )

    if ranked:
        ranked.sort(
            reverse=True
        )
        delta_inner = norm(
            ranked[0][2]
        )

# ============================================================
# DELTA LOOP
# ============================================================

delta_loop = ""

if delta_inner:

    m = re.search(
        r"for\(let\s+r\s+of\s+t\.deltas\?\?\[\]\)\{",
        delta_inner
    )

    if m:

        start = m.start()
        brace = delta_inner.find(
            "{",
            start
        )

        depth = 0
        quote = None
        escaped = False

        i = brace

        while i < len(delta_inner):

            ch = delta_inner[i]

            if quote:

                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == quote:
                    quote = None

                i += 1
                continue

            if ch in ("'", '"', ""):
                quote = ch
                i += 1
                continue

            if ch == "{":
                depth += 1

            elif ch == "}":

                depth -= 1

                if depth == 0:

                    delta_loop = norm(
                        delta_inner[
                            start:
                            i+1
                        ]
                    )

                    break

            i += 1

# ============================================================
# GUARDS
# ============================================================

process_guards = {

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

apply_guards = {

    "slot":
        bool(
            re.search(
                r"(?:e|t)\.slot\s*(?:!==|!=|===|==|<|>)",
                delta_inner
            )
        ),

    "version":
        bool(
            re.search(
                r"(?:e|t)\.version\s*(?:!==|!=|===|==|<|>)",
                delta_inner
            )
        ),

    "sequence":
        bool(
            re.search(
                r"(?:e|t)\.sequence\s*(?:!==|!=|===|==|<|>)",
                delta_inner
            )
        ),
}

order_guards = [
    {
        "offset":
            m.start(),
        "context":
            ctx(
                m.start(),
                1800,
                3500
            )
    }
    for m in re.finditer(
        r"orderSequenceNumber\s*(?:!==|!=|===|==|<|>)",
        text
    )
]

# ============================================================
# SEQUENCE GAP CONTEXTS
# ============================================================

sequence_gap = []

for m in re.finditer(
    r"sequenceGap",
    text
):

    c = ctx(
        m.start(),
        5000,
        8000
    )

    sequence_gap.append({
        "offset":
            m.start(),
        "context":
            c,
        "traderState":
            "traderState"
            in c,
        "cacheStore":
            "cacheStore"
            in c,
        "applyDelta":
            "applyDelta"
            in c,
        "refresh":
            ".refresh("
            in c,
    })

# ============================================================
# EXACT QUEUE
# ============================================================

queue = []

for token in [
    "AsyncQueue",
    "drop-oldest",
    "buffer:l=2048",
]:

    for m in re.finditer(
        re.escape(token),
        text,
        flags=re.I
    ):

        queue.append({
            "token":
                token,
            "offset":
                m.start(),
            "context":
                ctx(
                    m.start(),
                    5000,
                    8500
                )
        })

# ============================================================
# RESULT
# ============================================================

ground_truth = {

    "processMessage": {
        "found":
            bool(process_code),
        "code":
            process_code,
        "guards":
            process_guards,
    },

    "applyMessage": {
        "found":
            bool(apply_code),
        "offset":
            apply_candidates[0]["offset"]
            if apply_candidates
            else None,
        "score":
            apply_candidates[0]["score"]
            if apply_candidates
            else None,
        "code":
            apply_code,
        "deltaInner":
            delta_inner,
        "deltaLoop":
            delta_loop,
        "guards":
            apply_guards,
    },

    "reducers": {
        "pF":
            pF_code,
        "pE":
            pE_code,
        "pw":
            pw_code,
        "dS":
            dS_code,
        "df":
            df_code,
    },

    "channel": {
        "c1":
            c1_code,
        "u3":
            u3_code,
        "traderState":
            trader_channel_positions
            if False
            else [
                {
                    "offset":
                        m.start(),
                    "context":
                        ctx(
                            m.start(),
                            5000,
                            14000
                        )
                }
                for m in re.finditer(
                    r'channel:"traderState"',
                    text
                )
            ],
    },

    "orders": {
        "orderGuards":
            order_guards,

        "delete":
            "delete a[t.orderSequenceNumber]"
            in pF_code,

        "write":
            "a[t.orderSequenceNumber]=pE(t)"
            in pF_code,

        "closed":
            '"closed"'
            in pF_code,
    },

    "sequenceGap":
        sequence_gap,

    "queue":
        queue,
}

# ============================================================
# SUMMARY
# ============================================================

summary = {

    "processMessage":
        process_guards,

    "applyMessage":
        {
            "found":
                bool(apply_code),
            "deltaInner":
                bool(delta_inner),
            "deltaLoop":
                bool(delta_loop),
            "guards":
                apply_guards,
        },

    "pF":
        {
            "found":
                bool(pF_code),
            "sequenceStored":
                "sequence:t.sequence"
                in pF_code,
            "orderDelete":
                "delete a[t.orderSequenceNumber]"
                in pF_code,
            "orderWrite":
                "a[t.orderSequenceNumber]=pE(t)"
                in pF_code,
        },

    "dS":
        {
            "found":
                bool(dS_code),
            "sequence":
                "sequence"
                in dS_code,
            "orders":
                "orders"
                in dS_code,
        },

    "df":
        {
            "found":
                bool(df_code),
            "orderSequenceNumber":
                "orderSequenceNumber"
                in df_code,
            "change":
                "change"
                in df_code,
        },

    "queue":
        {
            "AsyncQueue":
                "AsyncQueue"
                in text,
            "dropOldest":
                "drop-oldest"
                in text,
            "buffer2048":
                "buffer:l=2048"
                in text,
        },

    "sequenceGap":
        {
            "count":
                len(sequence_gap),
            "traderContexts":
                sum(
                    1
                    for x in sequence_gap
                    if x["traderState"]
                ),
            "cacheContexts":
                sum(
                    1
                    for x in sequence_gap
                    if x["cacheStore"]
                ),
            "applyDeltaContexts":
                sum(
                    1
                    for x in sequence_gap
                    if x["applyDelta"]
                ),
            "refreshContexts":
                sum(
                    1
                    for x in sequence_gap
                    if x["refresh"]
                ),
        },
}

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

    "groundTruth":
        ground_truth,

    "summary":
        summary,
}

path = (
    REPORTS /
    "TRADERSTATE_GROUND_TRUTH_v1_2.json"
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
# EXPORTS
# ============================================================

exports = {
    "PROCESSMESSAGE":
        process_code,

    "APPLYMESSAGE":
        apply_code,

    "DELTA_INNER":
        delta_inner,

    "DELTA_LOOP":
        delta_loop,

    "PF":
        pF_code,

    "PE":
        pE_code,

    "PW":
        pw_code,

    "DS":
        dS_code,

    "DF":
        df_code,

    "C1":
        c1_code,

    "U3":
        u3_code,
}

for name, code in exports.items():

    if code:

        (
            CORPUS /
            f"GROUND_TRUTH_{name}_v1_2.txt"
        ).write_text(
            code,
            encoding="utf-8"
        )

print("=" * 115)
print("SANA FORENSICS — TRADERSTATE GROUND TRUTH v1.2")
print("=" * 115)

print()
print("PROCESSMESSAGE")

for k,v in process_guards.items():
    print(
        f"{k:22s}:",
        v
    )

print()
print("APPLYMESSAGE")
print(
    "FOUND:",
    bool(apply_code)
)
print(
    "DELTA INNER:",
    bool(delta_inner)
)
print(
    "DELTA LOOP:",
    bool(delta_loop)
)

for k,v in apply_guards.items():
    print(
        f"{k:22s}:",
        v
    )

print()
print("pF")
print(
    "FOUND:",
    bool(pF_code)
)
print(
    "SEQUENCE STORED:",
    "sequence:t.sequence"
    in pF_code
)
print(
    "ORDER DELETE:",
    "delete a[t.orderSequenceNumber]"
    in pF_code
)
print(
    "ORDER WRITE:",
    "a[t.orderSequenceNumber]=pE(t)"
    in pF_code
)

print()
print("dS len:", len(dS_code))
print(
    "dS sequence:",
    "sequence" in dS_code
)
print(
    "dS orders:",
    "orders" in dS_code
)

print()
print("df len:", len(df_code))
print(
    "df orderSequenceNumber:",
    "orderSequenceNumber"
    in df_code
)
print(
    "df change:",
    "change"
    in df_code
)

print()
print("SEQUENCE GAP")
print(
    json.dumps(
        summary["sequenceGap"],
        indent=2
    )
)

print()
print("QUEUE")
print(
    json.dumps(
        summary["queue"],
        indent=2
    )
)

print()
print("REPORT:")
print(path)

print("=" * 115)

