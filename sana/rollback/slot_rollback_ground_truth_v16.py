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

def around(source, pos, before=2500, after=5000):
    return norm(
        source[
            max(0, pos-before):
            min(len(source), pos+after)
        ]
    )

def find_hits(source, pattern, limit=200):
    out = []
    for m in re.finditer(
        pattern,
        source
    ):
        out.append({
            "offset": m.start(),
            "match": m.group(0),
            "context": around(
                source,
                m.start()
            )
        })
        if len(out) >= limit:
            break
    return out

# ============================================================
# 1. EXACT applyMessage FROM KNOWN OFFSET
# ============================================================

apply_start = 359707

if not text.startswith(
    "applyMessage(e,t){",
    apply_start
):
    m = re.search(
        r"applyMessage\(e,t\)\{",
        text
    )
    if not m:
        raise RuntimeError(
            "applyMessage no encontrado"
        )
    apply_start = m.start()

def extract_balanced(source, start, opener="{", limit=300000):
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
        nx = (
            source[i+1]
            if i + 1 < end
            else ""
        )

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

apply_raw = extract_balanced(
    text,
    apply_start,
    "{",
    300000
)

if not apply_raw:
    raise RuntimeError(
        "No se pudo extraer applyMessage"
    )

apply_code = norm(
    apply_raw
)

# ============================================================
# 2. DELTA BRANCH EXACTA
# ============================================================

delta_marker = ":((e,t,r,a)=>{"

delta_pos = apply_code.find(
    delta_marker
)

if delta_pos < 0:
    raise RuntimeError(
        "Delta branch no encontrada"
    )

delta_raw = extract_balanced(
    apply_code,
    delta_pos,
    "{",
    120000
)

if not delta_raw:
    raise RuntimeError(
        "Delta branch no extraida"
    )

delta_code = norm(
    delta_raw
)

# ============================================================
# 3. DELTA LOOP EXACTO
# ============================================================

loop_marker = "for(let r of t.deltas??[]){"

loop_pos = delta_code.find(
    loop_marker
)

if loop_pos < 0:
    raise RuntimeError(
        "Loop t.deltas no encontrado"
    )

loop_raw = extract_balanced(
    delta_code,
    loop_pos,
    "{",
    30000
)

delta_loop = norm(
    loop_raw
    if loop_raw
    else ""
)

# ============================================================
# 4. pF EXACTO
# ============================================================

pf_pos = 352870

if not text.startswith(
    "pF=(e,t)=>",
    pf_pos
):
    m = re.search(
        r"pF=\(e,t\)=>",
        text
    )
    if not m:
        raise RuntimeError(
            "pF exacto no encontrado"
        )
    pf_pos = m.start()

pf_raw = extract_balanced(
    text,
    pf_pos,
    "{",
    100000
)

if not pf_raw:
    raise RuntimeError(
        "No se pudo extraer pF"
    )

pf_code = norm(
    pf_raw
)

# ============================================================
# 5. pE EXACTO — USAR CONTEXTO, NO INVENTAR CUERPO
# ============================================================

pe_pos = 350554

pe_context = around(
    text,
    pe_pos,
    1200,
    9000
)

# ============================================================
# 6. pN() — TODAS LAS DEFINICIONES
# ============================================================

pn_positions = [
    m.start()
    for m in re.finditer(
        r"\bpN\s*=",
        text
    )
]

pn_candidates = []

for pos in pn_positions:

    raw = extract_balanced(
        text,
        pos,
        "{",
        70000
    )

    code = (
        norm(raw)
        if raw
        else around(
            text,
            pos,
            1000,
            7000
        )
    )

    pn_candidates.append({
        "offset":
            pos,
        "length":
            len(code),
        "code":
            code,

        "slot_refs":
            len(
                re.findall(
                    r"\bslot\b",
                    code
                )
            ),

        "version_refs":
            len(
                re.findall(
                    r"\bversion\b",
                    code
                )
            ),

        "sequence_refs":
            len(
                re.findall(
                    r"\bsequence\b",
                    code
                )
            ),

        "comparisons":
            {
                "slot":
                    find_hits(
                        code,
                        r"\bslot\s*(?:!==|!=|===|==|<|>|<=|>=)"
                    ),

                "version":
                    find_hits(
                        code,
                        r"\bversion\s*(?:!==|!=|===|==|<|>|<=|>=)"
                    ),

                "sequence":
                    find_hits(
                        code,
                        r"\bsequence\s*(?:!==|!=|===|==|<|>|<=|>=)"
                    ),
            }
    })

pn_candidates.sort(
    key=lambda x: (
        x["slot_refs"]
        +
        x["version_refs"]
        +
        x["sequence_refs"],
        x["length"]
    ),
    reverse=True
)

# ============================================================
# 7. pU() — MARGIN INPUTS
# ============================================================

pu_positions = [
    m.start()
    for m in re.finditer(
        r"\bpU\s*=",
        text
    )
]

pu_candidates = []

for pos in pu_positions:

    pu_candidates.append({
        "offset":
            pos,
        "context":
            around(
                text,
                pos,
                2500,
                10000
            )
    })

# ============================================================
# 8. pO() — SNAPSHOT NORMALIZATION
# ============================================================

po_positions = [
    m.start()
    for m in re.finditer(
        r"\bpO\s*=",
        text
    )
]

po_candidates = []

for pos in po_positions:

    po_candidates.append({
        "offset":
            pos,
        "context":
            around(
                text,
                pos,
                2500,
                10000
            )
    })

# ============================================================
# 9. pR() — EMPTY SUBACCOUNT
# ============================================================

pr_positions = [
    m.start()
    for m in re.finditer(
        r"\bpR\s*=",
        text
    )
]

pr_candidates = []

for pos in pr_positions:

    pr_candidates.append({
        "offset":
            pos,
        "context":
            around(
                text,
                pos,
                2500,
                10000
            )
    })

# ============================================================
# 10. SLOT / LAST MESSAGE USERS
# ============================================================

last_slot_refs = find_hits(
    apply_code,
    r"lastMessageSlot"
)

slot_delta_refs = find_hits(
    apply_code,
    r"slotDelta"
)

last_message_refs = find_hits(
    apply_code,
    r"lastMessage"
)

# ============================================================
# 11. DOES applyMessage COMPARE THE NEW SLOT?
# ============================================================

apply_slot_comparisons = find_hits(
    apply_code,
    r"(?:e|t)\.slot\s*(?:!==|!=|===|==|<|>|<=|>=)"
)

apply_version_comparisons = find_hits(
    apply_code,
    r"(?:e|t)\.version\s*(?:!==|!=|===|==|<|>|<=|>=)"
)

apply_sequence_comparisons = find_hits(
    apply_code,
    r"(?:e|t)\.sequence\s*(?:!==|!=|===|==|<|>|<=|>=)"
)

# ============================================================
# 12. pF SEQUENCE / SLOT / VERSION
# ============================================================

pf_slot_comparisons = find_hits(
    pf_code,
    r"(?:e|t)\.slot\s*(?:!==|!=|===|==|<|>|<=|>=)"
)

pf_version_comparisons = find_hits(
    pf_code,
    r"(?:e|t)\.version\s*(?:!==|!=|===|==|<|>|<=|>=)"
)

pf_sequence_comparisons = find_hits(
    pf_code,
    r"(?:e|t)\.sequence\s*(?:!==|!=|===|==|<|>|<=|>=)"
)

# ============================================================
# 13. ORDER SEQUENCE COMPARISONS
# ============================================================

order_sequence_comparisons = find_hits(
    text,
    r"orderSequenceNumber\s*(?:!==|!=|===|==|<|>|<=|>=)"
)

# ============================================================
# 14. ORDER REDUCER EXACT REGION
# ============================================================

orders_marker = (
    "currentBySymbol:e.ordersBySymbol"
)

orders_pos = pf_code.find(
    orders_marker
)

if orders_pos < 0:
    raise RuntimeError(
        "Reducer de orders no encontrado"
    )

order_region = pf_code[
    max(0, orders_pos-1000):
    min(
        len(pf_code),
        orders_pos+9000
    )
]

# ============================================================
# 15. PROCESS MESSAGE
# ============================================================

process_match = re.search(
    r"processMessage:\(e,\[t,r\]\)=>",
    text
)

if not process_match:
    raise RuntimeError(
        "processMessage exacto no encontrado"
    )

process_pos = process_match.start()

process_tail = text[
    process_pos:
    min(
        len(text),
        process_pos+5000
    )
]

process_end = re.search(
    r"deltas:e\.deltas\?\?\[\]",
    process_tail
)

process_code = norm(
    process_tail[
        :process_end.end()
    ]
    if process_end
    else
    process_tail
)

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
                r"e\.slot\s*(?:!==|!=|===|==|<|>|<=|>=)",
                process_code
            )
        ),

    "version":
        bool(
            re.search(
                r"e\.version\s*(?:!==|!=|===|==|<|>|<=|>=)",
                process_code
            )
        ),

    "sequence":
        bool(
            re.search(
                r"e\.sequence\s*(?:!==|!=|===|==|<|>|<=|>=)",
                process_code
            )
        ),
}

# ============================================================
# 16. c1 EXACT
# ============================================================

c1_match = re.search(
    r"c1=\(\)=>\(\{",
    text
)

c1_code = ""

if c1_match:

    raw = extract_balanced(
        text,
        c1_match.start(),
        "{",
        30000
    )

    if raw:
        c1_code = norm(raw)

# ============================================================
# 17. WS QUEUE
# ============================================================

queue_hits = []

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

        queue_hits.append({
            "token":
                token,
            "offset":
                m.start(),
            "context":
                around(
                    text,
                    m.start(),
                    4500,
                    8000
                )
        })

# ============================================================
# 18. SEQUENCE GAP
# ============================================================

sequence_gap_hits = []

for m in re.finditer(
    r"sequenceGap",
    text
):

    sequence_gap_hits.append({
        "offset":
            m.start(),
        "context":
            around(
                text,
                m.start(),
                5000,
                9000
            )
    })

# ============================================================
# 19. SNAPSHOT API
# ============================================================

snapshot_hits = []

for m in re.finditer(
    r"getTraderStateSnapshot",
    text
):

    snapshot_hits.append({
        "offset":
            m.start(),
        "context":
            around(
                text,
                m.start(),
                3500,
                7000
            )
    })

# ============================================================
# 20. STATIC STATE TRANSITION
# ============================================================

state_transition = {

    "snapshot":
        '"snapshot"===e.messageType'
        in apply_code,

    "delta":
        ':((e,t,r,a)=>'
        in apply_code,

    "delta_loop":
        bool(delta_loop),

    "delta_calls_pF":
        bool(
            re.search(
                r"\bpF\(",
                delta_loop
            )
        ),

    "delta_reads_subaccount":
        "r.subaccountIndex"
        in delta_loop,

    "delta_reads_existing_state":
        "e.subaccountsByIndex[r.subaccountIndex]"
        in delta_loop,

    "delta_fallback":
        "??pR(r.subaccountIndex)"
        in delta_loop,

    "delta_writes_subaccount":
        "n[r.subaccountIndex]=t"
        in delta_loop,

    "snapshot_slot_is_incoming":
        "slot:t.slot"
        in apply_code,

    "delta_slot_is_incoming":
        "slot:t.slot"
        in delta_code,

    "lastMessage_replaced":
        "lastMessage:t"
        in delta_code,

    "lastMessageSlot_replaced":
        "lastMessageSlot:t.slot"
        in delta_code,

    "slotDelta_calculated":
        "slotDelta:"
        in delta_code,

    "slotDelta_negative_possible":
        (
            "t.slot-e.lastMessage.slot"
            in delta_code
        ),

    "no_delta_sequence_compare":
        not bool(
            apply_sequence_comparisons
        ),

    "no_delta_version_compare":
        not bool(
            apply_version_comparisons
        ),

    "no_delta_slot_guard":
        not bool(
            apply_slot_comparisons
        ),
}

# ============================================================
# 21. IMPORTANT: slot comparison found in delta may be
# metadata calculation, not a guard.
# Extract exact instances.
# ============================================================

delta_slot_matches = []

for m in re.finditer(
    r"(?:e|t)\.slot\s*(?:!==|!=|===|==|<|>|<=|>=)",
    delta_code
):

    delta_slot_matches.append({
        "offset":
            m.start(),
        "context":
            delta_code[
                max(0,m.start()-1600):
                min(len(delta_code),m.end()+3000)
            ]
    })

# ============================================================
# 22. SYNTHETIC MODEL
# ============================================================

def observed_delta(
    state,
    message
):

    out = {
        "slot":
            message["slot"],

        "lastMessageSlot":
            message["slot"],

        "lastMessage":
            dict(message),

        "subaccounts":
            dict(
                state[
                    "subaccounts"
                ]
            )
    }

    idx = message[
        "subaccountIndex"
    ]

    out[
        "subaccounts"
    ][idx] = {
        "collateral":
            message.get(
                "collateral"
            )
    }

    return out


initial = {

    "slot":
        1000,

    "lastMessageSlot":
        1000,

    "lastMessage":
        {
            "slot":
                1000
        },

    "subaccounts":
        {
            0:
                {
                    "collateral":
                        1000
                }
        },
}

rollback = {

    "slot":
        900,

    "version":
        9,

    "sequence":
        40,

    "subaccountIndex":
        0,

    "collateral":
        990,
}

observed = observed_delta(
    initial,
    rollback
)

# Strict control model ONLY for comparison.
strict = dict(initial)

strict_status = (
    "REJECT_SLOT_ROLLBACK"
    if rollback["slot"]
    <
    initial["slot"]
    else
    "ACCEPT"
)

rollback_test = {

    "observed_final_slot":
        observed["slot"],

    "observed_lastMessageSlot":
        observed["lastMessageSlot"],

    "observed_slotDelta":
        rollback["slot"]
        -
        initial["slot"],

    "strict_status":
        strict_status,

    "diverged":
        strict_status
        !=
        "ACCEPT"
        and
        observed["slot"]
        !=
        initial["slot"],
}

# ============================================================
# 23. STATIC CLASSIFICATION
# ============================================================

static_surface = (

    state_transition[
        "snapshot"
    ]

    and

    state_transition[
        "delta"
    ]

    and

    state_transition[
        "delta_loop"
    ]

    and

    state_transition[
        "delta_calls_pF"
    ]

    and

    state_transition[
        "snapshot_slot_is_incoming"
    ]

    and

    state_transition[
        "delta_slot_is_incoming"
    ]

    and

    state_transition[
        "lastMessage_replaced"
    ]

    and

    state_transition[
        "lastMessageSlot_replaced"
    ]

    and

    state_transition[
        "slotDelta_calculated"
    ]

    and

    state_transition[
        "slotDelta_negative_possible"
    ]

    and

    state_transition[
        "no_delta_sequence_compare"
    ]

    and

    state_transition[
        "no_delta_version_compare"
    ]

)

# ============================================================
# 24. SAVE
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

    "processMessage": {
        "code":
            process_code,
        "guards":
            process_guards,
    },

    "c1":
        c1_code,

    "applyMessage": {

        "code":
            apply_code,

        "delta":
            delta_code,

        "deltaLoop":
            delta_loop,

        "pFCalls":
            pf_calls
            if 'pf_calls' in globals()
            else [],

        "deltaSlotComparisons":
            delta_slot_matches,

        "guards":
            {
                "slot":
                    apply_slot_comparisons,

                "version":
                    apply_version_comparisons,

                "sequence":
                    apply_sequence_comparisons,
            },
    },

    "pF": {

        "code":
            pf_code,

        "orderRegion":
            order_region,

        "slotComparisons":
            pf_slot_comparisons,

        "versionComparisons":
            pf_version_comparisons,

        "sequenceComparisons":
            pf_sequence_comparisons,
    },

    "pEContext":
        pe_context,

    "pN":
        pn_candidates,

    "pU":
        pu_candidates,

    "pO":
        po_candidates,

    "pR":
        pr_candidates,

    "lastMessage":
        last_message_refs,

    "lastMessageSlot":
        last_slot_refs,

    "slotDelta":
        slot_delta_refs,

    "orderSequenceComparisons":
        order_sequence_comparisons,

    "queue":
        queue_hits,

    "sequenceGap":
        sequence_gap_hits,

    "snapshotAPI":
        snapshot_hits,

    "stateTransition":
        state_transition,

    "syntheticRollback":
        rollback_test,

    "classification": {

        "staticSurface":
            static_surface,

        "productionBugConfirmed":
            False,

        "runtimeImpactConfirmed":
            False,

        "classification":
            (
                "STATIC_SLOT_ROLLBACK_PROPAGATION_SURFACE"
                if static_surface
                else
                "NOT_YET_ESTABLISHED"
            ),
    },
}

path = (
    REPORTS /
    "SLOT_ROLLBACK_GROUND_TRUTH_v1_6.json"
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
# EXPORT
# ============================================================

exports = {

    "APPLYMESSAGE":
        apply_code,

    "DELTA":
        delta_code,

    "DELTA_LOOP":
        delta_loop,

    "PF":
        pf_code,

    "PROCESSMESSAGE":
        process_code,

    "C1":
        c1_code,

}

for name, code in exports.items():

    if code:

        (
            CORPUS /
            f"GROUND_TRUTH_{name}_v1_6.txt"
        ).write_text(
            code,
            encoding="utf-8"
        )

# ============================================================
# PRINT
# ============================================================

print("=" * 115)
print("SANA FORENSICS — SLOT ROLLBACK GROUND TRUTH v1.6")
print("=" * 115)

print()
print("PROCESSMESSAGE")

for k,v in process_guards.items():
    print(
        f"{k:25s}:",
        v
    )

print()
print("APPLYMESSAGE")

print(
    "exact:",
    bool(apply_code)
)

print(
    "delta:",
    bool(delta_code)
)

print(
    "delta loop:",
    bool(delta_loop)
)

print(
    "pF calls:",
    len(
        pf_calls
        if 'pf_calls' in globals()
        else []
    )
)

print()
print("DELTA SLOT COMPARISONS")

print(
    "count:",
    len(delta_slot_matches)
)

for x in delta_slot_matches:
    print()
    print(
        x["context"]
    )

print()
print("pF SEMANTICS")

for k,v in [
    ("order state", "ordersBySequence:e.ordersBySequence" in pf_code),
    ("order delete", "delete a[t.orderSequenceNumber]" in pf_code),
    ("order write", "a[t.orderSequenceNumber]=pE(t)" in pf_code),
    ("sequence stored", "sequence:t.sequence" in pf_code),
]:
    print(
        f"{k:25s}:",
        v
    )

print()
print("STATE TRANSITION")

for k,v in state_transition.items():
    print(
        f"{k:38s}:",
        v
    )

print()
print("SEQUENCE GAP")

for x in sequence_gap_hits:
    print()
    print(
        "OFFSET:",
        x["offset"]
    )
    print(
        x["context"]
    )

print()
print("SYNTHETIC ROLLBACK")

for k,v in rollback_test.items():
    print(
        f"{k:30s}:",
        v
    )

print()
print(
    "STATIC SURFACE:",
    static_surface
)

print(
    "CLASSIFICATION:",
    (
        "STATIC_SLOT_ROLLBACK_PROPAGATION_SURFACE"
        if static_surface
        else
        "NOT_YET_ESTABLISHED"
    )
)

print()
print(
    "REPORT:",
    path
)

print("=" * 115)

