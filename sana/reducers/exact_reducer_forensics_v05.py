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
# EXTRACTOR ROBUSTO PARA JS MINIFICADO
# ============================================================

def norm(s):
    return re.sub(r"\s+", " ", s).strip()


def scan_until_statement_end(start, max_len=400000):
    """
    Extrae desde 'start' hasta el ';' que cierra la expresión
    superior, respetando strings y nesting.
    """

    quote = None
    escaped = False

    curly = 0
    square = 0
    paren = 0

    line_comment = False
    block_comment = False

    end = min(
        len(text),
        start + max_len
    )

    i = start

    while i < end:

        ch = text[i]
        nx = text[i + 1] if i + 1 < end else ""

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

        if ch == "{":
            curly += 1

        elif ch == "}":
            curly -= 1

        elif ch == "[":
            square += 1

        elif ch == "]":
            square -= 1

        elif ch == "(":
            paren += 1

        elif ch == ")":
            paren -= 1

        elif ch == ";":
            if (
                curly == 0
                and
                square == 0
                and
                paren == 0
            ):
                return text[start:i + 1]

        i += 1

    return text[start:end]


def extract_arrow_expression(start, max_len=400000):
    """
    Extrae:
        name=(args)=>EXPRESSION
    donde EXPRESSION puede ser:
        {...}
        ({...})
        value
        call(...)
    """

    arrow = text.find(
        "=>",
        start,
        min(
            len(text),
            start + 10000
        )
    )

    if arrow < 0:
        return None

    pos = arrow + 2

    # ignorar espacios
    while pos < len(text) and text[pos].isspace():
        pos += 1

    quote = None
    escaped = False
    curly = 0
    square = 0
    paren = 0
    line_comment = False
    block_comment = False

    end = min(
        len(text),
        start + max_len
    )

    i = pos

    while i < end:

        ch = text[i]
        nx = text[i + 1] if i + 1 < end else ""

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

        if quote:
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

        if ch == "{":
            curly += 1

        elif ch == "}":
            curly -= 1

        elif ch == "[":
            square += 1

        elif ch == "]":
            square -= 1

        elif ch == "(":
            paren += 1

        elif ch == ")":
            paren -= 1

        elif ch == ";":
            if (
                curly == 0
                and square == 0
                and paren == 0
            ):
                return text[start:i + 1]

        i += 1

    return text[start:end]


def extract_function_decl(start, max_len=400000):
    """
    Para:
        function x(...){...}
    o:
        x=(...)=>{...}
    """
    return scan_until_statement_end(
        start,
        max_len
    )


# ============================================================
# DEFINICIONES EXACTAS POR PATRON
# ============================================================

TARGETS = {
    "pF": [
        r"(?<![A-Za-z0-9_$])pF\s*=\s*\(",
    ],
    "pE": [
        r"(?<![A-Za-z0-9_$])pE\s*=",
    ],
    "pA": [
        r"(?<![A-Za-z0-9_$])pA\s*=",
    ],
    "pC": [
        r"(?<![A-Za-z0-9_$])pC\s*=",
    ],
    "pM": [
        r"(?<![A-Za-z0-9_$])pM\s*=",
    ],
    "pw": [
        r"(?<![A-Za-z0-9_$])pw\s*=",
    ],
    "dS": [
        r"(?<![A-Za-z0-9_$])dS\s*=",
    ],
    "df": [
        r"(?<![A-Za-z0-9_$])df\s*=",
    ],
    "u3": [
        r"(?<![A-Za-z0-9_$])u3\s*=",
        r"(?<![A-Za-z0-9_$])function\s+u3\s*\(",
    ],
}


definitions = {}

for name, regexes in TARGETS.items():

    items = []

    for regex in regexes:

        for m in re.finditer(
            regex,
            text
        ):

            pos = m.start()

            # Para aliases asignados:
            #   x=(... )=>...
            # usamos extractor de expresión arrow.
            if "=>" in text[
                pos:
                min(
                    len(text),
                    pos + 10000
                )
            ]:

                code = extract_arrow_expression(
                    pos
                )

            else:

                code = extract_function_decl(
                    pos
                )

            if not code:
                continue

            items.append({
                "offset":
                    pos,

                "pattern":
                    regex,

                "length":
                    len(code),

                "code":
                    norm(code),
            })

    seen = set()
    unique = []

    for item in items:

        key = (
            item["offset"],
            item["length"]
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)

    definitions[
        name
    ] = unique


# ============================================================
# FILTRO DE CALIDAD
# ============================================================

# pF real debe contener:
#   positions
#   orders
#   splines
#   triggers
#
# pE real debe contener:
#   orderSequenceNumber
#
# pw real debe contener:
#   currentBySymbol
#   deltas
#
# dS debe contener:
#   subaccountIndex
#   sequence
#
quality = {}

for name, items in definitions.items():

    scored = []

    for item in items:

        code = item["code"]
        low = code.lower()

        score = 0

        signatures = {
            "pF":
                [
                    "positions",
                    "orders",
                    "splines",
                    "triggers",
                    "margininputs",
                ],

            "pE":
                [
                    "ordersequencenumber",
                    "size",
                    "price",
                    "side",
                ],

            "pw":
                [
                    "currentbysymbol",
                    "deltas",
                    "getsymbol",
                    "applydelta",
                ],

            "dS":
                [
                    "subaccountindex",
                    "sequence",
                ],

            "df":
                [
                    "ordersequencenumber",
                    "change",
                ],

            "pA":
                [
                    "symbol",
                    "position",
                ],

            "pC":
                [
                    "symbol",
                ],

            "pM":
                [
                    "symbol",
                    "triggers",
                ],

            "u3":
                [
                    "processmessage",
                    "schema",
                    "onmsg",
                ],
        }

        for token in signatures.get(
            name,
            []
        ):

            if token in low:
                score += 1

        scored.append({
            **item,
            "quality_score":
                score
        })

    scored.sort(
        key=lambda x:
            (
                x["quality_score"],
                x["length"]
            ),
        reverse=True
    )

    quality[
        name
    ] = scored


# ============================================================
# EXACT BEST DEFINITIONS
# ============================================================

best = {}

for name, items in quality.items():

    best[name] = (
        items[0]
        if items
        else None
    )


# ============================================================
# WRITE EXACT CORPUS
# ============================================================

for name, item in best.items():

    if not item:
        continue

    path = (
        CORPUS /
        f"{name}_BEST_EXACT.js.txt"
    )

    path.write_text(
        item["code"],
        encoding="utf-8"
    )


# ============================================================
# CRITICAL SEMANTICS
# ============================================================

pf = (
    best["pF"]["code"]
    if best["pF"]
    else ""
)

pe = (
    best["pE"]["code"]
    if best["pE"]
    else ""
)

pw = (
    best["pw"]["code"]
    if best["pw"]
    else ""
)

ds = (
    best["dS"]["code"]
    if best["dS"]
    else ""
)

df = (
    best["df"]["code"]
    if best["df"]
    else ""
)

u3 = (
    best["u3"]["code"]
    if best["u3"]
    else ""
)


semantics = {

    "pF":

        {
            "length":
                len(pf),

            "positions":
                "positions"
                in pf,

            "orders":
                "orders"
                in pf,

            "splines":
                "splines"
                in pf,

            "triggers":
                "triggers"
                in pf,

            "uses_pw":
                "pw("
                in pf,

            "sequence_storage":
                "sequence:t.sequence"
                in pf,

            "collateral_storage":
                "collateral:t.collateral"
                in pf,

            "order_delete":
                "delete a[t.orderSequenceNumber]"
                in pf,

            "order_write":
                "a[t.orderSequenceNumber]=pE(t)"
                in pf,

            "closed":
                '"closed"'
                in pf,

            "slot":
                bool(
                    re.search(
                        r"\bslot\b",
                        pf
                    )
                ),

            "version":
                bool(
                    re.search(
                        r"\bversion\b",
                        pf
                    )
                ),

            "sequence_compare":
                bool(
                    re.search(
                        r"sequence\s*(?:!==|!=|===|==|<|>)",
                        pf
                    )
                ),
        },

    "pE":

        {
            "length":
                len(pe),

            "orderSequenceNumber":
                "orderSequenceNumber"
                in pe,

            "symbol":
                "symbol"
                in pe,

            "price":
                "price"
                in pe,

            "size":
                "size"
                in pe,

            "side":
                "side"
                in pe,

            "spread":
                "..."
                in pe,
        },

    "pw":

        {
            "length":
                len(pw),

            "currentBySymbol":
                "currentBySymbol"
                in pw,

            "deltas":
                "deltas"
                in pw,

            "applyDelta":
                "applyDelta"
                in pw,

            "getSymbol":
                "getSymbol"
                in pw,

            "closed":
                '"closed"'
                in pw,
        },

    "dS":

        {
            "length":
                len(ds),

            "subaccountIndex":
                "subaccountIndex"
                in ds,

            "sequence":
                "sequence"
                in ds,

            "orders":
                "orders"
                in ds,

            "positions":
                "positions"
                in ds,

            "collateral":
                "collateral"
                in ds,
        },

    "df":

        {
            "length":
                len(df),

            "orderSequenceNumber":
                "orderSequenceNumber"
                in df,

            "change":
                "change"
                in df,
        },

    "u3":

        {
            "length":
                len(u3),

            "processMessage":
                "processMessage"
                in u3,

            "schema":
                "schema"
                in u3,

            "onMsg":
                "onMsg"
                in u3,

            "drop_oldest":
                "drop-oldest"
                in u3,

            "buffer_2048":
                "buffer:l=2048"
                in u3,
        },
}


# ============================================================
# APPLYMESSAGE CONTEXT EXACTO
# ============================================================

apply_refs = []

for m in re.finditer(
    r"applyMessage\s*:",
    text
):

    pos = m.start()

    apply_refs.append({
        "offset":
            pos,
        "context":
            norm(
                text[
                    max(
                        0,
                        pos - 4000
                    ):
                    min(
                        len(text),
                        pos + 18000
                    )
                ]
            ),
    })


# ============================================================
# PROCESSMESSAGE CONTEXT
# ============================================================

process_refs = []

for m in re.finditer(
    r"processMessage\s*:",
    text
):

    pos = m.start()

    process_refs.append({
        "offset":
            pos,
        "context":
            norm(
                text[
                    max(
                        0,
                        pos - 2500
                    ):
                    min(
                        len(text),
                        pos + 7000
                    )
                ]
            ),
    })


# ============================================================
# ORDER REDUCER EXACT REGION
# ============================================================

order_start = pf.find(
    "ordersBySequence"
)

order_region = (
    pf[
        max(
            0,
            order_start - 2000
        ):
        min(
            len(pf),
            order_start + 12000
        )
    ]
    if order_start >= 0
    else ""
)


# ============================================================
# STATE TRANSITION TESTS
# ============================================================

def observed_order_reduce(
    state,
    delta
):

    result = {
        k: dict(v)
        for k, v in state.items()
    }

    for order in delta.get(
        "orders",
        []
    ):

        key = str(
            order[
                "orderSequenceNumber"
            ]
        )

        if (
            order.get(
                "change"
            )
            ==
            "closed"
        ):

            result.pop(
                key,
                None
            )

        else:

            result[
                key
            ] = dict(order)

    return result


initial = {
    "7": {
        "orderSequenceNumber":
            "7",
        "priceUsd":
            "150",
        "sizeRemainingLots":
            "100",
        "status":
            "open",
    }
}

fresh = {
    "sequence":
        200,
    "orders": [
        {
            "orderSequenceNumber":
                "7",
            "priceUsd":
                "200",
            "sizeRemainingLots":
                "20",
            "change":
                "updated",
        }
    ]
}

stale = {
    "sequence":
        199,
    "orders": [
        {
            "orderSequenceNumber":
                "7",
            "priceUsd":
                "180",
            "sizeRemainingLots":
                "80",
            "change":
                "updated",
        }
    ]
}

close = {
    "sequence":
        201,
    "orders": [
        {
            "orderSequenceNumber":
                "7",
            "change":
                "closed",
        }
    ]
}

unrelated = {
    "sequence":
        202,
    "orders": [
        {
            "orderSequenceNumber":
                "8",
            "priceUsd":
                "210",
            "sizeRemainingLots":
                "10",
            "change":
                "updated",
        }
    ]
}

observed_fresh_then_stale = observed_order_reduce(
    observed_order_reduce(
        initial,
        fresh
    ),
    stale
)

observed_complete_close = observed_order_reduce(
    observed_order_reduce(
        observed_order_reduce(
            initial,
            fresh
        ),
        close
    ),
    unrelated
)

observed_missing_close = observed_order_reduce(
    observed_order_reduce(
        initial,
        fresh
    ),
    unrelated
)


# ============================================================
# STRICT REFERENCE
# ============================================================

def strict_reduce(
    state,
    delta,
    last_sequence
):

    incoming = int(
        delta[
            "sequence"
        ]
    )

    if incoming <= last_sequence:
        return (
            dict(state),
            last_sequence,
            "REJECT_STALE"
        )

    result = observed_order_reduce(
        state,
        delta
    )

    return (
        result,
        incoming,
        "ACCEPT"
    )


strict_1, strict_seq, strict_status = strict_reduce(
    {
        "7": dict(
            initial["7"]
        )
    },
    fresh,
    199
)

strict_2, strict_seq2, strict_status2 = strict_reduce(
    strict_1,
    stale,
    strict_seq
)


# ============================================================
# FINAL FINDINGS
# ============================================================

finding = {

    "exact_pF_found":
        bool(pf),

    "exact_pE_found":
        bool(pe),

    "exact_pw_found":
        bool(pw),

    "exact_dS_found":
        bool(ds),

    "exact_df_found":
        bool(df),

    "exact_u3_found":
        bool(u3),

    "incremental_state":
        semantics["pF"]["uses_pw"]
        and
        semantics["pw"]["currentBySymbol"]
        and
        semantics["pw"]["deltas"],

    "order_entity_replacement":
        semantics["pF"]["order_write"],

    "order_close_deletes":
        semantics["pF"]["order_delete"],

    "sequence_persisted":
        semantics["pF"]["sequence_storage"],

    "sequence_checked_in_pF":
        semantics["pF"]["sequence_compare"],

    "sequence_checked_in_processMessage":
        bool(
            process_refs
            and
            re.search(
                r"e\.sequence\s*(?:!==|!=|===|==|<|>)",
                process_refs[0]["context"]
            )
        ),

    "stale_order_overwrite":
        (
            observed_fresh_then_stale[
                "7"
            ][
                "priceUsd"
            ]
            ==
            "180"
        ),

    "strict_rejects_stale":
        strict_status2
        ==
        "REJECT_STALE",

    "missing_close_diverges":
        observed_complete_close
        !=
        observed_missing_close,

    "queue_drop_oldest":
        "drop-oldest"
        in text,

    "snapshot_api":
        "getTraderStateSnapshot"
        in text,

    "sequence_gap_handler_global":
        "sequenceGap"
        in text,
}


# ============================================================
# SAVE
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

    "definitions":
        definitions,

    "best":
        best,

    "semantics":
        semantics,

    "applyMessage":
        apply_refs,

    "processMessage":
        process_refs,

    "orderReducer":
        order_region,

    "tests": {

        "freshThenStale":
            observed_fresh_then_stale,

        "strict":
            strict_2,

        "strictStatus":
            strict_status2,

        "completeClose":
            observed_complete_close,

        "missingClose":
            observed_missing_close,

    },

    "finding":
        finding,
}


report_path = (
    REPORTS /
    "EXACT_REDUCER_FORENSICS_v0_5.json"
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
# PRINT
# ============================================================

print("=" * 115)
print("SANA FORENSICS — EXACT REDUCER FORENSICS v0.5")
print("=" * 115)
print()

print("DEFINICIONES EXACTAS")

for name in [
    "u3",
    "pF",
    "pE",
    "pA",
    "pC",
    "pM",
    "pw",
    "dS",
    "df",
]:

    item = best.get(name)

    if item:

        print(
            f"{name:8s} "
            f"offset={item['offset']} "
            f"len={item['length']} "
            f"score={item['quality_score']}"
        )

    else:

        print(
            f"{name:8s} NOT FOUND"
        )


print()
print("SEMANTICA")

for key, value in semantics.items():

    print(
        "\n[" + key + "]"
    )

    for k, v in value.items():

        print(
            f"  {k:35s}:",
            v
        )


print()
print("FINDINGS")

for k, v in finding.items():

    print(
        f"{k:42s}:",
        v
    )


print()
print("STALE ORDER TEST")

print(
    "OBSERVED:",
    json.dumps(
        observed_fresh_then_stale,
        indent=2
    )
)

print(
    "STRICT:",
    json.dumps(
        strict_2,
        indent=2
    )
)

print(
    "STRICT STATUS:",
    strict_status2
)


print()
print("MISSING CLOSE")

print(
    "COMPLETE:",
    json.dumps(
        observed_complete_close,
        indent=2
    )
)

print(
    "MISSING:",
    json.dumps(
        observed_missing_close,
        indent=2
    )
)

print(
    "DIVERGED:",
    observed_complete_close
    !=
    observed_missing_close
)

print()
print(
    "REPORT:",
    report_path
)

print(
    "CORPUS:",
    CORPUS
)

print("=" * 115)

