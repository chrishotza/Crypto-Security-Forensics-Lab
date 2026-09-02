import json
import re
from pathlib import Path
from collections import deque

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

def ctx(source, pos, before=2500, after=5000):
    return compact(
        source[
            max(0, pos-before):
            min(len(source), pos+after)
        ]
    )

def refs(pattern, source=text, flags=0, limit=1000):
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
                ctx(
                    source,
                    m.start()
                )
        })

        if len(out) >= limit:
            break

    return out

# ============================================================
# 1. BUILD GLOBAL DEFINITION INDEX
# ============================================================

definition_index = {}

patterns = [

    (
        "function",
        r"\bfunction\s+"
        r"([A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*\("
    ),

    (
        "arrow",
        r"\b"
        r"([A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*=\s*"
        r"(?:async\s*)?"
        r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*=>"
    ),

    (
        "assignment",
        r"\b"
        r"([A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*=\s*"
    ),

    (
        "object",
        r"\b"
        r"([A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*:\s*"
        r"(?:async\s*)?"
        r"(?:function\s*)?"
        r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s*=>?"
    ),
]

seen_defs = set()

for kind, pattern in patterns:

    for m in re.finditer(
        pattern,
        text
    ):

        name = m.group(1)
        offset = m.start()

        key = (
            name,
            offset
        )

        if key in seen_defs:
            continue

        seen_defs.add(key)

        raw = balanced(
            text,
            offset,
            "{",
            180000
        )

        if not raw:
            continue

        code = compact(raw)

        definition_index.setdefault(
            name,
            []
        ).append({
            "name":
                name,

            "kind":
                kind,

            "offset":
                offset,

            "length":
                len(raw),

            "declaration":
                m.group(0),

            "code":
                code,
        })

# ============================================================
# 2. EXACT PLACEORDER -> R
# ============================================================

place_prop = re.search(
    r"\bplaceOrder\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)",
    text
)

if not place_prop:
    raise RuntimeError(
        "placeOrder property no encontrada"
    )

binding = place_prop.group(1)

if binding != "R":
    print(
        f"ADVERTENCIA: binding esperado R, encontrado {binding}"
    )

r_defs = definition_index.get(
    binding,
    []
)

if not r_defs:
    raise RuntimeError(
        f"No se encontró definición de {binding}"
    )

# elegir por contenido de orden
def semantic_score(code):
    low = code.lower()

    return sum(
        token in low
        for token in [
            "order",
            "orders",
            "placeisolated",
            "buildplace",
            "limitorder",
            "marketorder",
            "reduceonly",
            "leverage",
            "price",
            "size",
            "side",
            "sign",
        ]
    )

r_def = max(
    r_defs,
    key=lambda x: (
        semantic_score(
            x["code"]
        ),
        x["length"]
    )
)

r_code = r_def[
    "code"
]

# ============================================================
# 3. EXACT R CALLS
# ============================================================

JS_RESERVED = {
    "if","else","for","while","do","switch","case",
    "break","continue","return","throw","try","catch",
    "finally","new","typeof","void","delete","in",
    "instanceof","await","async","yield","this",
    "true","false","null","undefined","function",
}

builtin_skip = {
    "Error","Number","String","Boolean","Object",
    "Array","Promise","Date","Math","JSON","console",
    "abs","trim","stringify","parse","push","pop",
    "map","filter","reduce","flatMap","keys","values",
    "assign","from","setTimeout","clearTimeout",
}

def extract_calls(code):
    result = set()

    for m in re.finditer(
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
        code
    ):

        name = m.group(1)

        if (
            name not in JS_RESERVED
            and name not in builtin_skip
        ):
            result.add(
                name
            )

    return sorted(
        result
    )

r_calls = extract_calls(
    r_code
)

# ============================================================
# 4. DEFINITIONS OF DIRECT R CALLEES
# ============================================================

direct_resolution = {}

for name in r_calls:

    defs = definition_index.get(
        name,
        []
    )

    scored = sorted(
        defs,
        key=lambda x: (
            semantic_score(
                x["code"]
            ),
            x["length"]
        ),
        reverse=True
    )

    direct_resolution[
        name
    ] = scored[:10]

# ============================================================
# 5. EXPECTED ORDER FUNCTIONS
# ============================================================

targets = [
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
    "buildLimitOrderPacket",
    "buildMarketOrderPacket",
    "buildPlaceLimitOrder",
    "buildPlaceMarketOrder",
    "buildLimit",
    "buildMarket",
    "placeLimit",
    "placeMarket",
]

target_resolution = {}

for name in targets:

    target_resolution[
        name
    ] = definition_index.get(
        name,
        []
    )[:20]

# ============================================================
# 6. RESOLVE IDENTIFIER CHAINS WITHOUT GUESSING NAMES
# ============================================================

def best_def(
    name,
    caller_offset=None
):

    defs = definition_index.get(
        name,
        []
    )

    if not defs:
        return None

    def score(d):

        semantic = semantic_score(
            d["code"]
        )

        distance = (
            abs(
                d["offset"]
                -
                caller_offset
            )
            if caller_offset is not None
            else 10**12
        )

        return (
            semantic,
            -distance,
            d["length"]
        )

    return max(
        defs,
        key=score
    )

# ============================================================
# 7. BFS FROM R — KEEP EXACT IDENTIFIERS
# ============================================================

graph = {}
queue = deque()

queue.append(
    (
        binding,
        r_def,
        0,
        [binding]
    )
)

visited = set()

while queue:

    name, definition, depth, path = (
        queue.popleft()
    )

    if depth > 8:
        continue

    key = (
        name,
        definition[
            "offset"
        ]
    )

    if key in visited:
        continue

    visited.add(key)

    code = definition[
        "code"
    ]

    calls = extract_calls(
        code
    )

    low = code.lower()

    graph[key] = {

        "name":
            name,

        "offset":
            definition[
                "offset"
            ],

        "length":
            definition[
                "length"
            ],

        "kind":
            definition[
                "kind"
            ],

        "path":
            path,

        "calls":
            calls,

        "orderTerms":
            [
                x
                for x in [
                    "placeOrder",
                    "placeIsolatedLimitOrder",
                    "placeIsolatedMarketOrder",
                    "buildLimitOrderPacket",
                    "buildMarketOrderPacket",
                    "buildPlaceLimitOrder",
                    "buildPlaceMarketOrder",
                    "limitOrder",
                    "marketOrder",
                    "order",
                    "orders",
                    "perp",
                    "position",
                    "reduceOnly",
                    "leverage",
                    "price",
                    "size",
                    "side",
                ]
                if x.lower() in low
            ],

        "stateTerms":
            [
                x
                for x in [
                    "marginInputs",
                    "collateral",
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
                if x.lower() in low
            ],

        "networkTerms":
            [
                x
                for x in [
                    "fetch",
                    "request",
                    "rpc",
                    "post",
                    "send",
                    "submit",
                    "execute",
                    "mutate",
                    "dispatch",
                    "broadcast",
                    "sendTransaction",
                    "signAndSend",
                ]
                if x.lower() in low
            ],

        "authTerms":
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
                if x.lower() in low
            ],
    }

    if depth >= 8:
        continue

    for child in calls:

        child_def = best_def(
            child,
            definition[
                "offset"
            ]
        )

        if not child_def:
            continue

        queue.append(
            (
                child,
                child_def,
                depth + 1,
                path + [child]
            )
        )

# ============================================================
# 8. FIND EXACT ORDER FUNCTIONS IN THE ENTIRE GLOBAL GRAPH
# ============================================================

order_named_nodes = []

for key,node in graph.items():

    lname = node[
        "name"
    ].lower()

    if any(
        term in lname
        for term in [
            "order",
            "place",
            "market",
            "limit",
            "perp",
            "position",
        ]
    ):

        order_named_nodes.append(
            node
        )

# ============================================================
# 9. FUNCTION BODIES WITH ORDER + NETWORK
# ============================================================

order_network_nodes = [
    node
    for node in graph.values()
    if
    node["orderTerms"]
    and
    node["networkTerms"]
]

order_state_nodes = [
    node
    for node in graph.values()
    if
    node["orderTerms"]
    and
    node["stateTerms"]
]

order_auth_nodes = [
    node
    for node in graph.values()
    if
    node["orderTerms"]
    and
    node["authTerms"]
]

# ============================================================
# 10. EXACT STATE TRANSITION FROM PREVIOUS FINDINGS
# ============================================================

process_sequence_guard = bool(
    re.search(
        r"processMessage:"
        r".{0,7000}"
        r"e\.sequence\s*"
        r"(?:!==|!=|===|==|<|>|<=|>=)",
        text
    )
)

delta_sequence_guard = bool(
    re.search(
        r"t\.deltas"
        r".{0,15000}"
        r"(?:e|t)\.sequence\s*"
        r"(?:!==|!=|===|==|<|>|<=|>=)",
        text
    )
)

order_sequence_guard = bool(
    re.search(
        r"pF=\(e,t\)=>"
        r".{0,15000}"
        r"orderSequenceNumber\s*"
        r"(?:!==|!=|===|==|<|>|<=|>=)",
        text
    )
)

order_replacement = (
    "a[t.orderSequenceNumber]=pE(t)"
    in text
)

order_delete = (
    "delete a[t.orderSequenceNumber]"
    in text
)

# ============================================================
# 11. FIND FUNCTIONS THAT READ THESE STATE DOMAINS
# ============================================================

state_readers = []

for term in [
    "collateral",
    "ordersBySymbol",
    "ordersBySequence",
    "positionsBySymbol",
    "marginInputs",
    "sequence",
]:

    for m in re.finditer(
        rf"\b{re.escape(term)}\b",
        text,
        flags=re.I
    ):

        p = m.start()

        # closest graph node by offset
        nearest = None
        nearest_distance = None

        for node in graph.values():

            d = abs(
                node[
                    "offset"
                ]
                -
                p
            )

            if (
                nearest_distance is None
                or
                d < nearest_distance
            ):

                nearest_distance = d
                nearest = node

        if nearest:

            state_readers.append({

                "state":
                    term,

                "offset":
                    p,

                "nearestFunction":
                    nearest[
                        "name"
                    ],

                "nearestFunctionOffset":
                    nearest[
                        "offset"
                    ],

                "distance":
                    nearest_distance,

                "context":
                    ctx(
                        text,
                        p,
                        1800,
                        3000
                    )
            })

# ============================================================
# 12. BUILD EXACT PATH CANDIDATES:
# R -> ORDER -> NETWORK
# R -> ORDER -> AUTH
# R -> STATE/ORDER
# ============================================================

paths_order_network = []
paths_order_auth = []
paths_order_state = []

for node in order_network_nodes:

    paths_order_network.append({

        "path":
            node[
                "path"
            ],

        "target":
            node[
                "name"
            ],

        "offset":
            node[
                "offset"
            ],

        "orderTerms":
            node[
                "orderTerms"
            ],

        "stateTerms":
            node[
                "stateTerms"
            ],

        "networkTerms":
            node[
                "networkTerms"
            ],

        "authTerms":
            node[
                "authTerms"
            ],
    })

for node in order_auth_nodes:

    paths_order_auth.append({

        "path":
            node[
                "path"
            ],

        "target":
            node[
                "name"
            ],

        "offset":
            node[
                "offset"
            ],

        "orderTerms":
            node[
                "orderTerms"
            ],

        "stateTerms":
            node[
                "stateTerms"
            ],

        "networkTerms":
            node[
                "networkTerms"
            ],

        "authTerms":
            node[
                "authTerms"
            ],
    })

for node in order_state_nodes:

    paths_order_state.append({

        "path":
            node[
                "path"
            ],

        "target":
            node[
                "name"
            ],

        "offset":
            node[
                "offset"
            ],

        "orderTerms":
            node[
                "orderTerms"
            ],

        "stateTerms":
            node[
                "stateTerms"
            ],

        "networkTerms":
            node[
                "networkTerms"
            ],

        "authTerms":
            node[
                "authTerms"
            ],
    })

# ============================================================
# 13. R -> SPECIFIC PLACE ISOLATED TARGETS
# ============================================================

isolated_nodes = [
    node
    for node in graph.values()
    if node[
        "name"
    ]
    in [
        "placeIsolatedLimitOrder",
        "placeIsolatedMarketOrder",
    ]
]

packet_nodes = [
    node
    for node in graph.values()
    if node[
        "name"
    ]
    in [
        "buildLimitOrderPacket",
        "buildMarketOrderPacket",
        "buildPlaceLimitOrder",
        "buildPlaceMarketOrder",
    ]
]

# ============================================================
# 14. HARD RESULT — NO PROXIMITY-ONLY CLAIM
# ============================================================

has_order_path = (
    len(
        isolated_nodes
    )
    >
    0
)

has_packet_path = (
    len(
        packet_nodes
    )
    >
    0
)

has_order_network = (
    len(
        order_network_nodes
    )
    >
    0
)

has_order_state = (
    len(
        order_state_nodes
    )
    >
    0
)

# ============================================================
# 15. CLASSIFICATION
# ============================================================

if (
    has_order_path
    and
    has_packet_path
    and
    has_order_network
):

    classification = (
        "EXACT_ISOLATED_ORDER_TO_NETWORK_PATH"
    )

elif (
    has_order_path
    and
    has_packet_path
):

    classification = (
        "EXACT_ISOLATED_ORDER_PACKET_PATH"
    )

elif (
    has_order_network
):

    classification = (
        "ORDER_NETWORK_FUNCTION_PATH_FOUND"
    )

elif (
    has_order_state
):

    classification = (
        "ORDER_STATE_PATH_FOUND_NETWORK_UNRESOLVED"
    )

else:

    classification = (
        "ORDER_EXECUTION_PATH_STILL_UNRESOLVED"
    )

# ============================================================
# 16. REPORT
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
                )
        },

    "placeOrder":
        {
            "propertyOffset":
                place_prop.start(),

            "binding":
                binding,

            "rDefinition":
                r_def
        },

    "rCalls":
        r_calls,

    "directResolution":
        direct_resolution,

    "targets":
        target_resolution,

    "graph":
        list(
            graph.values()
        ),

    "orderNamedNodes":
        order_named_nodes,

    "orderNetworkNodes":
        order_network_nodes,

    "orderStateNodes":
        order_state_nodes,

    "orderAuthNodes":
        order_auth_nodes,

    "pathsOrderNetwork":
        paths_order_network,

    "pathsOrderState":
        paths_order_state,

    "pathsOrderAuth":
        paths_order_auth,

    "isolatedNodes":
        isolated_nodes,

    "packetNodes":
        packet_nodes,

    "stateReaders":
        state_readers[:1000],

    "static":
        {
            "processSequenceGuard":
                process_sequence_guard,

            "deltaSequenceGuard":
                delta_sequence_guard,

            "orderSequenceGuard":
                order_sequence_guard,

            "orderReplacement":
                order_replacement,

            "orderCloseDelete":
                order_delete,

            "staleSequenceSurface":
                (
                    not process_sequence_guard
                    and
                    not delta_sequence_guard
                    and
                    not order_sequence_guard
                ),
        },

    "milestone":
        {
            "RResolved":
                True,

            "isolatedFunctionInGraph":
                has_order_path,

            "packetFunctionInGraph":
                has_packet_path,

            "orderNetworkFunction":
                has_order_network,

            "orderStateFunction":
                has_order_state,

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
    "ORDER_EXECUTION_DATAFLOW_v4_7.json"
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

    "R_EXACT.txt":
        r_code,

    "R_CALLS.json":
        r_calls,

    "DIRECT_RESOLUTION.json":
        direct_resolution,

    "GRAPH.json":
        list(
            graph.values()
        ),

    "ORDER_NETWORK.json":
        order_network_nodes,

    "ORDER_STATE.json":
        order_state_nodes,

    "ORDER_AUTH.json":
        order_auth_nodes,

    "ISOLATED.json":
        isolated_nodes,

    "PACKETS.json":
        packet_nodes,

    "PATH_ORDER_NETWORK.json":
        paths_order_network,

    "PATH_ORDER_STATE.json":
        paths_order_state,

    "PATH_ORDER_AUTH.json":
        paths_order_auth,

    "STATIC.json":
        report[
            "static"
        ],
}

for name,obj in exports.items():

    out = (
        CORPUS /
        f"ORDER_EXECUTION_{name}"
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
# PRINT
# ============================================================

print("=" * 115)
print("SANA FORENSICS — ORDER EXECUTION DATAFLOW v4.7")
print("=" * 115)

print()
print("CORE")

print(
    "placeOrder binding:",
    binding
)

print(
    "R offset:",
    r_def[
        "offset"
    ]
)

print(
    "R length:",
    r_def[
        "length"
    ]
)

print()
print("R CALLS")

for x in r_calls:
    print(
        x
    )

print()
print("DIRECT RESOLUTION")

for name,defs in direct_resolution.items():

    if not defs:
        continue

    print()
    print(
        name,
        "defs=",
        len(
            defs
        )
    )

    for d in defs[:3]:

        print(
            "  ",
            d[
                "offset"
            ],
            "len=",
            d[
                "length"
            ]
        )

print()
print("ISOLATED ORDER NODES:",
      len(isolated_nodes))

for node in isolated_nodes:

    print()
    print(
        "NAME:",
        node[
            "name"
        ]
    )

    print(
        "PATH:",
        " -> ".join(
            node[
                "path"
            ]
        )
    )

    print(
        "NETWORK:",
        node[
            "networkTerms"
        ]
    )

    print(
        "STATE:",
        node[
            "stateTerms"
        ]
    )

    print(
        "AUTH:",
        node[
            "authTerms"
        ]
    )

print()
print("PACKET NODES:",
      len(packet_nodes))

for node in packet_nodes:

    print()
    print(
        node[
            "name"
        ],
        "PATH=",
        " -> ".join(
            node[
                "path"
            ]
        )
    )

print()
print("ORDER + NETWORK:", 
      len(order_network_nodes))

for node in order_network_nodes[:80]:

    print()
    print(
        node[
            "name"
        ],
        "PATH=",
        " -> ".join(
            node[
                "path"
            ]
        )
    )

    print(
        "  NETWORK:",
        node[
            "networkTerms"
        ]
    )

    print(
        "  ORDER:",
        node[
            "orderTerms"
        ]
    )

    print(
        "  STATE:",
        node[
            "stateTerms"
        ]
    )

    print(
        "  AUTH:",
        node[
            "authTerms"
        ]
    )

print()
print("ORDER + STATE:",
      len(order_state_nodes))

for node in order_state_nodes[:80]:

    print(
        node[
            "name"
        ],
        "PATH=",
        " -> ".join(
            node[
                "path"
            ]
        ),
        "STATE=",
        node[
            "stateTerms"
        ]
    )

print()
print("ORDER + AUTH:",
      len(order_auth_nodes))

for node in order_auth_nodes[:80]:

    print(
        node[
            "name"
        ],
        "PATH=",
        " -> ".join(
            node[
                "path"
            ]
        ),
        "AUTH=",
        node[
            "authTerms"
        ]
    )

print()
print("STATIC")

print(
    "process sequence guard:",
    process_sequence_guard
)

print(
    "delta sequence guard:",
    delta_sequence_guard
)

print(
    "order sequence guard:",
    order_sequence_guard
)

print(
    "order replacement:",
    order_replacement
)

print(
    "order close delete:",
    order_delete
)

print()
print("MILESTONE")

for k,v in report[
    "milestone"
].items():

    print(
        f"{k:38s}:",
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

