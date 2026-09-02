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
    end = min(
        len(source),
        start + limit
    )

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

def ctx(source, pos, before=2500, after=5000):
    return compact(
        source[
            max(0, pos-before):
            min(len(source), pos+after)
        ]
    )

# ============================================================
# 1. EXACT placeOrder EXPORT
# ============================================================

prop = re.search(
    r"\bplaceOrder\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)",
    text
)

if not prop:
    raise RuntimeError(
        "placeOrder export no encontrado"
    )

binding = prop.group(1)
export_offset = prop.start()

# ============================================================
# 2. IDENTIFICAR EL MODULO QUE CONTIENE placeOrder:R
# ============================================================

module_start_candidates = []

patterns = [
    r"\b\d+:\(e,t,r\)=>\{",
    r"\b\d+:\(e,t\)=>\{",
    r"\b\d+:\([^)]*\)=>\{",
    r"\b\d+\s*:\s*function\([^)]*\)\{",
]

for pattern in patterns:

    for m in re.finditer(
        pattern,
        text[:export_offset]
    ):

        module_start_candidates.append(
            m
        )

if module_start_candidates:

    module_start_match = module_start_candidates[-1]

    module_start = module_start_match.start()

else:

    module_start = max(
        0,
        export_offset - 50000
    )

# ============================================================
# 3. MODULE WINDOW
# ============================================================

module_end = min(
    len(text),
    export_offset + 20000
)

module_code = text[
    module_start:
    module_end
]

# ============================================================
# 4. TODAS LAS DEFINICIONES DE R
# ============================================================

definitions = []

definition_patterns = [

    rf"\b{re.escape(binding)}\s*=\s*",

    rf"\b{re.escape(binding)}\s*:\s*",

    rf"\bconst\s+{re.escape(binding)}\b",

    rf"\blet\s+{re.escape(binding)}\b",

    rf"\bvar\s+{re.escape(binding)}\b",

    rf"\bfunction\s+{re.escape(binding)}\s*\(",
]

seen = set()

for pattern in definition_patterns:

    for m in re.finditer(
        pattern,
        module_code
    ):

        abs_pos = (
            module_start
            +
            m.start()
        )

        if abs_pos in seen:
            continue

        seen.add(
            abs_pos
        )

        raw = balanced(
            text,
            abs_pos,
            "{",
            150000
        )

        if not raw:
            continue

        code = compact(
            raw
        )

        definitions.append({

            "offset":
                abs_pos,

            "length":
                len(raw),

            "definition":
                m.group(0),

            "code":
                code
        })

# ============================================================
# 5. CALLS TO R WITHIN SAME MODULE
# ============================================================

r_calls = []

for m in re.finditer(
    rf"\b{re.escape(binding)}\s*\(",
    module_code
):

    abs_pos = (
        module_start
        +
        m.start()
    )

    r_calls.append({

        "offset":
            abs_pos,

        "context":
            ctx(
                text,
                abs_pos,
                5000,
                8000
            )
    })

# ============================================================
# 6. CHOOSE R DEFINITION:
#    same module + actual order fields + exported usage
# ============================================================

for d in definitions:

    code = d[
        "code"
    ]

    score = 0

    for token in [
        "symbol",
        "side",
        "price",
        "priceUsd",
        "sizeUsd",
        "reduceOnly",
        "leverage",
        "orderType",
        "subaccountIndex",
    ]:

        if re.search(
            rf"\b{re.escape(token)}\b",
            code,
            flags=re.I
        ):

            score += 2

    for token in [
        "sign",
        "sessionManager",
        "wallet",
        "transaction",
        "request",
        "send",
        "rpc",
        "fetch",
    ]:

        if re.search(
            rf"\b{re.escape(token)}\b",
            code,
            flags=re.I
        ):

            score += 3

    d[
        "score"
    ] = score

definitions.sort(
    key=lambda x: (
        x["score"],
        x["length"]
    ),
    reverse=True
)

if not definitions:

    raise RuntimeError(
        "No se encontró definición local de R"
    )

r_definition = definitions[0]
r_code = r_definition[
    "code"
]

# ============================================================
# 7. IDENTIFICAR TODOS LOS IDENTIFICADORES LLAMADOS POR R
# ============================================================

JS_RESERVED = {
    "if","else","for","while","do","switch","case","break",
    "continue","return","throw","try","catch","finally",
    "new","typeof","void","delete","in","instanceof",
    "await","async","yield","this","true","false","null",
    "undefined","class","extends","super","import","export",
    "const","let","var","function"
}

called_identifiers = []

# normal function calls: foo(
for m in re.finditer(
    r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
    r_code
):

    name = m.group(1)

    if name in JS_RESERVED:
        continue

    if name == binding:
        continue

    called_identifiers.append({
        "name":
            name,

        "offset":
            m.start(),

        "syntax":
            "direct"
    })

# property calls: obj.foo(
for m in re.finditer(
    r"\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
    r_code
):

    name = m.group(1)

    if name in JS_RESERVED:
        continue

    called_identifiers.append({
        "name":
            name,

        "offset":
            m.start(),

        "syntax":
            "property"
    })

# unique names
unique_called = {}

for item in called_identifiers:

    key = item["name"]

    if key not in unique_called:
        unique_called[key] = item

called_identifiers = list(
    unique_called.values()
)

# ============================================================
# 8. RESOLVE LOCAL DEFINITIONS OF CALLED IDENTIFIERS
# ============================================================

resolved_calls = []

for item in called_identifiers:

    name = item[
        "name"
    ]

    candidates = []

    patterns = [

        rf"\b{re.escape(name)}\s*=\s*",

        rf"\b{re.escape(name)}\s*:\s*",

        rf"\bconst\s+{re.escape(name)}\b",

        rf"\blet\s+{re.escape(name)}\b",

        rf"\bvar\s+{re.escape(name)}\b",

        rf"\bfunction\s+{re.escape(name)}\s*\(",
    ]

    for pattern in patterns:

        for m in re.finditer(
            pattern,
            module_code
        ):

            abs_pos = (
                module_start
                +
                m.start()
            )

            raw = balanced(
                text,
                abs_pos,
                "{",
                120000
            )

            if not raw:
                continue

            code = compact(
                raw
            )

            score = 0

            for token in [
                "order",
                "orders",
                "perp",
                "position",
                "transaction",
                "request",
                "fetch",
                "rpc",
                "send",
                "sign",
                "sessionManager",
                "wallet",
                "collateral",
                "margin",
                "sequence",
                "subaccount",
            ]:

                if re.search(
                    rf"\b{re.escape(token)}\b",
                    code,
                    flags=re.I
                ):

                    score += 1

            candidates.append({

                "offset":
                    abs_pos,

                "definition":
                    m.group(0),

                "length":
                    len(raw),

                "score":
                    score,

                "code":
                    code
            })

    candidates.sort(
        key=lambda x: (
            x["score"],
            x["length"]
        ),
        reverse=True
    )

    resolved_calls.append({

        "name":
            name,

        "syntax":
            item[
                "syntax"
            ],

        "callOffset":
            item[
                "offset"
            ],

        "definitions":
            candidates[:5]
    })

# ============================================================
# 9. BUILD 2-HOP / 3-HOP CALL GRAPH
# ============================================================

def extract_calls(code):

    names = set()

    for m in re.finditer(
        r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
        code
    ):

        name = m.group(1)

        if name not in JS_RESERVED:
            names.add(
                name
            )

    for m in re.finditer(
        r"\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
        code
    ):

        names.add(
            m.group(1)
        )

    return sorted(
        names
    )

def best_definition(
    name
):

    candidates = []

    patterns = [

        rf"\b{re.escape(name)}\s*=\s*",

        rf"\b{re.escape(name)}\s*:\s*",

        rf"\bconst\s+{re.escape(name)}\b",

        rf"\blet\s+{re.escape(name)}\b",

        rf"\bvar\s+{re.escape(name)}\b",

        rf"\bfunction\s+{re.escape(name)}\s*\(",
    ]

    for pattern in patterns:

        for m in re.finditer(
            pattern,
            module_code
        ):

            abs_pos = (
                module_start
                +
                m.start()
            )

            raw = balanced(
                text,
                abs_pos,
                "{",
                120000
            )

            if not raw:
                continue

            code = compact(
                raw
            )

            score = sum(
                1
                for token
                in [
                    "order",
                    "position",
                    "perp",
                    "transaction",
                    "request",
                    "fetch",
                    "rpc",
                    "send",
                    "sign",
                    "sessionManager",
                    "wallet",
                    "margin",
                    "collateral",
                ]
                if re.search(
                    rf"\b{re.escape(token)}\b",
                    code,
                    flags=re.I
                )
            )

            candidates.append({

                "offset":
                    abs_pos,

                "definition":
                    m.group(0),

                "length":
                    len(raw),

                "score":
                    score,

                "code":
                    code
            })

    if not candidates:
        return None

    candidates.sort(
        key=lambda x: (
            x["score"],
            x["length"]
        ),
        reverse=True
    )

    return candidates[0]

# BFS limited to 3 hops
graph = {
    binding: {
        "offset":
            r_definition[
                "offset"
            ],

        "length":
            r_definition[
                "length"
            ],

        "calls":
            []
    }
}

frontier = [
    (
        binding,
        r_code,
        0
    )
]

visited = {
    binding
}

while frontier:

    name, code, depth = (
        frontier.pop(0)
    )

    if depth >= 3:
        continue

    calls = extract_calls(
        code
    )

    graph.setdefault(
        name,
        {}
    )

    graph[
        name
    ][
        "calls"
    ] = calls

    for called in calls:

        if called in JS_RESERVED:
            continue

        if called == name:
            continue

        if called in visited:
            continue

        if called in [
            "log",
            "error",
            "warn",
            "map",
            "filter",
            "reduce",
            "flatMap",
            "push",
            "pop",
            "slice",
            "join",
            "stringify",
            "parse",
            "assign",
            "keys",
            "values",
            "from",
            "isArray",
        ]:
            continue

        definition = best_definition(
            called
        )

        if not definition:
            continue

        visited.add(
            called
        )

        graph[
            called
        ] = {

            "offset":
                definition[
                    "offset"
                ],

            "length":
                definition[
                    "length"
                ],

            "score":
                definition[
                    "score"
                ],

            "calls":
                []
        }

        frontier.append(
            (
                called,
                definition[
                    "code"
                ],
                depth + 1
            )
        )

# ============================================================
# 10. FLAG NETWORK / AUTH / ORDER / STATE HOPS
# ============================================================

NETWORK_TERMS = [
    "fetch",
    "request",
    "rpc",
    "post",
    "send",
    "submit",
    "execute",
    "mutate",
    "sendTransaction",
    "signAndSend",
    "broadcast",
]

ORDER_TERMS = [
    "order",
    "orders",
    "placeOrder",
    "cancelOrder",
    "modifyOrder",
    "perp",
    "position",
    "reduceOnly",
    "leverage",
    "price",
    "size",
    "side",
]

STATE_TERMS = [
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

AUTH_TERMS = [
    "sessionManager",
    "knownAuthToken",
    "wallet",
    "sign",
    "transaction",
    "sendTransaction",
    "signAndSend",
]

for name, node in graph.items():

    code = ""

    if name == binding:
        code = r_code
    else:
        d = best_definition(
            name
        )
        if d:
            code = d[
                "code"
            ]

    node[
        "networkTerms"
    ] = [
        x
        for x in NETWORK_TERMS
        if re.search(
            rf"\b{re.escape(x)}\b",
            code,
            flags=re.I
        )
    ]

    node[
        "orderTerms"
    ] = [
        x
        for x in ORDER_TERMS
        if re.search(
            rf"\b{re.escape(x)}\b",
            code,
            flags=re.I
        )
    ]

    node[
        "stateTerms"
    ] = [
        x
        for x in STATE_TERMS
        if re.search(
            rf"\b{re.escape(x)}\b",
            code,
            flags=re.I
        )
    ]

    node[
        "authTerms"
    ] = [
        x
        for x in AUTH_TERMS
        if re.search(
            rf"\b{re.escape(x)}\b",
            code,
            flags=re.I
        )
    ]

# ============================================================
# 11. EXACT PATHS R -> NETWORK
# ============================================================

def find_paths(
    start,
    target_terms,
    max_depth=3
):

    results = []

    def walk(
        name,
        path,
        depth
    ):

        if depth > max_depth:
            return

        node = graph.get(
            name
        )

        if not node:
            return

        if any(
            term
            in
            node.get(
                "networkTerms",
                []
            )
            for term
            in
            target_terms
        ):

            results.append(
                path + [name]
            )

        for child in node.get(
            "calls",
            []
        ):

            if child in path:
                continue

            walk(
                child,
                path + [name],
                depth + 1
            )

    walk(
        start,
        [],
        0
    )

    return results

network_paths = find_paths(
    binding,
    NETWORK_TERMS,
    3
)

# ============================================================
# 12. AUTHENTICATED NETWORK PATHS
# ============================================================

def path_nodes(path):

    return [
        graph[
            x
        ]
        for x in path
        if x in graph
    ]

authenticated_paths = []

for path in network_paths:

    nodes = path_nodes(
        path
    )

    all_auth = set()
    all_order = set()
    all_state = set()
    all_network = set()

    for node in nodes:

        all_auth.update(
            node.get(
                "authTerms",
                []
            )
        )

        all_order.update(
            node.get(
                "orderTerms",
                []
            )
        )

        all_state.update(
            node.get(
                "stateTerms",
                []
            )
        )

        all_network.update(
            node.get(
                "networkTerms",
                []
            )
        )

    if (
        all_auth
        and
        all_order
        and
        all_network
    ):

        authenticated_paths.append({

            "path":
                path,

            "auth":
                sorted(
                    all_auth
                ),

            "order":
                sorted(
                    all_order
                ),

            "state":
                sorted(
                    all_state
                ),

            "network":
                sorted(
                    all_network
                )
        })

# ============================================================
# 13. EXACT STATE PARAMETERS IN R
# ============================================================

r_state_refs = []

for token in STATE_TERMS:

    for m in re.finditer(
        rf"\b{re.escape(token)}\b",
        r_code,
        flags=re.I
    ):

        r_state_refs.append({

            "token":
                token,

            "offset":
                m.start(),

            "context":
                compact(
                    r_code[
                        max(
                            0,
                            m.start()-800
                        ):
                        min(
                            len(r_code),
                            m.start()+1200
                        )
                    ]
                )
        })

# ============================================================
# 14. EXACT IMPORTANT STRINGS INSIDE R
# ============================================================

important_strings = []

for m in re.finditer(
    r"""(["'])(.{1,160}?)(\1)""",
    r_code
):

    value = m.group(2)

    if any(
        x.lower()
        in value.lower()
        for x in [
            "order",
            "perp",
            "position",
            "trade",
            "cancel",
            "modify",
            "rpc",
            "http",
            "api",
            "withdraw",
        ]
    ):

        important_strings.append({

            "offset":
                m.start(),

            "value":
                value
        })

# ============================================================
# 15. FINAL STATIC CLASSIFICATION
# ============================================================

classification = (
    "R_TO_NETWORK_AUTH_ORDER_PATH_FOUND"
    if authenticated_paths
    else
    "R_TO_NETWORK_ORDER_PATH_FOUND"
    if network_paths
    else
    "R_ORDER_CONSTRUCTION_ONLY_NETWORK_UNRESOLVED"
)

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

    "placeOrderExport": {

        "offset":
            export_offset,

        "binding":
            binding
    },

    "module": {

        "start":
            module_start,

        "end":
            module_end,

        "length":
            len(module_code)
    },

    "R": {

        "definition":
            r_definition,

        "calls":
            r_calls,

        "stateRefs":
            r_state_refs,

        "importantStrings":
            important_strings
    },

    "definitions":
        definitions,

    "calledIdentifiers":
        resolved_calls,

    "graph":
        graph,

    "networkPaths":
        network_paths,

    "authenticatedPaths":
        authenticated_paths,

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
            False
    }
}

report_path = (
    REPORTS /
    "PLACEORDER_CALLGRAPH_EXACT_v4_4.json"
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

files = {

    "R_EXACT.txt":
        r_code,

    "R_CALLS.json":
        r_calls,

    "R_STATE_REFS.json":
        r_state_refs,

    "R_CALLED_IDENTIFIERS.json":
        resolved_calls,

    "R_CALLGRAPH.json":
        graph,

    "R_NETWORK_PATHS.json":
        network_paths,

    "R_AUTHENTICATED_PATHS.json":
        authenticated_paths,

    "R_IMPORTANT_STRINGS.json":
        important_strings,
}

for name, obj in files.items():

    path = (
        CORPUS /
        f"PLACEORDER_{name}"
    )

    if isinstance(
        obj,
        str
    ):

        path.write_text(
            obj,
            encoding="utf-8"
        )

    else:

        path.write_text(
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
print("SANA FORENSICS — PLACEORDER CALLGRAPH EXACT v4.4")
print("=" * 115)

print()
print("PLACEORDER")

print(
    "binding:",
    binding
)

print(
    "export offset:",
    export_offset
)

print(
    "module start:",
    module_start
)

print(
    "module length:",
    len(module_code)
)

print()
print("R DEFINITION")

print(
    "offset:",
    r_definition[
        "offset"
    ]
)

print(
    "length:",
    r_definition[
        "length"
    ]
)

print(
    "score:",
    r_definition[
        "score"
    ]
)

print()
print("R STATE REFS")

for item in r_state_refs:

    print(
        item[
            "token"
        ],
        "@",
        item[
            "offset"
        ]
    )

print()
print("R CALLS")

for item in r_calls:

    print(
        item[
            "offset"
        ]
    )

print()
print("CALLED IDENTIFIERS")

for item in resolved_calls:

    print()
    print(
        item[
            "name"
        ],
        "syntax=",
        item[
            "syntax"
        ]
    )

    for d in item[
        "definitions"
    ][:2]:

        print(
            "  DEF",
            d[
                "offset"
            ],
            "score=",
            d[
                "score"
            ],
            "len=",
            d[
                "length"
            ]
        )

print()
print("CALL GRAPH")

for name, node in graph.items():

    print()
    print(
        name,
        "@",
        node.get(
            "offset"
        )
    )

    print(
        "  calls:",
        node.get(
            "calls",
            []
        )
    )

    print(
        "  network:",
        node.get(
            "networkTerms",
            []
        )
    )

    print(
        "  order:",
        node.get(
            "orderTerms",
            []
        )
    )

    print(
        "  state:",
        node.get(
            "stateTerms",
            []
        )
    )

    print(
        "  auth:",
        node.get(
            "authTerms",
            []
        )
    )

print()
print("NETWORK PATHS")

for path in network_paths:

    print(
        " -> ".join(path)
    )

print()
print("AUTHENTICATED ORDER PATHS")

for item in authenticated_paths:

    print(
        " -> ".join(
            item[
                "path"
            ]
        )
    )

    print(
        "  ORDER:",
        item[
            "order"
        ]
    )

    print(
        "  STATE:",
        item[
            "state"
        ]
    )

    print(
        "  AUTH:",
        item[
            "auth"
        ]
    )

    print(
        "  NETWORK:",
        item[
            "network"
        ]
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

