from pathlib import Path
import re

ROOT = Path(r"SANA_FORENSICS_ROOT")

FILES = [
    ROOT / "data" / "runtime" / "LIVE_BUNDLE_13.js",
    ROOT / "data" / "runtime" / "LIVE_BUNDLE_01.js",
    ROOT / "data" / "raw" / "sana_bundle.js",
]

TERMS = [
    "verifyCapabilities",
    ".capabilities",
    "capabilities.placeLimitOrder",
    "capabilities.placeMarketOrder",
    "capabilities.riskIncreasingTrade",
    "capabilities.riskReducingTrade",
    "placeLimitOrder.immediate",
    "placeMarketOrder.immediate",
    "riskIncreasingTrade.immediate",
    "riskReducingTrade.immediate",
]

def compact(s, n=3200):
    s = re.sub(r"\s+", " ", s).strip()
    return s[:n] + (" ...[TRUNCATED]" if len(s) > n else "")

def find(text, term, limit=30):
    out = []
    p = 0

    while True:
        p = text.find(term, p)

        if p < 0:
            break

        out.append(p)
        p += len(term)

        if len(out) >= limit:
            break

    return out

def context(text, pos, before=1000, after=1800):
    a = max(0, pos-before)
    b = min(len(text), pos+after)

    return compact(text[a:b])

print("=" * 110)
print("SANA FORENSICS — CAPABILITY GATE v14.6")
print("=" * 110)
print("")

for path in FILES:

    if not path.exists():
        continue

    text = path.read_text(
        encoding="utf-8",
        errors="replace"
    )

    print("BUNDLE:", path)

    for term in TERMS:

        hits = find(text, term)

        if hits:
            print(
                f"  {term}: {len(hits)}"
            )

    # ------------------------------------------------------
    # Call-like uses only
    # ------------------------------------------------------

    call_patterns = [
        r"\.verifyCapabilities\s*\(",
        r"\bverifyCapabilities\s*\(",
        r"\.capabilities\.[A-Za-z_$][A-Za-z0-9_$]*",
    ]

    candidates = set()

    for pattern in call_patterns:

        for m in re.finditer(
            pattern,
            text
        ):

            candidates.add(
                m.start()
            )

    print("")
    print("CALL-LIKE / PROPERTY USES:")

    shown = 0

    for pos in sorted(candidates):

        ctx = context(
            text,
            pos
        )

        low = ctx.lower()

        # Exclude the pure schema declaration region where possible.
        security_words = [
            "placeorder",
            "buildplace",
            "placeisolated",
            "withdraw",
            "deposit",
            "riskincreasing",
            "riskreducing",
            "traderstate",
            "collateral",
            "margin",
        ]

        signal = sum(
            word in low
            for word in security_words
        )

        if signal < 1:
            continue

        print("")
        print(
            "OFFSET:",
            pos,
            "SIGNAL:",
            signal
        )
        print(ctx)

        shown += 1

        if shown >= 10:
            break

print("")
print("=" * 110)
print("END")
print("=" * 110)

