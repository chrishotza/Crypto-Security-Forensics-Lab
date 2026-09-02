from pathlib import Path
import re

ROOT = Path(r"SANA_FORENSICS_ROOT")

FILES = [
    ROOT / "data" / "runtime" / "LIVE_BUNDLE_13.js",
    ROOT / "data" / "runtime" / "LIVE_BUNDLE_01.js",
    ROOT / "data" / "raw" / "sana_bundle.js",
]

TERMS = [
    "effectiveCollateral",
    "maintenanceMargin",
    "initialMargin",
    "limitOrderMargin",
    "riskState",
    "riskTier",
    "capabilities",
    "placeLimitOrder",
    "placeMarketOrder",
    "riskIncreasingTrade",
    "riskReducingTrade",
    "verifyCapabilities",
    "estimatedLiquidationPriceUsd",
    "placeIsolatedLimitOrder",
    "placeIsolatedMarketOrder",
    "/v1/ix/place-isolated-limit-order",
    "/v1/ix/place-isolated-market-order",
]

def compact(s, n=2600):
    s = re.sub(r"\s+", " ", s).strip()
    return s[:n] + (" ...[TRUNCATED]" if len(s) > n else "")

def hits(text, term, limit=20):
    out = []
    p = 0
    while True:
        p = text.find(term, p)
        if p < 0:
            return out
        out.append(p)
        p += len(term)
        if len(out) >= limit:
            return out

def ctx(text, p, before=1100, after=1800):
    a = max(0, p-before)
    b = min(len(text), p+after)
    return compact(text[a:b])

print("=" * 110)
print("SANA FORENSICS — RISK / CAPABILITY BOUNDARY v14.5")
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

        ps = hits(text, term)

        if not ps:
            continue

        print(
            f"  {term}: {len(ps)}"
        )

    print("")

print("=" * 110)
print("HIGH-SIGNAL COLOCATIONS")
print("=" * 110)

for path in FILES:
    if not path.exists():
        continue

    text = path.read_text(
        encoding="utf-8",
        errors="replace"
    )

    anchors = []

    for term in [
        "verifyCapabilities",
        "riskIncreasingTrade",
        "riskReducingTrade",
        "limitOrderMargin",
        "effectiveCollateral",
        "estimatedLiquidationPriceUsd",
    ]:
        for p in hits(text, term, 10):
            anchors.append((p, term))

    for p, term in sorted(anchors):

        region = text[
            max(0,p-2200):
            min(len(text),p+3500)
        ]

        low = region.lower()

        order_terms = [
            "placeisolatedlimitorder",
            "placeisolatedmarketorder",
            "buildplacelimitorder",
            "buildplacemarketorder",
            "/v1/ix/place-isolated",
        ]

        if any(x in low for x in order_terms):

            print("")
            print("BUNDLE:", path)
            print("ANCHOR:", term)
            print("OFFSET:", p)
            print("CONTEXT:")
            print(compact(region, 4200))

print("")
print("=" * 110)
print("END")
print("=" * 110)

