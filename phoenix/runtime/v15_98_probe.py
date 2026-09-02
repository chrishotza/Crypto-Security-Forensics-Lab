from pathlib import Path
import struct

B=Path(
    r"SANA_FORENSICS_ROOT\data\runtime\phoenix_eternal_deployed.so"
)

data=B.read_bytes()

TEXT=0x120

def insn(a):
    b=data[a:a+8]

    return {
        "addr":a,
        "bytes":b.hex(),
        "op":b[0],
        "dst":b[1]&15,
        "src":(b[1]>>4)&15,
        "off":struct.unpack_from("<h",b,2)[0],
        "imm":struct.unpack_from("<i",b,4)[0],
    }

def show(a):
    x=insn(a)

    print(
        f"0x{a:x}: {x['bytes']} "
        f"OP=0x{x['op']:02x} "
        f"dst=r{x['dst']} src=r{x['src']} "
        f"off={x['off']} imm={x['imm']}"
    )

print("="*72)
print("PHOENIX TWO-SLOT OBJECT ANALYSIS V15.98")
print("="*72)
print()

BASE=0x2000000000
FIELD0=BASE
FIELD8=BASE+8

print("RUNTIME OBJECT")
print(f"  BASE    = 0x{BASE:x}")
print(f"  FIELD+0 = 0x{FIELD0:x}")
print(f"  FIELD+8 = 0x{FIELD8:x}")
print()

print("KNOWN RUNTIME VALUES")
print("  FIELD+0 = 0x4000000010")
print("  FIELD+8 = 0x0000000000000000")
print()

# =========================================================
# SEARCH ALL STATIC MEMORY REFERENCES TO THESE OFFSETS
# =========================================================

print("="*72)
print("STATIC REFERENCES TO [r10-4096] / [r10-4088]")
print("="*72)
print()

for a in range(0x120,0x4000,8):

    x=insn(a)

    # r10-4096 or r10-4088
    if x["src"] == 10 and x["off"] in (-4096,-4088):

        show(a)

    if x["dst"] == 10 and x["off"] in (-4096,-4088):

        show(a)

print()

# =========================================================
# SEARCH NEAR CALLER FOR DIRECT USES
# =========================================================

print("="*72)
print("CALLER WINDOW 0x220-0x330")
print("="*72)
print()

for a in range(0x220,0x330,8):
    show(a)

# =========================================================
# SEARCH CALLEE FOR r5 RELATIVE USES
# =========================================================

print()
print("="*72)
print("CALLEE WINDOW 0x1E3EE0-0x1E40A0")
print("="*72)
print()

for a in range(0x1e3ee0,0x1e40a0,8):
    show(a)

print()
print("="*72)
print("V15.98 COMPLETE")
print("="*72)

