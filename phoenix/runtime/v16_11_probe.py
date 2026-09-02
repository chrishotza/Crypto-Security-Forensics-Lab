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
print("PHOENIX ENTRY DISCRIMINATOR PATH ANALYSIS V16.11")
print("="*72)
print()

# =========================================================
# BRANCH AT 0x138
# =========================================================

a=0x138
x=insn(a)

idx=(a-TEXT)//8
target_idx=idx+1+x["off"]
target=TEXT+target_idx*8
fallthrough=a+8

print("BRANCH @ 0x138")
print(
    f"  opcode=0x{x['op']:02x} "
    f"dst=r{x['dst']} "
    f"imm={x['imm']} "
    f"off={x['off']}"
)
print(f"  TARGET      = 0x{target:x}")
print(f"  FALLTHROUGH = 0x{fallthrough:x}")
print()

# =========================================================
# TAKEN PATH
# =========================================================

print("="*72)
print("TAKEN PATH 0x228 - 0x280")
print("="*72)
print()

for p in range(0x228,0x288,8):
    show(p)

# =========================================================
# OTHER PATH
# =========================================================

print()
print("="*72)
print("FALLTHROUGH PATH 0x140 - 0x220")
print("="*72)
print()

for p in range(0x140,0x228,8):
    show(p)

# =========================================================
# ALL IMMEDIATE COMPARISONS IN ENTRY
# =========================================================

print()
print("="*72)
print("ENTRY COMPARISONS")
print("="*72)
print()

for p in range(0x120,0x228,8):

    x=insn(p)

    if x["op"] in (
        0x15,0x25,0x35,0x45,
        0x55,0x65,0x75
    ):
        show(p)

print()
print("="*72)
print("V16.11 COMPLETE")
print("="*72)

