from pathlib import Path
import struct

B=Path(
    r"SANA_FORENSICS_ROOT\data\runtime\phoenix_eternal_deployed.so"
)

data=B.read_bytes()

TEXT=0x120
TARGET=0x1e3ee0

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

# =========================================================
# 1. SEARCH ALL CALLS TO 0x1E3EE0
# =========================================================

target_index=(TARGET-TEXT)//8

print("="*72)
print("PHOENIX 0x1E3EE0 CALLER ANALYSIS V15.92")
print("="*72)
print()

print(f"TARGET ELF  = 0x{TARGET:x}")
print(f"TARGET INDEX = {target_index}")
print()

callers=[]

for a in range(TEXT,len(data)-7,8):

    x=insn(a)

    if x["op"] == 0x85 and x["src"] == 1:

        idx=(a-TEXT)//8
        next_idx=idx+1
        calc=next_idx+x["imm"]

        if calc == target_index:

            callers.append(a)

print("CALLERS:")
print()

print(f"COUNT = {len(callers)}")
print()

for a in callers:

    print(f"CALLER = 0x{a:x}")

    start=max(TEXT,a-0x80)
    end=min(len(data)-8,a+0x10)

    for p in range(start,end,8):
        show(p)

    print()
    
# =========================================================
# 2. FUNCTION ENTRY CONTEXT
# =========================================================

print("="*72)
print("0x1E3EE0 ENTRY CONTEXT")
print("="*72)
print()

for a in range(
    TARGET,
    TARGET+0x80,
    8
):
    show(a)

print()

# =========================================================
# 3. DATA OFFSETS USED BY THE FUNCTION
# =========================================================

print("="*72)
print("STRUCTURE OFFSETS USED BY 0x1E3EE0")
print("="*72)
print()

for a in range(
    TARGET,
    TARGET+0x80,
    8
):

    x=insn(a)

    # Register-memory operations.
    if x["op"] in (
        0x61, 0x69, 0x71, 0x79,
        0x63, 0x6b, 0x73, 0x7b
    ):

        print(
            f"0x{a:x}: "
            f"OP=0x{x['op']:02x} "
            f"dst=r{x['dst']} "
            f"src=r{x['src']} "
            f"off={x['off']}"
        )

print()

# =========================================================
# 4. LOG DATA POINTER
# =========================================================

# From V15.91:
# 0x1E3F08 loads:
#   r1 = r0 + 2830996
#
# Compute its VM/ELF-relative address.

LOG_OFFSET=2830996
LOG_ADDR=TEXT+LOG_OFFSET

print("="*72)
print("LOG POINTER")
print("="*72)
print()

print(f"IMM = {LOG_OFFSET}")
print(f"TEXT + IMM = 0x{LOG_ADDR:x}")

# Give surrounding raw bytes for manual string inspection.
start=max(0,LOG_ADDR-64)
end=min(len(data),LOG_ADDR+128)

raw=data[start:end]

print()
print("RAW:")
print(raw.hex())

try:
    print()
    print("ASCII:")
    print(
        ''.join(
            chr(b) if 32 <= b < 127 else '.'
            for b in raw
        )
    )
except:
    pass

print()
print("="*72)
print("V15.92 COMPLETE")
print("="*72)

