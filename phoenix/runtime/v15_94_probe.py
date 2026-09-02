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

def idx(a):
    return (a-TEXT)//8

def show(a):
    x=insn(a)
    print(
        f"0x{a:x}: {x['bytes']} "
        f"OP=0x{x['op']:02x} "
        f"dst=r{x['dst']} src=r{x['src']} "
        f"off={x['off']} imm={x['imm']}"
    )

# ---------------------------------------------------------
# BRANCH ORIGIN
# ---------------------------------------------------------

BR=0x1e3f00
x=insn(BR)

i=idx(BR)
target_index=i+1+x["off"]
target=TEXT+target_index*8

fallthrough=BR+8

print("="*72)
print("PHOENIX BRANCH DIVERGENCE V15.94")
print("="*72)
print()

print("BRANCH")
print(f"  ELF PC       = 0x{BR:x}")
print(f"  INDEX        = {i}")
print(f"  OPCODE       = 0x{x['op']:02x}")
print(f"  DST          = r{x['dst']}")
print(f"  OFF          = {x['off']}")
print(f"  IMM          = {x['imm']}")
print()

print("TARGET")
print(f"  INDEX        = {target_index}")
print(f"  ELF PC       = 0x{target:x}")

print()

print("FALLTHROUGH")
print(f"  ELF PC       = 0x{fallthrough:x}")

# ---------------------------------------------------------
# PATH A: FALLTHROUGH
# ---------------------------------------------------------

print()
print("="*72)
print("PATH A — FALLTHROUGH (CURRENT RUNTIME PATH)")
print("="*72)
print()

for a in range(
    fallthrough,
    0x1e3f38,
    8
):
    show(a)

# ---------------------------------------------------------
# PATH B: BRANCH TARGET
# ---------------------------------------------------------

print()
print("="*72)
print("PATH B — BRANCH TARGET")
print("="*72)
print()

for a in range(
    target,
    target+0x80,
    8
):
    show(a)

# ---------------------------------------------------------
# SEARCH FOR r9 WRITES IN BOTH PATHS
# ---------------------------------------------------------

print()
print("="*72)
print("r9 WRITERS IN PATH A")
print("="*72)
print()

for a in range(fallthrough,0x1e3f38,8):

    x=insn(a)

    if x["dst"]==9:
        show(a)

print()
print("="*72)
print("r9 WRITERS IN PATH B")
print("="*72)
print()

for a in range(target,target+0x80,8):

    x=insn(a)

    if x["dst"]==9:
        show(a)

print()
print("="*72)
print("V15.94 COMPLETE")
print("="*72)

