#!/usr/bin/env python3
"""Read-only ARM64 Mach-O disassembly with script.json annotations; no live APIs."""
import json, struct, pathlib, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
ROOT = pathlib.Path('/Users/mac/Desktop/RR02')
BIN = pathlib.Path('/tmp/GameAssembly_thin.dylib')
data = BIN.read_bytes()
assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
ncmds = struct.unpack_from('<I', data, 16)[0]
segments = []
off = 32
for _ in range(ncmds):
    cmd, size = struct.unpack_from('<II', data, off)
    if cmd == 0x19:
        name, va, vs, fo, fs = struct.unpack_from('<16sQQQQ', data, off+8)
        segments.append((name.rstrip(b'\0').decode(), va, vs, fo, fs))
    off += size
meta = json.loads((ROOT/'dump/macos_dump_2026/script.json').read_text())
names = {}
for key in ('ScriptMethod', 'ScriptMetadata', 'ScriptMetadataMethod'):
    for row in meta[key]:
        names.setdefault(row['Address'], []).append(row.get('Name', str(row)))
def read(va, size):
    for _, a, _, f, s in segments:
        if a <= va and va+size <= a+s:
            return data[f+va-a:f+va-a+size]
    raise ValueError(hex(va))
def dis(start, size):
    print('\nFUNCTION', hex(start), names.get(start, []))
    regs = {}
    for i in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(read(start,size), start):
        annotation = []
        ops = i.op_str.split(', ')
        if i.mnemonic == 'adrp':
            regs[ops[0]] = int(ops[1].lstrip('#'), 0)
        elif i.mnemonic == 'add' and len(ops)==3 and ops[1] in regs and ops[2].startswith('#'):
            regs[ops[0]] = regs[ops[1]] + int(ops[2].lstrip('#'), 0)
            annotation += [hex(regs[ops[0]])] + names.get(regs[ops[0]], [])
        elif i.mnemonic == 'ldr' and len(ops)>=2 and ops[1].startswith('['):
            base = ops[1].strip('[]')
            imm = int(ops[2].strip('#]'),0) if len(ops)==3 and ops[2].startswith('#') else 0
            if base in regs:
                addr = regs[base]+imm
                annotation += ['slot '+hex(addr)] + names.get(addr, [])
            regs.pop(ops[0], None)
        elif i.mnemonic in ('bl','b') and ops[0].startswith('#'):
            annotation += names.get(int(ops[0][1:], 0), [])
            if i.mnemonic == 'bl':
                for r in range(19): regs.pop('x'+str(r),None)
        print(f'{i.address:09x}: {i.mnemonic:8} {i.op_str:44} '+ (' ; '+' | '.join(annotation) if annotation else ''))
if __name__ == '__main__':
    print('BINARY', BIN, 'segments', segments)
    for arg in sys.argv[1:]:
        a, _, n = arg.partition(':')
        dis(int(a,0), int(n,0) if n else 0x200)
