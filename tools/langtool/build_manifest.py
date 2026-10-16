"""Analysis-time patch generator; requires Capstone and pefile."""

from collections import deque
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from ui_patches import apply as apply_ui

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_ESP, X86_REG_EAX
import pefile

ROOT = Path(__file__).parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("input", type=Path, help="Original langtool.exe")
parser.add_argument("output", type=Path, help="Generated patch manifest")
parser.add_argument("--work-dir", type=Path, required=True, help="Directory for compiled helpers")
args = parser.parse_args()
SOURCE = args.input
original = SOURCE.read_bytes()
expected_hash = "b51d99260742857c454a7f4d67a029dd2fb4f9e7200ebda0c9a965860b7911ba"
if hashlib.sha256(original).hexdigest() != expected_hash:
    parser.error("Unsupported original executable SHA-256")
args.work_dir.mkdir(parents=True, exist_ok=True)
pe = pefile.PE(data=original)
decoder = Cs(CS_ARCH_X86, CS_MODE_32)
decoder.detail = True
decoder.skipdata = True
instructions = {
    i.address: i for i in decoder.disasm(
        pe.sections[0].get_data()[:pe.sections[0].Misc_VirtualSize], 0x401000
    ) if i.id
}
function_entries = sorted({
    operand.imm for instruction in instructions.values()
    if instruction.mnemonic == "call"
    for operand in instruction.operands if operand.type == X86_OP_IMM
    if 0x401000 <= operand.imm < 0x401000 + pe.sections[0].Misc_VirtualSize
})
patches = {}
reasons = {}
DATA_BASE = 0x728000
UI_DATA_BASE = 0x751000
CODE_BASE = UI_DATA_BASE + 11 * 65536
TEXT_CAPACITY = 32768
GUARD_STATE = DATA_BASE + TEXT_CAPACITY * 5
code = bytearray()
scratch = [
    (0x4BF130, 552, DATA_BASE),
    (0x4BF388, 552, DATA_BASE + TEXT_CAPACITY),
    (0x4BF5D8, 552, DATA_BASE + TEXT_CAPACITY * 2),
    (0x4BF828, 552, DATA_BASE + TEXT_CAPACITY * 3),
    (0x4BEB78, 552, DATA_BASE + TEXT_CAPACITY * 4),
]


def put(address, value, reason):
    offset = pe.get_offset_from_rva(address - 0x400000)
    for index, byte in enumerate(value):
        point = offset + index
        if point in patches and patches[point] != byte:
            raise ValueError(f"Conflicting patch at {point:x}: {reasons[point]} / {reason}")
        patches[point] = byte
        reasons[point] = reason


def number(address, size, value, reason):
    put(address, (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little"), reason)


def replacement(start, end, value, reason):
    assert len(value) <= end - start
    offset = pe.get_offset_from_rva(start - 0x400000)
    for point in range(offset, offset + end - start):
        patches.pop(point, None)
        reasons.pop(point, None)
    put(start, value + b"\x90" * (end - start - len(value)), reason)


def immediate(address, value, reason):
    instruction = instruction_at(address)
    number(address + instruction.imm_offset, instruction.imm_size, value, reason)


def relocate(value):
    if value == 0x4BF386:
        return DATA_BASE + TEXT_CAPACITY - 2
    for old, size, new in scratch:
        if old <= value < old + size:
            return new + value - old
    return value


def instruction_at(address):
    instruction = instructions.get(address)
    if instruction is None and 0x401000 <= address < 0x401000 + pe.sections[0].Misc_VirtualSize:
        decoded = next(decoder.disasm(pe.get_data(address - 0x400000, 15), address, count=1), None)
        if decoded is not None and decoded.id:
            instructions[address] = decoded
            instruction = decoded
    if instruction is None:
        raise ValueError(f"Cannot decode instruction at {address:#x}")
    return instruction


def probe(size):
    # Probe each crossed page without changing incoming registers. The final
    # indirect jump consumes the call-site return address without using a GPR.
    address = CODE_BASE + len(code)
    body = (
        b"\x50\x51"                         # push eax; push ecx
        b"\x8d\x44\x24\x0c"                 # lea eax,[esp+12]
        b"\xb9" + struct.pack("<I", size) +
        b"\x81\xf9\x00\x10\x00\x00"         # cmp ecx,4096
        b"\x76\x10"                         # jbe final
        b"\x2d\x00\x10\x00\x00"             # sub eax,4096
        b"\xf6\x00\x00"                     # test byte ptr[eax],0
        b"\x81\xe9\x00\x10\x00\x00"         # sub ecx,4096
        b"\xeb\xe8"                         # jmp compare
        b"\x29\xc8"                         # final: sub eax,ecx
        b"\xf6\x00\x00"                     # test byte ptr[eax],0
        b"\x59\x58"                         # pop ecx; pop eax
        b"\x8d\xa4\x24" + struct.pack("<i", 4 - size) +
        b"\xff\xa4\x24" + struct.pack("<I", size - 4)
    )
    code.extend(body)
    return address


cleanup_cache = {}


def return_cleanup(entry):
    """Read the callee's RET operand without assuming all calls are cdecl."""
    if entry in cleanup_cache:
        return cleanup_cache[entry]
    queue = [entry]
    seen = set()
    returns = set()
    end = next((address for address in function_entries if address > entry), 0x44D000)
    while queue:
        address = queue.pop()
        if address in seen:
            continue
        seen.add(address)
        if len(seen) > 25000:
            raise ValueError(f"Callee return analysis exceeded bounds at {entry:x}")
        instruction = instruction_at(address)
        operands = instruction.operands
        if instruction.mnemonic == "ret":
            returns.add(operands[0].imm if operands else 0)
            continue
        if instruction.group(CS_GRP_JUMP):
            if operands[0].type == X86_OP_IMM:
                queue.append(operands[0].imm)
            elif (operands[0].type == X86_OP_MEM and not operands[0].mem.base
                  and operands[0].mem.disp >= 0x400000):
                table = operands[0].mem.disp
                for index in range(256):
                    offset = pe.get_offset_from_rva(table + index * 4 - 0x400000)
                    target = struct.unpack_from("<I", original, offset)[0]
                    if not entry <= target < end:
                        break
                    queue.append(target)
            if instruction.mnemonic != "jmp":
                queue.append(address + instruction.size)
        else:
            queue.append(address + instruction.size)
    if len(returns) != 1:
        raise ValueError(f"Ambiguous callee cleanup at {entry:x}: {returns}")
    result = returns.pop()
    cleanup_cache[entry] = result
    return result


def expand_stack(entry, end, buffers):
    """Grow downward, retaining entry-relative saved registers and arguments."""
    extra = sum(new - old for start, old, new in buffers)
    queue = deque([(entry, 0, False)])
    visited = {}
    failures = []
    while queue:
        address, depth, active = queue.popleft()
        state = (depth, active)
        if address in visited:
            if visited[address] != state:
                raise ValueError(f"Stack join mismatch at {address:x}: {visited[address]} / {state}")
            continue
        visited[address] = state
        if not entry <= address < end:
            raise ValueError(f"Unknown instruction {address:x} in {entry:x}")
        instruction = instruction_at(address)
        operands = instruction.operands
        reason = f"expand stack buffers in {entry:#x}"
        if active:
            for operand in operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_ESP:
                    position = operand.mem.disp - depth
                    shift = sum(
                        new - old for start, old, new in buffers if position < start + old
                    )
                    value = operand.mem.disp + extra - shift
                    if value != operand.mem.disp:
                        if instruction.disp_size == 1 and not -128 <= value < 128:
                            failures.append((address, instruction.mnemonic, instruction.op_str, value))
                        else:
                            number(address + instruction.disp_offset, instruction.disp_size, value, reason)
        mnemonic = instruction.mnemonic
        if mnemonic == "push":
            depth += 4
        elif mnemonic == "pop":
            depth -= 4
        elif (mnemonic == "call" and operands[0].type == X86_OP_IMM
              and operands[0].imm == 0x443250):
            allocation = instructions[entry]
            if (active or allocation.mnemonic != "mov"
                    or allocation.operands[0].type != X86_OP_REG
                    or allocation.operands[0].reg != X86_REG_EAX
                    or allocation.operands[1].type != X86_OP_IMM
                    or address != entry + allocation.size):
                raise ValueError(f"Unexpected stack-probe call at {address:x}")
            amount = allocation.operands[1].imm
            immediate(entry, amount + extra, reason)
            depth += amount
            active = True
        elif (mnemonic == "call" and entry >= 0x42C700
              and operands[0].type == X86_OP_IMM):
            depth -= return_cleanup(operands[0].imm)
        elif (mnemonic in ("sub", "add") and len(operands) == 2
              and operands[0].type == X86_OP_REG and operands[0].reg == X86_REG_ESP
              and operands[1].type == X86_OP_IMM):
            amount = operands[1].imm
            if mnemonic == "sub":
                if amount >= 200 and not active:
                    target = probe(amount + extra)
                    replacement(address, address + instruction.size,
                                b"\xe8" + struct.pack("<i", target - address - 5), reason)
                    active = True
                depth += amount
            else:
                if active and amount >= 200:
                    immediate(address, amount + extra, reason)
                    active = False
                depth -= amount
        elif mnemonic == "ret":
            if depth != 0:
                raise ValueError(f"Unbalanced return {address:x}: {depth}")
            continue
        targets = []
        if instruction.group(CS_GRP_JUMP):
            if operands[0].type == X86_OP_IMM:
                targets.append(operands[0].imm)
            elif operands[0].type == X86_OP_MEM:
                table = operands[0].mem.disp
                for index in range(256):
                    offset = pe.get_offset_from_rva(table + index * 4 - 0x400000)
                    target = struct.unpack_from("<I", original, offset)[0]
                    if not entry <= target < end:
                        break
                    targets.append(target)
                if not targets:
                    raise ValueError(f"Unresolved jump at {address:x}")
            if mnemonic != "jmp":
                targets.append(address + instruction.size)
        else:
            targets.append(address + instruction.size)
        for target in targets:
            queue.append((target, depth, active))
    if failures:
        raise ValueError(f"Displacements needing wider instructions in {entry:x}: {failures}")
    print(f"Stack {entry:x}: {len(visited)} reachable instructions, +{extra} bytes")


for instruction in instructions.values():
    for operand in instruction.operands:
        if operand.type == X86_OP_IMM:
            new = relocate(operand.imm)
            if new != operand.imm:
                immediate(instruction.address, new, "relocate static language scratch buffer")
        elif operand.type == X86_OP_MEM:
            new = relocate(operand.mem.disp)
            if new != operand.mem.disp:
                number(instruction.address + instruction.disp_offset, instruction.disp_size,
                       new, "relocate static language scratch buffer")

for instruction in instructions.values():
    if not 0x412400 <= instruction.address < 0x416E50:
        continue
    for operand in instruction.operands:
        if operand.type == X86_OP_IMM and operand.imm in (550, 556, 590, 1100):
            value = {550: 2048, 556: 2052, 590: 2088, 1100: 4096}[operand.imm]
            if instruction.address in (0x41467D, 0x414961, 0x415C7E, 0x415D30, 0x415F7B, 0x41612E):
                value = TEXT_CAPACITY
            immediate(instruction.address, value, "expand language field width/record allocation")
        if (operand.type == X86_OP_MEM and operand.mem.base != X86_REG_ESP
                and operand.mem.disp in (552, -550, -551)):
            value = {552: 2048, -550: -2048, -551: -2049}[operand.mem.disp]
            if 0x415B70 <= instruction.address < 0x4161D0 and operand.mem.disp < 0:
                value = -TEXT_CAPACITY - (operand.mem.disp == -551)
            number(instruction.address + instruction.disp_offset, instruction.disp_size,
                   value, "expand source-record member or translated-field stride")

frames = [
    (0x412ED0, 0x4135A0, [(-1312, 100, TEXT_CAPACITY), (-1212, 100, TEXT_CAPACITY),
                          (-1112, 100, TEXT_CAPACITY), (-1012, 1000, TEXT_CAPACITY)]),
    (0x413AA0, 0x414440, [(-1100, 550, 2048), (-550, 550, 2048)]),
    (0x414440, 0x415330, [(-1656, 552, TEXT_CAPACITY),
                          (-1104, 552, TEXT_CAPACITY), (-552, 552, 4096)]),
    (0x415330, 0x4158E0, [(-552, 552, 2048)]),
    (0x415B70, 0x415DD0, [(-552, 552, 2048)]),
    (0x415DD0, 0x4161D0, [(-1104, 552, TEXT_CAPACITY), (-552, 552, 2048)]),
    (0x416230, 0x4163D0, [(-652, 652, TEXT_CAPACITY + 100)]),
    (0x4163D0, 0x416750, [(-1104, 552, 2048), (-552, 552, 2048)]),
    (0x416750, 0x416D50, [(-1104, 552, 2048), (-552, 552, 2048)]),
    (0x416E50, 0x427FD0, [(-3316, 552, TEXT_CAPACITY), (-2760, 552, TEXT_CAPACITY),
                          (-2208, 552, TEXT_CAPACITY), (-1656, 552, TEXT_CAPACITY),
                          (-1104, 552, TEXT_CAPACITY), (-552, 552, TEXT_CAPACITY)]),
    (0x427FE0, 0x428060, [(-552, 552, TEXT_CAPACITY)]),
]
for entry, end, buffers in frames:
    expand_stack(entry, end, buffers)
immediate(0x41332E, 2048, "expand grammatical formatting input limit")

# The compiler expanded the original constant multiplications into LEA chains.
# Keep instruction addresses stable, replacing reviewed chains with IMUL/NOPs.
replacements = [
    (0x41401C, 0x414022, bytes.fromhex("69d300040000")),
    (0x4140A6, 0x4140AC, bytes.fromhex("69c500040000")),
    (0x4140F3, 0x4140F9, bytes.fromhex("69d500040000")),
    (0x4143A6, 0x4143AC, bytes.fromhex("69d000040000")),
    (0x4143CF, 0x4143D5, bytes.fromhex("69c100040000")),
    (0x414753, 0x41475F, bytes.fromhex("69d000080000")),
    (0x41477E, 0x41478A, bytes.fromhex("69c000080000")),
    (0x4147A6, 0x4147B1, bytes.fromhex("69c000100000")),
    (0x414979, 0x41497F, bytes.fromhex("69d000080000")),
    (0x414A20, 0x414A29, bytes.fromhex("69d000080000")),
    (0x414A96, 0x414AA9, bytes.fromhex("69d0000800008d7c243c83c9ff")),
    (0x4150FF, 0x415116, bytes.fromhex("69d0000800005368f0ea4b0068") + struct.pack("<I", DATA_BASE)),
    (0x415B9E, 0x415BAD, bytes.fromhex("69c82808000083e90a")),
    (0x416D03, 0x416D15, bytes.fromhex("69d02808000081ea0a080000")),
]
for start, end, value in replacements:
    replacement(start, end, value, "expand optimized language-width multiplication")
for start, end in ((0x414F44, 0x414F46), (0x414F58, 0x414F5D),
                   (0x415147, 0x415149), (0x415162, 0x415167)):
    replacement(start, end, b"", "replace leading-space rotation with terminated fixed-field output")
ui_layout = apply_ui(globals())

subprocess.run([
    "i686-w64-mingw32-gcc", "-Os", "-nostdlib", "-fno-builtin",
    "-fno-stack-protector", "-fno-asynchronous-unwind-tables", "-fno-ident",
    "-Wall", "-Wextra", "-Werror",
    f"-DGUARD_TRAMPOLINE={CODE_BASE + 0x800}",
    f"-DGUARD_IMPORT_TRAMPOLINE={CODE_BASE + 0x820}", f"-DGUARD_STATE={GUARD_STATE}",
    f"-DGUARD_WIDGET_TRAMPOLINE={CODE_BASE + 0x840}",
    f"-DGUARD_EDIT_TRAMPOLINE={CODE_BASE + 0x860}",
    f"-DGUARD_SETTEXT_TRAMPOLINE={CODE_BASE + 0x880}",
    f"-DUI_DATA_BASE={UI_DATA_BASE}",
    f"-Wl,--image-base,{CODE_BASE:#x},--entry,_guard_write,--disable-reloc-section,--no-insert-timestamp",
    str(ROOT / "guards.c"), "-o", str(args.work_dir / "guards.exe"),
], check=True)
helper = pefile.PE(str(args.work_dir / "guards.exe"))
assert helper.OPTIONAL_HEADER.ImageBase == CODE_BASE
symbol_output = subprocess.check_output(
    ["i686-w64-mingw32-nm", str(args.work_dir / "guards.exe")], text=True
)
symbols = {line.split()[2]: int(line.split()[0], 16)
           for line in symbol_output.splitlines() if len(line.split()) == 3}
assert len(code) <= 0x800
for entry, location in ((0x415DD0, 0x800), (0x414440, 0x820)):
    offset = pe.get_offset_from_rva(entry - 0x400000)
    original_call = bytes(patches[offset + i] for i in range(5))
    assert original_call[0] == 0xE8
    target = entry + 5 + struct.unpack_from("<i", original_call, 1)[0]
    code.extend(b"\0" * (location - len(code)))
    code.extend(b"\xe8" + struct.pack("<i", target - (CODE_BASE + location + 5)))
    code.extend(b"\xe9" + struct.pack("<i", entry + 6 - (CODE_BASE + location + 10)))
for entry, size, location in (
    (0x411300, 8, 0x840), (0x4050C0, 6, 0x860), (0x411EA0, 7, 0x880),
):
    code.extend(b"\0" * (location - len(code)))
    code.extend(pe.get_data(entry - 0x400000, size))
    after = CODE_BASE + len(code) + 5
    code.extend(b"\xe9" + struct.pack("<i", entry + size - after))
for section in helper.sections:
    if not section.SizeOfRawData:
        continue
    offset = section.VirtualAddress
    assert offset >= len(code)
    code.extend(b"\0" * (offset - len(code)))
    code.extend(section.get_data())
replacement(0x415DD0, 0x415DD6,
            b"\xe9" + struct.pack("<i", symbols["_guard_write"] - 0x415DD5),
            "validate every field before writing any record bytes")
replacement(0x414440, 0x414446,
            b"\xe9" + struct.pack("<i", symbols["_guard_import"] - 0x414445),
            "preflight imported field sizes before creating an output database")
for instruction in instructions.values():
    if ((0x415DD0 < instruction.address < 0x4161D0
         or 0x414440 < instruction.address < 0x415330)
            and instruction.address not in (0x414F58, 0x415162)
            and instruction.mnemonic == "call"
            and instruction.operands[0].type == X86_OP_IMM
            and instruction.operands[0].imm == 0x442E5E):
        replacement(instruction.address, instruction.address + instruction.size,
                    b"\xe8" + struct.pack("<i", symbols["_guard_fwrite"] - instruction.address - 5),
                    "write zero-padded fixed-width fields without reading beyond text")
for entry, name in ((0x4312F0, "_display_encode"), (0x431350, "_display_decode")):
    replacement(entry, entry + 5,
                b"\xe9" + struct.pack("<i", symbols[name] - entry - 5),
                "use checked 32-bit display escaping instead of signed 16-bit indices")
for entry, size, name in (
    (0x411300, 8, "_guard_widget_init"),
    (0x4050C0, 6, "_guard_edit"),
    (0x411EA0, 7, "_guard_settext"),
):
    replacement(entry, entry + size,
                b"\xe9" + struct.pack("<i", symbols[name] - entry - 5),
                "keep full editor strings outside fixed 256-byte widget captions")

groups = []
for offset in sorted(patches):
    if groups and offset == groups[-1]["offset"] + len(bytes.fromhex(groups[-1]["after"])):
        groups[-1]["before"] += f"{original[offset]:02x}"
        groups[-1]["after"] += f"{patches[offset]:02x}"
        if reasons[offset] not in groups[-1]["reasons"]:
            groups[-1]["reasons"].append(reasons[offset])
    else:
        groups.append({"offset": offset, "before": f"{original[offset]:02x}",
                       "after": f"{patches[offset]:02x}", "reasons": [reasons[offset]]})
manifest = {
    "source_sha256": hashlib.sha256(original).hexdigest(),
    "source_size": len(original),
    "data_rva": DATA_BASE - 0x400000,
    "data_size": CODE_BASE - DATA_BASE,
    "guard_state": GUARD_STATE,
    "ui_data_base": UI_DATA_BASE,
    "translation_capacity": TEXT_CAPACITY,
    "ui_layout": ui_layout,
    "code_rva": CODE_BASE - 0x400000,
    "code": code.hex(),
    "patches": groups,
}
args.output.write_text(json.dumps(manifest, indent=2) + "\n")
print(f"Prepared {len(groups)} patch spans and {len(code)} bytes of stack-probe code")
