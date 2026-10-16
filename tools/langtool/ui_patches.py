"""UI/editor-side patch integration for the original langtool.exe."""

import struct


def apply(namespace):
    instructions = namespace["instructions"]
    put = namespace["put"]
    number = namespace["number"]
    immediate = namespace["immediate"]
    replacement = namespace["replacement"]
    expand_stack = namespace["expand_stack"]
    code = namespace["code"]
    code_base = namespace["CODE_BASE"]
    guard_state = namespace["GUARD_STATE"]
    ui_data_base = namespace["UI_DATA_BASE"]

    def patch_disp(address, old, new, reason):
        instruction = namespace["instruction_at"](address)
        matches = [
            operand for operand in instruction.operands
            if operand.type == 3 and operand.mem.disp == old
        ]
        if len(matches) != 1:
            raise ValueError(
                f"Expected one displacement {old:#x} at {address:#x}, "
                f"found {len(matches)}"
            )
        number(
            address + instruction.disp_offset,
            instruction.disp_size,
            new,
            reason,
        )

    def replace_nopped(start, end, body, reason):
        if len(body) > end - start:
            raise ValueError(f"Replacement too long at {start:#x}")
        replacement(start, end, body, reason)

    def rel32(source_after, target):
        return struct.pack("<i", target - source_after)

    def append_jump_stub(site, end, body, reason):
        stub = code_base + len(code)
        code.extend(body)
        jump_at = code_base + len(code)
        code.extend(b"\xe9" + rel32(jump_at + 5, end))
        replace_nopped(
            site,
            end,
            b"\xe9" + rel32(site + 5, stub),
            reason,
        )
        return stub

    # The stack remapper receives ranges relative to the entry ESP, not the
    # ESP value at an arbitrary instruction. Each range is (start, old, new).
    expand_stack(
        0x42E6B0,
        0x42EDA3,
        [(-0x17A4 + row * 0x226, 0x226, 0x10000) for row in range(11)]
        + [(-2, 2, 0)],
    )
    expand_stack(
        0x42EDB0,
        0x42EFF9,
        [(-0x158E + row * 0x226, 0x226, 0x8000) for row in range(10)],
    )
    expand_stack(
        0x42FB40,
        0x4309A2,
        [(-0x228, 0x228, 0x10000)],
    )
    expand_stack(
        0x4309C0,
        0x430C08,
        [(-0x100, 0x100, 0x8064)],
    )

    # Original parser frame B=S-0xb18. The exact nonoverlapping local ranges
    # are source B+0x28/0x228, ten-pointer array B+0x250/0x28, 14-byte token
    # B+0x278/0xe, annotation output B+0x4a0/0x228, mutable input
    # B+0x6c8/0x228, and parser output B+0x8f0/0x228. The array/token boundary
    # and several LEAs alias after transient pushes; use entry-ESP coordinates.
    #
    # The remapper yields frame size 0x9a68 and B'=S-0x9a78:
    # source +0x28, pointers +0x828, token +0x850, annotation +0xa78,
    # mutable input +0x8a78, output +0x9278. Non-buffer locals are retained.
    parser_buffers = [
        (-0xAF0, 0x228, 0x800),
        (-0x8C8, 0x28, 0x28),
        (-0x8A0, 0x0E, 0x0E),
        (-0x678, 0x228, 0x8000),
        (-0x450, 0x228, 0x800),
        (-0x228, 0x228, 0x800),
    ]
    if 0xB08 + sum(new - old for _, old, new in parser_buffers) != 0x9A68:
        raise ValueError("Parser-frame sizing no longer matches the local map")
    expand_stack(0x430C10, 0x4312E8, parser_buffers)

    # Record header is source[2048] followed by the translation-array pointer.
    immediate(0x42E6D6, 0x804, "allocate 2048-byte source plus pointer")
    immediate(0x4304D6, 0x804, "allocate secondary 2048-byte source plus pointer")
    for address in (
        0x42E709,
        0x42EC6B,
        0x42EE81,
        0x42EF07,
        0x430517,
        0x430599,
        0x430607,
    ):
        patch_disp(address, 0x228, 0x800, "move translation pointer to source+0x800")

    # Translation array allocations: count*0x8000, preserving EAX/ECX and
    # returning the byte count in EDX, as expected by the allocator call.
    replace_nopped(
        0x42E6ED,
        0x42E6FB,
        bytes.fromhex("8bd0c1e20f"),
        "allocate 0x8000-byte translation slots",
    )
    replace_nopped(
        0x4304F8,
        0x430506,
        bytes.fromhex("8bd0c1e20f"),
        "allocate secondary 0x8000-byte translation slots",
    )

    # The original allocation has eleven 550-byte text slots (source plus
    # ten language rows), not ten slots plus 0x228 bytes of padding. Expand
    # all eleven to 64 KiB. The record array remains 32-KiB-strided; row 1
    # therefore addresses translation offset 0.
    replace_nopped(
        0x42EB7F,
        0x42EB9E,
        bytes.fromhex("8bddc1e3108b04a983c9ff8b3c852c11450033c0"),
        "compute display row offset and preserve language-label lookup",
    )
    append_jump_stub(
        0x42EC71,
        0x42EC78,
        bytes.fromhex("8bc5c1e00f8d84020080ffff"),
        "compute translation address row*0x8000-0x8000",
    )

    # Save-handler loop index is already zero-based. Preserve it through the
    # record-pointer load, then use the same 0x8000 stride for source scratch
    # and raw translation storage.
    replace_nopped(
        0x42EEEB,
        0x42EEF1,
        b"\x90" * 6,
        "preserve zero-based save row index",
    )
    replace_nopped(
        0x42EEF7,
        0x42EEFF,
        bytes.fromhex("c1e00f") + b"\x90" * 5,
        "compute save row offset row*0x8000",
    )
    replace_nopped(
        0x42EEFF,
        0x42EF06,
        b"\x8d\x14\x45" + struct.pack("<I", ui_data_base + 65536),
        "decode persistent editor fields rather than expired constructor-stack slots",
    )

    # Secondary table display uses ESI as its zero-based translation index.
    replace_nopped(
        0x430593,
        0x430599,
        bytes.fromhex("8bc6c1e00f90"),
        "compute secondary row offset row*0x8000",
    )
    replace_nopped(
        0x4305A3,
        0x4305AC,
        bytes.fromhex("8d0402") + b"\x90" * 6,
        "add secondary raw translation base",
    )

    # Edit-field character limit (NUL excluded) and its bit-sidecar cap.
    immediate(0x42EC9E, 0xFFFF, "set translation edit limit to 65535 characters")
    immediate(0x43BB12, 0xFFFF, "raise per-character sidecar limit")
    immediate(0x43BB19, 0xFFFF, "raise per-character sidecar clamp")

    # Parser linked-node format: debug[0x8064], metadata, query[0x800],
    # then next pointer. The node first string capacity includes its NUL.
    immediate(0x431078, 0x886C, "allocate expanded parser node")
    for address in (0x430BA8, 0x430BE6, 0x430DFD, 0x43109F):
        patch_disp(address, 0x32C, 0x8868, "move parser-node next pointer")
    immediate(0x4310B8, 0x8068, "move parser-node query string")
    for address in (0x430DC6, 0x431255):
        patch_disp(address, 0x104, 0x8068, "move parser-node query pointer")
    patch_disp(0x43125C, 0x100, 0x8064, "move parser-node metadata")

    # Save decode writes only translation slots (the destination is
    # record+0x800+row*0x8000); the immutable source is validated by the
    # parent's pre-write guard. No source-field copy precedes this decoder.
    # Reset sticky decode-overflow state at save-event entry. Replay the
    # post-remap MOV EAX,0x5022c without changing flags or other registers.
    reset = code_base + len(code)
    code.extend(b"\xc7\x05" + struct.pack("<I", guard_state) + b"\0\0\0\0")
    code.extend(b"\xb8" + struct.pack("<I", 0x5022C))
    resume = code_base + len(code)
    code.extend(b"\xe9" + rel32(resume + 5, 0x42EDB5))
    replace_nopped(
        0x42EDB0,
        0x42EDB5,
        b"\xe9" + rel32(0x42EDB5, reset),
        "clear stale decode overflow before save event",
    )

    if len(code) > 0x800:
        raise ValueError(f"UI stack probes/stubs exceed reserved trampoline: {len(code):#x}")

    return {
        "parser_frame_size": 0x9A68,
        "parser_buffers": {
            "source": (0x28, 0x800),
            "argument_pointers": (0x828, 0x28),
            "token": (0x850, 0x0E),
            "annotated_output": (0xA78, 0x8000),
            "mutable_input": (0x8A78, 0x800),
            "parser_output": (0x9278, 0x800),
        },
        "unsupported": (),
    }
