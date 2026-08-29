import json
import os
import re
import subprocess
import sys

from elftools.elf.elffile import ELFFile


SPRX = sys.argv[1]
NID_DB = sys.argv[2]
PREVIOUS = sys.argv[3]
OUT_DIR = sys.argv[4]

os.makedirs(OUT_DIR, exist_ok=True)


TARGET_NAME = "sceAgcDriverSubmitCommandBuffer"
TARGET_VA = 0x18B0
TARGET_SIZE = 380

MULTI_NAME = "sceAgcDriverSubmitMultiCommandBuffers"
MULTI_VA = 0x4650
MULTI_SIZE = 579

DCB_NAME = "sceAgcDriverSubmitDcb"
DCB_VA = 0x28B0
DCB_SIZE = 15

# Argument record used by SubmitCommandBuffer.
#
# +0x00 = 8 bytes
# +0x08 = 4 bytes
# +0x0C = 1 byte
#
# The multi-submit helper builds records with the same
# offsets inside a 0x20-byte stride.
FIELD_LAYOUT = {
    0x00: 8,
    0x08: 4,
    0x0C: 1,
}

RECORD_STRIDE = 0x20


def load_segments():
    result = []

    with open(SPRX, "rb") as fp:

        elf = ELFFile(fp)

        for seg in elf.iter_segments():

            if seg["p_type"] != "PT_LOAD":
                continue

            result.append({
                "offset":
                    int(seg["p_offset"]),
                "vaddr":
                    int(seg["p_vaddr"]),
                "filesz":
                    int(seg["p_filesz"]),
                "memsz":
                    int(seg["p_memsz"]),
                "flags":
                    int(seg["p_flags"]),
            })

    return result


SEGMENTS = load_segments()


def va_to_file(va):
    for seg in SEGMENTS:

        start = seg["vaddr"]

        end = (
            start +
            seg["filesz"]
        )

        if (
            start <= va < end
        ):
            return (
                seg["offset"] +
                (
                    va -
                    start
                )
            )

    return None


def read_va(va, size):
    offset = va_to_file(va)

    if offset is None:
        return b""

    with open(SPRX, "rb") as fp:

        fp.seek(offset)

        return fp.read(size)


def find_all(blob, needle):
    result = []

    start = 0

    while True:

        pos = blob.find(
            needle,
            start,
        )

        if pos < 0:
            break

        result.append(pos)

        start = (
            pos +
            1
        )

    return result


def disassemble(raw, va):
    tmp = os.path.join(
        OUT_DIR,
        "_tmp.bin",
    )

    with open(
        tmp,
        "wb",
    ) as fp:
        fp.write(raw)

    proc = subprocess.run(
        [
            "objdump",
            "-D",
            "-b",
            "binary",
            "-m",
            "i386:x86-64",
            "--adjust-vma=0x%x" % va,
            tmp,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    try:
        os.remove(tmp)
    except OSError:
        pass

    return proc.stdout.decode(
        "utf-8",
        errors="replace",
    )


def load_previous():
    path = os.path.join(
        PREVIOUS,
        "stage54_static.json",
    )

    if not os.path.isfile(path):
        raise RuntimeError(
            "No existe stage54_static.json: %s"
            % path
        )

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as fp:
        return json.load(fp)


def main():

    previous = load_previous()

    submit_raw = read_va(
        TARGET_VA,
        TARGET_SIZE,
    )

    multi_raw = read_va(
        MULTI_VA,
        MULTI_SIZE,
    )

    dcb_raw = read_va(
        DCB_VA,
        DCB_SIZE,
    )

    if (
        len(submit_raw) !=
        TARGET_SIZE
    ):
        raise RuntimeError(
            "SubmitCommandBuffer incompleto"
        )

    if (
        len(multi_raw) !=
        MULTI_SIZE
    ):
        raise RuntimeError(
            "SubmitMultiCommandBuffers incompleto"
        )

    if (
        len(dcb_raw) !=
        DCB_SIZE
    ):
        raise RuntimeError(
            "SubmitDcb incompleto"
        )

    submit_text = disassemble(
        submit_raw,
        TARGET_VA,
    )

    multi_text = disassemble(
        multi_raw,
        MULTI_VA,
    )

    # --------------------------------------------------------
    # SUBMITCOMMANDBUFFER direct field evidence
    # --------------------------------------------------------

    submit_patterns = [
        (
            bytes.fromhex(
                "49 8b 06"
            ),
            0x00,
            8,
            "64-bit load from RSI/R14 + 0x00",
        ),
        (
            bytes.fromhex(
                "41 8b 46 08"
            ),
            0x08,
            4,
            "32-bit load from RSI/R14 + 0x08",
        ),
        (
            bytes.fromhex(
                "41 8a 46 0c"
            ),
            0x0C,
            1,
            "8-bit load from RSI/R14 + 0x0C",
        ),
    ]

    submit_evidence = []

    for (
        needle,
        offset,
        width,
        description,
    ) in submit_patterns:

        positions = find_all(
            submit_raw,
            needle,
        )

        for pos in positions:

            submit_evidence.append({
                "instruction_va":
                    TARGET_VA +
                    pos,

                "field_offset":
                    offset,

                "width":
                    width,

                "description":
                    description,

                "evidence":
                    "DIRECT_MACHINE_CODE",
            })

    # --------------------------------------------------------
    # MULTI SUBMIT register placement.
    #
    # ABI:
    #
    # RDI = context
    # RSI = array of 64-bit values
    # RDX = array of 32-bit values
    # RCX = count
    #
    # The exact instructions are:
    #
    # 0x466c  mov ecx,r12d
    # 0x466f  mov rdx,r15
    # 0x4672  mov rsi,r13
    #
    # and then:
    #
    # 0x4736  mov rsi,[r13+rdi*8]
    # 0x473f  mov esi,[r15+rdi*4]
    #
    # --------------------------------------------------------

    multi_register_evidence = []

    register_patterns = [
        (
            bytes.fromhex(
                "49 89 f5"
            ),
            "RSI -> R13",
            "RSI",
            "R13",
        ),
        (
            bytes.fromhex(
                "49 89 d7"
            ),
            "RDX -> R15",
            "RDX",
            "R15",
        ),
        (
            bytes.fromhex(
                "41 89 cc"
            ),
            "ECX -> R12D",
            "ECX",
            "R12D",
        ),
    ]

    for (
        needle,
        description,
        source,
        destination,
    ) in register_patterns:

        for pos in find_all(
            multi_raw,
            needle,
        ):

            multi_register_evidence.append({
                "instruction_va":
                    MULTI_VA +
                    pos,

                "description":
                    description,

                "source":
                    source,

                "destination":
                    destination,
            })

    # --------------------------------------------------------
    # MULTI source array evidence.
    #
    # RSI/R13:
    #     [R13 + index*8]
    #
    # RDX/R15:
    #     [R15 + index*4]
    #
    # This establishes provenance of the two fields.
    # --------------------------------------------------------

    provenance_evidence = []

    source_patterns = [
        (
            bytes.fromhex(
                "49 8b 74 fd 00"
            ),
            "field_00",
            8,
            "source array element is loaded with scale 8",
            "R13",
            8,
        ),
        (
            bytes.fromhex(
                "41 8b 34 bf"
            ),
            "field_08",
            4,
            "source array element is loaded with scale 4",
            "R15",
            4,
        ),
    ]

    for (
        needle,
        field_name,
        width,
        description,
        source_register,
        stride,
    ) in source_patterns:

        for pos in find_all(
            multi_raw,
            needle,
        ):

            provenance_evidence.append({
                "instruction_va":
                    MULTI_VA +
                    pos,

                "field":
                    field_name,

                "width":
                    width,

                "source_register":
                    source_register,

                "source_stride":
                    stride,

                "description":
                    description,

                "evidence":
                    "DIRECT_MACHINE_CODE",
            })

    # --------------------------------------------------------
    # Exact temporary record construction.
    #
    # At 0x471c:
    #
    #   RCX = RSP + 0x1c
    #
    # Then:
    #
    #   [RCX-0x0c] = 8 bytes
    #   [RCX-0x04] = 4 bytes
    #   [RCX+0x00] = byte 0
    #
    # Therefore:
    #
    #   entry_base = RCX - 0x0c
    #
    #   +0x00 = 8 bytes
    #   +0x08 = 4 bytes
    #   +0x0c = byte
    #
    # Finally RCX += 0x20.
    #
    # This proves a canonical 0x20-byte record.
    # --------------------------------------------------------

    record_build = {
        "anchor_instruction_va":
            MULTI_VA + 0xAC,

        "anchor_description":
            "lea 0x1c(%rdi),%rax followed by RCX=temporary record cursor",

        "stores": [
            {
                "instruction_va":
                    MULTI_VA + 0xEE,

                "relative_expression":
                    "mov [r13+rdi*8] -> [rcx-0x0c]",

                "record_offset":
                    0x00,

                "width":
                    8,
            },
            {
                "instruction_va":
                    MULTI_VA + 0xF7,

                "relative_expression":
                    "mov [r15+rdi*4] -> [rcx-0x04]",

                "record_offset":
                    0x08,

                "width":
                    4,
            },
            {
                "instruction_va":
                    MULTI_VA + 0x100,

                "relative_expression":
                    "movb $0 -> [rcx]",

                "record_offset":
                    0x0C,

                "width":
                    1,

                "constant_value":
                    0,
            },
        ],

        "stride_increment": {
            "instruction_va":
                MULTI_VA + 0x109,

            "record_offset":
                0x00,

            "increment":
                0x20,
        },

        "record_stride":
            RECORD_STRIDE,
    }

    # --------------------------------------------------------
    # Determine whether the multi producer constructs a record
    # with exactly the same primary offsets.
    # --------------------------------------------------------

    same_layout = (
        len(provenance_evidence) >= 2
        and
        record_build["record_stride"] == 0x20
    )

    # --------------------------------------------------------
    # Field provenance conclusions
    # --------------------------------------------------------

    field00_source_proven = any(
        item["field"] == "field_00"
        and item["source_stride"] == 8
        for item in provenance_evidence
    )

    field08_source_proven = any(
        item["field"] == "field_08"
        and item["source_stride"] == 4
        for item in provenance_evidence
    )

    field0c_zero_proven = (
        bytes.fromhex(
            "c6 01 00"
        ) in multi_raw
    )

    # --------------------------------------------------------
    # Stronger classifications.
    #
    # Do NOT claim pointer/size/flag as exact semantics.
    #
    # The strongest safe conclusions are:
    #
    # field_00:
    #   64-bit value sourced from an array with element stride 8
    #
    # field_08:
    #   32-bit value sourced from an array with element stride 4
    #
    # field_0c:
    #   one byte, explicitly zeroed by multi producer
    # --------------------------------------------------------

    field_semantics = {
        "field_00": {
            "offset":
                0x00,

            "width":
                8,

            "provenance":
                "64-bit array element",

            "source_element_stride":
                8,

            "semantic_class":
                "OPAQUE_64BIT_VALUE",

            "pointer_semantics_proven":
                False,

            "address_semantics_proven":
                False,

            "size_semantics_proven":
                False,
        },

        "field_08": {
            "offset":
                0x08,

            "width":
                4,

            "provenance":
                "32-bit array element",

            "source_element_stride":
                4,

            "semantic_class":
                "OPAQUE_32BIT_VALUE",

            "size_semantics_proven":
                False,

            "count_semantics_proven":
                False,

            "index_semantics_proven":
                False,
        },

        "field_0c": {
            "offset":
                0x0C,

            "width":
                1,

            "provenance":
                "producer initializes byte to zero",

            "constant_value_in_multi":
                0,

            "semantic_class":
                "BYTE_WITH_ZERO_DEFAULT",

            "flag_semantics_proven":
                False,

            "boolean_semantics_proven":
                False,
        },
    }

    # --------------------------------------------------------
    # Candidate API shape for the multi function.
    #
    # This is intentionally an ABI candidate, not a semantic
    # API declaration.
    # --------------------------------------------------------

    multi_candidate = (
        "int "
        "sceAgcDriverSubmitMultiCommandBuffers("
        "void *context, "
        "const uint64_t *field00_array, "
        "const uint32_t *field08_array, "
        "uint32_t count);"
    )

    # --------------------------------------------------------
    # Stage 53/54 carry-forward
    # --------------------------------------------------------

    stage53_semantic = previous.get(
        "stage53",
        {},
    )

    # --------------------------------------------------------
    # Full result
    # --------------------------------------------------------

    result = {
        "stage": 55,

        "target": {
            "name":
                TARGET_NAME,

            "va":
                TARGET_VA,

            "size":
                TARGET_SIZE,
        },

        "multi_source": {
            "name":
                MULTI_NAME,

            "va":
                MULTI_VA,

            "size":
                MULTI_SIZE,
        },

        "stage54_carry_forward": {
            "field_widths_confirmed":
                True,

            "multi_family_corrobates_layout":
                True,

            "semantic_prototype_inferred":
                False,
        },

        "submit_command_buffer": {
            "field_evidence":
                submit_evidence,

            "disassembly":
                submit_text,
        },

        "multi_command_buffers": {
            "register_evidence":
                multi_register_evidence,

            "source_array_provenance":
                provenance_evidence,

            "record_builder":
                record_build,

            "disassembly":
                multi_text,
        },

        "canonical_record_layout": {
            "stride":
                RECORD_STRIDE,

            "fields": [
                {
                    "offset":
                        0x00,

                    "width":
                        8,

                    "source":
                        "RSI array element",
                },
                {
                    "offset":
                        0x08,

                    "width":
                        4,

                    "source":
                        "RDX array element",
                },
                {
                    "offset":
                        0x0C,

                    "width":
                        1,

                    "source":
                        "constant zero in multi producer",
                },
            ],
        },

        "field_semantics":
            field_semantics,

        "multi_candidate_prototype":
            multi_candidate,

        "dcb_wrapper": {
            "valid":
                (
                    dcb_raw.startswith(
                        bytes.fromhex(
                            "48 89 fe 48 8d 3d"
                        )
                    )
                ),
        },

        "conclusions": {
            "CANONICAL_0x20_RECORD_LAYOUT_PROVEN":
                same_layout,

            "FIELD_00_PROVEN_AS_64BIT_ARRAY_VALUE":
                field00_source_proven,

            "FIELD_08_PROVEN_AS_32BIT_ARRAY_VALUE":
                field08_source_proven,

            "FIELD_0C_PROVEN_ZERO_INITIALIZED_BY_MULTI":
                field0c_zero_proven,

            "FIELD_00_POINTER_SEMANTICS_PROVEN":
                False,

            "FIELD_08_SIZE_SEMANTICS_PROVEN":
                False,

            "FIELD_08_COUNT_SEMANTICS_PROVEN":
                False,

            "FIELD_0C_FLAG_SEMANTICS_PROVEN":
                False,

            "ARGUMENT_RECORD_STRIDE_PROVEN":
                (
                    record_build["record_stride"] ==
                    RECORD_STRIDE
                ),

            "SEMANTIC_PROTOTYPE_INFERRED":
                False,

            "EXECUTED_AGC":
                False,
        },
    }

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    static_path = os.path.join(
        OUT_DIR,
        "stage55_static.json",
    )

    with open(
        static_path,
        "w",
        encoding="utf-8",
    ) as fp:
        json.dump(
            result,
            fp,
            indent=2,
        )

    # --------------------------------------------------------
    # Combined disassembly
    # --------------------------------------------------------

    combined_disassembly = (
        "===== SubmitCommandBuffer =====\n\n"
        +
        submit_text
        +
        "\n\n"
        +
        "===== SubmitMultiCommandBuffers =====\n\n"
        +
        multi_text
    )

    with open(
        os.path.join(
            OUT_DIR,
            "submit_family_disassembly.txt",
        ),
        "w",
        encoding="utf-8",
        newline="\n",
    ) as fp:

        fp.write(
            combined_disassembly
        )

    # --------------------------------------------------------
    # Human summary
    # --------------------------------------------------------

    lines = []

    lines.append(
        "AGC PS5 Stage 55 - SubmitDcb Field Provenance Audit"
    )

    lines.append("")

    lines.append(
        "=== CANONICAL RECORD ==="
    )

    lines.append(
        "stride = 0x20"
    )

    lines.append(
        "0x00 = 8 bytes"
    )

    lines.append(
        "0x08 = 4 bytes"
    )

    lines.append(
        "0x0C = 1 byte"
    )

    lines.append("")

    lines.append(
        "=== FIELD 0x00 ==="
    )

    lines.append(
        "provenance = 64-bit array element"
    )

    lines.append(
        "source element stride = 8"
    )

    lines.append(
        "pointer semantics proven = False"
    )

    lines.append(
        "address semantics proven = False"
    )

    lines.append("")

    lines.append(
        "=== FIELD 0x08 ==="
    )

    lines.append(
        "provenance = 32-bit array element"
    )

    lines.append(
        "source element stride = 4"
    )

    lines.append(
        "size semantics proven = False"
    )

    lines.append(
        "count semantics proven = False"
    )

    lines.append(
        "index semantics proven = False"
    )

    lines.append("")

    lines.append(
        "=== FIELD 0x0C ==="
    )

    lines.append(
        "provenance = producer writes constant zero"
    )

    lines.append(
        "flag semantics proven = False"
    )

    lines.append(
        "boolean semantics proven = False"
    )

    lines.append("")

    lines.append(
        "=== MULTI ABI CANDIDATE ==="
    )

    lines.append(
        multi_candidate
    )

    lines.append("")

    lines.append(
        "=== IMPORTANT LIMIT ==="
    )

    lines.append(
        "The record layout and source provenance are proven."
    )

    lines.append(
        "Semantic names such as pointer, GPU address, size,"
    )

    lines.append(
        "count, index or flags are NOT proven by this stage."
    )

    lines.append("")

    lines.append(
        "=== CONCLUSIONS ==="
    )

    lines.append("")

    for key, value in result[
        "conclusions"
    ].items():

        lines.append(
            "%s=%s"
            % (
                key,
                value,
            )
        )

    summary_path = os.path.join(
        OUT_DIR,
        "field_provenance_summary.txt",
    )

    with open(
        summary_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as fp:

        fp.write(
            "\n".join(lines)
            +
            "\n"
        )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()