import json
import os
import re
import sys

from elftools.elf.elffile import ELFFile

SPRX = sys.argv[1]
PREVIOUS = sys.argv[2]
OUT_DIR = sys.argv[3]

os.makedirs(OUT_DIR, exist_ok=True)

TARGET_VA = 0x18B0
TARGET_SIZE = 0x17C

SUBMIT_DCB_VA = 0x28B0
AGR_SUBMIT_DCB_VA = 0x28C0

EXPECTED_FIELDS = {
    0x00: 8,
    0x08: 4,
    0x0C: 1,
}

def load_segments():
    result = []

    with open(SPRX, "rb") as fp:
        elf = ELFFile(fp)

        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue

            result.append({
                "offset": int(seg["p_offset"]),
                "vaddr": int(seg["p_vaddr"]),
                "filesz": int(seg["p_filesz"]),
                "memsz": int(seg["p_memsz"]),
                "flags": int(seg["p_flags"]),
            })

    return result


SEGMENTS = load_segments()


def va_to_file(va):
    for seg in SEGMENTS:
        start = seg["vaddr"]
        end = start + seg["filesz"]

        if start <= va < end:
            return seg["offset"] + (va - start)

    return None


def read_va(va, size):
    offset = va_to_file(va)

    if offset is None:
        return b""

    with open(SPRX, "rb") as fp:
        fp.seek(offset)
        return fp.read(size)


def find(needle, blob):
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
        start = pos + 1

    return result


def load_stage52():
    path = os.path.join(
        PREVIOUS,
        "stage52_static.json",
    )

    if not os.path.isfile(path):
        raise RuntimeError(
            "No existe stage52_static.json: %s"
            % path
        )

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as fp:
        return json.load(fp)


def run_objdump(raw, va):
    import subprocess

    path = os.path.join(
        OUT_DIR,
        "_prototype.bin",
    )

    with open(path, "wb") as fp:
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
            path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )

    try:
        os.remove(path)
    except OSError:
        pass

    return proc.stdout.decode(
        "utf-8",
        errors="replace",
    )


def analyze():
    stage52 = load_stage52()

    raw = read_va(
        TARGET_VA,
        TARGET_SIZE,
    )

    if len(raw) != TARGET_SIZE:
        raise RuntimeError(
            "No se pudieron leer %d bytes de SubmitCommandBuffer; "
            "se obtuvieron %d"
            % (
                TARGET_SIZE,
                len(raw),
            )
        )

    # --------------------------------------------------------
    # Campos del segundo argumento:
    #
    # r14 se obtiene de rsi al comienzo del cuerpo.
    # --------------------------------------------------------

    field_patterns = [
        (
            bytes.fromhex("49 8b 06"),
            0x00,
            8,
            "mov (%r14),%rax",
            "pointer-sized / 64-bit load",
        ),
        (
            bytes.fromhex("41 8b 46 08"),
            0x08,
            4,
            "mov 0x8(%r14),%eax",
            "32-bit load",
        ),
        (
            bytes.fromhex("41 8a 46 0c"),
            0x0C,
            1,
            "mov 0xc(%r14),%al",
            "8-bit load",
        ),
    ]

    field_evidence = []

    for needle, offset, width, instruction, meaning in field_patterns:
        positions = find(
            needle,
            raw,
        )

        for position in positions:
            field_evidence.append({
                "instruction_va":
                    TARGET_VA + position,
                "instruction":
                    instruction,
                "register":
                    "R14",
                "source_register":
                    "RSI",
                "field_offset":
                    offset,
                "field_offset_hex":
                    "0x%x" % offset,
                "width":
                    width,
                "width_hex":
                    "0x%x" % width,
                "meaning_inference":
                    meaning,
                "evidence":
                    "DIRECT_MACHINE_CODE",
            })

    field_evidence.sort(
        key=lambda item: (
            item["field_offset"],
            item["instruction_va"],
        )
    )

    # --------------------------------------------------------
    # Entrada RDI/RSI:
    #
    #   49 89 f6 = mov r14,rsi
    #   ... más tarde r14 es usado para leer los campos.
    # --------------------------------------------------------

    rsi_to_r14 = find(
        bytes.fromhex("49 89 f6"),
        raw,
    )

    # --------------------------------------------------------
    # Retorno:
    #
    #   44 89 f8 = mov eax,r15d
    #   ... ret
    #
    # Lo tratamos como evidencia de retorno de 32 bits,
    # no como prueba semántica de que sea exactamente int.
    # --------------------------------------------------------

    return_pattern = bytes.fromhex(
        "44 89 f8"
    )

    return_positions = find(
        return_pattern,
        raw,
    )

    # --------------------------------------------------------
    # Wrapper público SubmitDcb:
    #
    # 48 89 fe = mov rsi,rdi
    # 48 8d 3d ... = lea dcb_context,rdi
    # e9 ... = tail jump
    # --------------------------------------------------------

    dcb_raw = read_va(
        SUBMIT_DCB_VA,
        15,
    )

    agr_raw = read_va(
        AGR_SUBMIT_DCB_VA,
        72,
    )

    dcb_wrapper_ok = (
        dcb_raw.startswith(
            bytes.fromhex(
                "48 89 fe 48 8d 3d"
            )
        )
        and
        b"\xe9\xf1\xef\xff\xff"
        in dcb_raw
    )

    agr_wrapper_ok = (
        bytes.fromhex(
            "48 89 fe"
        )
        in agr_raw
        and
        bytes.fromhex(
            "48 8d 3d 8a 7f 01 00"
        )
        in agr_raw
        and
        bytes.fromhex(
            "e9 cc ef ff ff"
        )
        in agr_raw
    )

    # --------------------------------------------------------
    # Candidaturas
    # --------------------------------------------------------

    argument_offsets_proven = (
        {x["field_offset"] for x in field_evidence}
        == set(EXPECTED_FIELDS.keys())
        and len(field_evidence) == 3
    )

    widths_exact = (
        argument_offsets_proven
        and all(
            next(
                (
                    x["width"]
                    for x in field_evidence
                    if x["field_offset"] == offset
                ),
                None,
            ) == width
            for offset, width
            in EXPECTED_FIELDS.items()
        )
    )

    register_placement_proven = (
        bool(rsi_to_r14)
        and dcb_wrapper_ok
        and agr_wrapper_ok
    )

    return_width_evidence = (
        len(return_positions) > 0
    )

    candidate_two_arg = (
        register_placement_proven
        and argument_offsets_proven
        and widths_exact
    )

    # --------------------------------------------------------
    # Prototipo candidato.
    #
    # NO se etiqueta como "inferred" porque los nombres
    # semánticos de los tres campos no han sido recuperados.
    # --------------------------------------------------------

    candidates = [
        {
            "name":
                "opaque_struct_candidate",
            "prototype":
                "int sceAgcDriverSubmitCommandBuffer("
                "void *context, "
                "const struct SceAgcSubmitCommandBufferArgs *args"
                ");",
            "abi_shape":
                "RDI=context, RSI=args, EAX=return",
            "confidence":
                "ABI_COMPATIBLE_CANDIDATE",
            "semantic_field_names":
                False,
        },
        {
            "name":
                "byte_layout_exact_candidate",
            "prototype":
                "int sceAgcDriverSubmitCommandBuffer("
                "void *context, "
                "const unsigned char *args"
                ");",
            "abi_shape":
                "RDI=context, RSI=args, EAX=return",
            "confidence":
                "ABI_COMPATIBLE_BUT_SEMANTICALLY_WEAK",
            "semantic_field_names":
                False,
        },
    ]

    # --------------------------------------------------------
    # Guardar resumen
    # --------------------------------------------------------

    result = {
        "stage": 53,
        "target": {
            "name":
                "sceAgcDriverSubmitCommandBuffer",
            "va":
                TARGET_VA,
            "size":
                TARGET_SIZE,
        },
        "stage52_conclusions":
            stage52.get(
                "conclusions",
                {},
            ),
        "register_evidence": {
            "rsi_to_r14_positions": [
                TARGET_VA + x
                for x in rsi_to_r14
            ],
            "submit_dcb_wrapper_valid":
                dcb_wrapper_ok,
            "agr_submit_dcb_wrapper_valid":
                agr_wrapper_ok,
        },
        "argument_field_evidence":
            field_evidence,
        "return_evidence": {
            "eax_from_r15d_positions": [
                TARGET_VA + x
                for x in return_positions
            ],
            "return_width_evidence":
                return_width_evidence,
        },
        "candidate_prototypes":
            candidates,
        "conclusions": {
            "REGISTER_PLACEMENT_PROVEN":
                register_placement_proven,
            "ARGUMENT_OFFSETS_PROVEN":
                argument_offsets_proven,
            "ARGUMENT_WIDTHS_EXACT":
                widths_exact,
            "TWO_ARGUMENT_ABI_SHAPE_PROVEN":
                candidate_two_arg,
            "RETURN_REGISTER_EVIDENCE":
                return_width_evidence,
            "ABI_COMPATIBLE_PROTOTYPE_CANDIDATE":
                candidate_two_arg,
            "SEMANTIC_PROTOTYPE_INFERRED":
                False,
            "EXECUTED_AGC":
                False,
        },
    }

    static_path = os.path.join(
        OUT_DIR,
        "stage53_static.json",
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
    # Disassembly
    # --------------------------------------------------------

    disassembly = run_objdump(
        raw,
        TARGET_VA,
    )

    with open(
        os.path.join(
            OUT_DIR,
            "submitdcb_prototype_disassembly.txt",
        ),
        "w",
        encoding="utf-8",
        newline="\n",
    ) as fp:
        fp.write(disassembly)

    # --------------------------------------------------------
    # C probe
    # --------------------------------------------------------

    c_probe = r'''
#include <stdint.h>

struct SceAgcSubmitCommandBufferArgsCandidate {
    uint64_t field_00;
    uint32_t field_08;
    uint8_t  field_0c;
};

extern int
sceAgcDriverSubmitCommandBuffer(
    void *context,
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
);

extern int
sceAgcDriverSubmitDcb(
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
);

extern int
sceAgcDriverAgrSubmitDcb(
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
);

int
stage53_call_target(
    void *context,
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
)
{
    return sceAgcDriverSubmitCommandBuffer(
        context,
        args
    );
}

int
stage53_call_dcb(
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
)
{
    return sceAgcDriverSubmitDcb(
        args
    );
}

int
stage53_call_agr(
    const struct SceAgcSubmitCommandBufferArgsCandidate *args
)
{
    return sceAgcDriverAgrSubmitDcb(
        args
    );
}
'''.strip() + "\n"

    source_path = os.path.join(
        OUT_DIR,
        "prototype_probe.c",
    )

    with open(
        source_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as fp:
        fp.write(c_probe)

    # --------------------------------------------------------
    # Resumen
    # --------------------------------------------------------

    lines = []

    lines.append(
        "AGC PS5 Stage 53 - SubmitDcb Prototype / ABI Audit"
    )
    lines.append("")

    lines.append(
        "=== ABI REGISTERS ==="
    )
    lines.append("")

    lines.append(
        "SubmitDcb wrapper:"
    )
    lines.append(
        "  RDI(original) -> RSI"
    )
    lines.append(
        "  RDI <- dcb_context"
    )
    lines.append(
        "  tail-jump -> SubmitCommandBuffer"
    )
    lines.append("")

    lines.append(
        "AgrSubmitDcb wrapper:"
    )
    lines.append(
        "  RDI(original) -> RSI"
    )
    lines.append(
        "  RDI <- agr_context"
    )
    lines.append(
        "  tail-jump -> SubmitCommandBuffer"
    )
    lines.append("")

    lines.append(
        "SubmitCommandBuffer:"
    )
    lines.append(
        "  RSI -> R14"
    )
    lines.append(
        "  R14+0x00 -> 8 bytes"
    )
    lines.append(
        "  R14+0x08 -> 4 bytes"
    )
    lines.append(
        "  R14+0x0C -> 1 byte"
    )
    lines.append("")

    lines.append(
        "=== PROTOTYPE CANDIDATE ==="
    )
    lines.append("")

    lines.append(
        "int sceAgcDriverSubmitCommandBuffer("
    )
    lines.append(
        "    void *context,"
    )
    lines.append(
        "    const struct SceAgcSubmitCommandBufferArgs *args"
    )
    lines.append(
        ");"
    )
    lines.append("")

    lines.append(
        "Interpretacion:"
    )
    lines.append(
        "  ABI-compatible candidate = %s"
        % candidate_two_arg
    )
    lines.append(
        "  semantic prototype inferred = False"
    )
    lines.append("")

    lines.append(
        "=== FIELD SEMANTICS ==="
    )
    lines.append("")

    lines.append(
        "field_00: 64-bit load"
    )
    lines.append(
        "field_08: 32-bit load"
    )
    lines.append(
        "field_0c: 8-bit load"
    )
    lines.append("")

    lines.append(
        "Los nombres/semantica de esos tres campos"
    )
    lines.append(
        "NO estan demostrados por esta auditoria."
    )
    lines.append("")

    lines.append(
        "=== CONCLUSIONES ==="
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

    with open(
        os.path.join(
            OUT_DIR,
            "prototype_summary.txt",
        ),
        "w",
        encoding="utf-8",
        newline="\n",
    ) as fp:
        fp.write(
            "\n".join(lines) + "\n"
        )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )


if __name__ == "__main__":
    analyze()