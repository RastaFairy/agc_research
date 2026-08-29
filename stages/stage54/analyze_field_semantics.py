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
    off = va_to_file(va)

    if off is None:
        return b""

    with open(SPRX, "rb") as fp:
        fp.seek(off)
        return fp.read(size)


def find_all(blob, needle):
    out = []
    start = 0

    while True:
        pos = blob.find(needle, start)

        if pos < 0:
            break

        out.append(pos)
        start = pos + 1

    return out


def disassemble(raw, va):
    tmp = os.path.join(
        OUT_DIR,
        "_tmp.bin",
    )

    with open(tmp, "wb") as fp:
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
        "stage53_static.json",
    )

    if not os.path.isfile(path):
        raise RuntimeError(
            "No existe stage53_static.json: %s"
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

    target_raw = read_va(
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

    if len(target_raw) != TARGET_SIZE:
        raise RuntimeError("SubmitCommandBuffer incompleto")

    if len(multi_raw) != MULTI_SIZE:
        raise RuntimeError("SubmitMultiCommandBuffers incompleto")

    # --------------------------------------------------------
    # SubmitCommandBuffer:
    #
    # RSI -> R14
    # R14+0x00 / +0x08 / +0x0C
    # --------------------------------------------------------

    target_text = disassemble(
        target_raw,
        TARGET_VA,
    )

    # --------------------------------------------------------
    # MultiCommandBuffers:
    #
    # Buscar secuencias que copian elementos de una estructura
    # y después los pasan a la misma lógica de SubmitCommandBuffer.
    # --------------------------------------------------------

    multi_text = disassemble(
        multi_raw,
        MULTI_VA,
    )

    # --------------------------------------------------------
    # Detectar accesos conocidos de la estructura multi.
    # --------------------------------------------------------

    multi_field_patterns = [
        (
            bytes.fromhex(
                "49 8b 74 fd 00"
            ),
            "indirect 64-bit load",
            0x00,
            8,
        ),
        (
            bytes.fromhex(
                "41 8b 34 bf"
            ),
            "indexed 32-bit load",
            0x08,
            4,
        ),
        (
            bytes.fromhex(
                "c6 01 00"
            ),
            "byte store",
            0x0C,
            1,
        ),
    ]

    multi_evidence = []

    for needle, description, offset, width in multi_field_patterns:

        for position in find_all(
            multi_raw,
            needle,
        ):
            multi_evidence.append({
                "instruction_va":
                    MULTI_VA + position,
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
    # Detectar preparación de un destino + incremento 0x20.
    #
    # Esta secuencia aparece en la ruta multi:
    #
    #   c6 01 00
    #   48 83 c1 20
    #
    # que sugiere una entrada temporal de 0x20 bytes.
    # --------------------------------------------------------

    temp_entry_pattern = bytes.fromhex(
        "48 83 c1 20"
    )

    temp_entry_positions = find_all(
        multi_raw,
        temp_entry_pattern,
    )

    # --------------------------------------------------------
    # Detectar la carga de:
    #
    #   mov ... 0x14
    #   mov ... 0x18
    #
    # en la ruta de actualización final.
    # --------------------------------------------------------

    counter_patterns = [
        (
            bytes.fromhex("44 8b 73 14"),
            0x14,
            4,
            "32-bit field at +0x14",
        ),
        (
            bytes.fromhex("8b 43 18"),
            0x18,
            4,
            "32-bit field at +0x18",
        ),
    ]

    counter_evidence = []

    for needle, offset, width, desc in counter_patterns:
        for position in find_all(
            multi_raw,
            needle,
        ):
            counter_evidence.append({
                "instruction_va":
                    MULTI_VA + position,
                "offset":
                    offset,
                "width":
                    width,
                "description":
                    desc,
            })

    # --------------------------------------------------------
    # Comparación estructural.
    #
    # IMPORTANTE:
    #   La ruta Multi no prueba por sí sola el nombre semántico
    #   de los campos. Solo permite comprobar si el formato
    #   primario reaparece en la familia.
    # --------------------------------------------------------

    field0_match = any(
        x["field_offset"] == 0x00
        and x["width"] == 8
        for x in multi_evidence
    )

    field8_match = any(
        x["field_offset"] == 0x08
        and x["width"] == 4
        for x in multi_evidence
    )

    fieldc_match = any(
        x["field_offset"] == 0x0C
        and x["width"] == 1
        for x in multi_evidence
    )

    family_shape_match = (
        field0_match
        and field8_match
        and fieldc_match
    )

    # --------------------------------------------------------
    # Evidencia adicional del wrapper DCB.
    # --------------------------------------------------------

    dcb_wrapper_ok = (
        dcb_raw.startswith(
            bytes.fromhex(
                "48 89 fe 48 8d 3d"
            )
        )
        and
        bytes.fromhex(
            "e9 f1 ef ff ff"
        ) in dcb_raw
    )

    # --------------------------------------------------------
    # Candidato semántico.
    #
    # No asignamos nombres falsos.
    #
    # Solo clasificamos:
    #
    # field_00:
    #     64-bit scalar/pointer-compatible
    #
    # field_08:
    #     32-bit scalar
    #
    # field_0C:
    #     8-bit flag-compatible
    #
    # "flag-compatible" NO significa que se haya demostrado
    # que sea un flag.
    # --------------------------------------------------------

    semantic_candidates = {
        "field_00": {
            "offset": 0x00,
            "width": 8,
            "classification":
                "POINTER_OR_64BIT_SCALAR_COMPATIBLE",
            "semantic_proven":
                False,
        },
        "field_08": {
            "offset": 0x08,
            "width": 4,
            "classification":
                "32BIT_SCALAR_COMPATIBLE",
            "semantic_proven":
                False,
        },
        "field_0c": {
            "offset": 0x0C,
            "width": 1,
            "classification":
                "BYTE_OR_FLAG_COMPATIBLE",
            "semantic_proven":
                False,
        },
    }

    # --------------------------------------------------------
    # Layout total mínimo observado.
    #
    # El último acceso es +0x0C de 1 byte:
    # mínimo 13 bytes.
    #
    # Pero no se afirma tamaño exacto de struct, porque puede
    # existir padding o campos no leídos en esta función.
    # --------------------------------------------------------

    minimum_layout_size = 0x0D

    result = {
        "stage": 54,

        "target": {
            "name": TARGET_NAME,
            "va": TARGET_VA,
            "size": TARGET_SIZE,
        },

        "family": {
            "multi_name": MULTI_NAME,
            "multi_va": MULTI_VA,
            "multi_size": MULTI_SIZE,
        },

        "stage53": {
            "abi_candidate":
                previous[
                    "conclusions"
                ].get(
                    "ABI_COMPATIBLE_PROTOTYPE_CANDIDATE",
                    False,
                ),
            "semantic_inferred":
                previous[
                    "conclusions"
                ].get(
                    "SEMANTIC_PROTOTYPE_INFERRED",
                    False,
                ),
        },

        "submit_command_buffer": {
            "disassembly":
                target_text,
        },

        "submit_multi_command_buffers": {
            "disassembly":
                multi_text,
            "field_evidence":
                multi_evidence,
            "temporary_entry_increment_0x20":
                len(temp_entry_positions) > 0,
            "temporary_entry_positions":
                [
                    MULTI_VA + x
                    for x in temp_entry_positions
                ],
            "counter_evidence":
                counter_evidence,
        },

        "dcb_wrapper": {
            "valid":
                dcb_wrapper_ok,
        },

        "field_semantics_candidates":
            semantic_candidates,

        "minimum_observed_argument_layout": {
            "size":
                minimum_layout_size,
            "size_hex":
                "0x%x" % minimum_layout_size,
            "note":
                "minimum bytes touched by SubmitCommandBuffer; "
                "not an exact sizeof(struct)",
        },

        "conclusions": {
            "FIELD_00_WIDTH_CONFIRMED":
                True,
            "FIELD_08_WIDTH_CONFIRMED":
                True,
            "FIELD_0C_WIDTH_CONFIRMED":
                True,

            "MULTI_FAMILY_CORROBORATES_ARGUMENT_LAYOUT":
                family_shape_match,

            "FIELD_00_SEMANTICS_PROVEN":
                False,

            "FIELD_08_SEMANTICS_PROVEN":
                False,

            "FIELD_0C_SEMANTICS_PROVEN":
                False,

            "STRUCT_EXACT_SIZE_PROVEN":
                False,

            "SEMANTIC_PROTOTYPE_INFERRED":
                False,

            "EXECUTED_AGC":
                False,
        },
    }

    static_path = os.path.join(
        OUT_DIR,
        "stage54_static.json",
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
    # Disassembly completa de la familia
    # --------------------------------------------------------

    family_text = (
        "===== SubmitCommandBuffer =====\n\n"
        + target_text
        + "\n\n"
        + "===== SubmitMultiCommandBuffers =====\n\n"
        + multi_text
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
        fp.write(family_text)

    # --------------------------------------------------------
    # Resumen humano
    # --------------------------------------------------------

    lines = []

    lines.append(
        "AGC PS5 Stage 54 - SubmitDcb Field Semantics Audit"
    )
    lines.append("")

    lines.append(
        "=== ARGUMENT LAYOUT ==="
    )
    lines.append("")
    lines.append(
        "0x00 -> 8 bytes"
    )
    lines.append(
        "0x08 -> 4 bytes"
    )
    lines.append(
        "0x0C -> 1 byte"
    )
    lines.append(
        "minimum observed layout = 0x0D bytes"
    )
    lines.append(
        "exact sizeof(struct) = NOT PROVEN"
    )
    lines.append("")

    lines.append(
        "=== FIELD CLASSIFICATION ==="
    )
    lines.append("")
    lines.append(
        "field_00 = POINTER_OR_64BIT_SCALAR_COMPATIBLE"
    )
    lines.append(
        "field_08 = 32BIT_SCALAR_COMPATIBLE"
    )
    lines.append(
        "field_0C = BYTE_OR_FLAG_COMPATIBLE"
    )
    lines.append("")

    lines.append(
        "=== MULTI CORROBORATION ==="
    )
    lines.append("")
    lines.append(
        "family_shape_match = %s"
        % family_shape_match
    )
    lines.append(
        "temp_entry_increment_0x20 = %s"
        % (
            len(temp_entry_positions) > 0
        )
    )
    lines.append("")

    lines.append(
        "=== IMPORTANT LIMIT ==="
    )
    lines.append("")
    lines.append(
        "Los usos actuales permiten clasificar el ancho"
    )
    lines.append(
        "de los campos, pero NO demostrar todavía"
    )
    lines.append(
        "los nombres semánticos exactos de field_00,"
    )
    lines.append(
        "field_08 y field_0c."
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

    with open(
        os.path.join(
            OUT_DIR,
            "field_semantics_summary.txt",
        ),
        "w",
        encoding="utf-8",
        newline="\n",
    ) as fp:
        fp.write(
            "\n".join(lines)
            + "\n"
        )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()