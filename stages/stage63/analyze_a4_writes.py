import json
import os
import re
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile


SPRX = sys.argv[1]
NID_DB = sys.argv[2]
PREVIOUS_RESULTS = sys.argv[3]
OUT_DIR = sys.argv[4]

os.makedirs(OUT_DIR, exist_ok=True)

GLOBAL_CONTEXT_VA = 0x1A908
A4_OFFSET = 0xA4
A4_VA = GLOBAL_CONTEXT_VA + A4_OFFSET

# We scan executable image space broadly, but cap each individual
# window to avoid pathological files.
WINDOW_SIZE = 0x120
WINDOW_STEP = 0x40


# ------------------------------------------------------------
# ELF
# ------------------------------------------------------------

ELF_FP = open(SPRX, "rb")
ELF = ELFFile(ELF_FP)


def load_segments():
    segments = []

    for seg in ELF.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue

        segments.append(
            {
                "offset": int(seg["p_offset"]),
                "vaddr": int(seg["p_vaddr"]),
                "filesz": int(seg["p_filesz"]),
                "memsz": int(seg["p_memsz"]),
                "flags": int(seg["p_flags"]),
            }
        )

    return segments


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


def executable_ranges():
    ranges = []

    for seg in SEGMENTS:
        # ELF PF_X = 1
        if (seg["flags"] & 1) == 0:
            continue

        start = seg["vaddr"]
        end = start + seg["filesz"]

        if end > start:
            ranges.append((start, end))

    return ranges


EXEC_RANGES = executable_ranges()


# ------------------------------------------------------------
# Disassembly
# ------------------------------------------------------------

def disassemble(raw, start_va):
    if not raw:
        return ""

    tmp = None

    try:
        with tempfile.NamedTemporaryFile(
            prefix="agc_stage63_",
            suffix=".bin",
            dir=OUT_DIR,
            delete=False,
        ) as fp:
            fp.write(raw)
            fp.flush()
            tmp = fp.name

        commands = [
            [
                "objdump",
                "-D",
                "-b",
                "binary",
                "-m",
                "i386:x86-64",
                "--adjust-vma=0x%x" % start_va,
                tmp,
            ],
            [
                "llvm-objdump",
                "-D",
                "--triple=x86_64",
                "--adjust-vma=0x%x" % start_va,
                tmp,
            ],
        ]

        for cmd in commands:
            try:
                proc = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                )
            except FileNotFoundError:
                continue

            if proc.returncode == 0:
                return proc.stdout

        return ""

    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def normalize_instruction(text):
    text = text.replace("\t", " ").strip()

    while "  " in text:
        text = text.replace("  ", " ")

    return text


def parse_disassembly(text):
    result = []

    for line in text.splitlines():
        stripped = line.strip()

        # Flexible parser: no assumptions about byte column count.
        m = re.match(
            r"^([0-9a-fA-F]+):\s+(.*)$",
            stripped,
        )

        if not m:
            continue

        va = int(m.group(1), 16)

        remainder = m.group(2)

        # Find the instruction after hexadecimal byte tokens.
        parts = remainder.split()

        byte_count = 0
        index = 0

        while index < len(parts):
            token = parts[index]

            if re.fullmatch(r"[0-9a-fA-F]{2}", token):
                byte_count += 1
                index += 1
                continue

            break

        instruction = " ".join(parts[index:])

        if not instruction:
            continue

        result.append(
            {
                "va": va,
                "instruction": normalize_instruction(
                    instruction
                ),
                "text": stripped,
            }
        )

    return result


# ------------------------------------------------------------
# Symbols / ownership
# ------------------------------------------------------------

def load_symbols():
    symbols = []

    try:
        with open(
            SPRX,
            "rb",
        ) as fp:
            elf = ELFFile(fp)

            for section in elf.iter_sections():
                if section["sh_type"] not in (
                    "SHT_SYMTAB",
                    "SHT_DYNSYM",
                ):
                    continue

                try:
                    iterator = section.iter_symbols()
                except Exception:
                    continue

                for sym in iterator:
                    value = int(sym["st_value"])
                    size = int(sym["st_size"])

                    if value == 0:
                        continue

                    info = sym["st_info"]

                    if str(info["type"]) != "STT_FUNC":
                        continue

                    symbols.append(
                        {
                            "name": sym.name,
                            "value": value,
                            "size": size,
                        }
                    )

    except Exception:
        return []

    symbols.sort(
        key=lambda x: (
            x["value"],
            x["size"],
            x["name"],
        )
    )

    return symbols


SYMBOLS = load_symbols()


def owner_for_va(va):
    best = None

    for sym in SYMBOLS:
        start = sym["value"]

        if sym["size"] > 0:
            end = start + sym["size"]
        else:
            end = start + 1

        if start <= va < end:
            best = sym

    return best


# ------------------------------------------------------------
# Helpers to classify writes
# ------------------------------------------------------------

HEX_IMM_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h)(?![0-9A-Fa-f])"
)

NUM_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:0x[0-9A-Fa-f]+|\d+)(?![A-Za-z0-9_])"
)


def extract_numeric_immediates(text):
    values = []

    for match in re.finditer(
        r"\$0x[0-9A-Fa-f]+|\$[0-9]+",
        text,
    ):
        token = match.group(0)

        if token.startswith("$0x"):
            value = int(
                token[1:],
                16,
            )
        else:
            value = int(
                token[1:],
                10,
            )

        values.append(value)

    return values


def is_a4_write(instruction):
    """
    Identify memory stores touching global_context + 0xA4.

    This is deliberately conservative:
      - exact A4 addressing
      - range-form SIMD stores at A0/A4 when width overlaps A4
      - [base+...] patterns

    We do not claim semantic meaning here.
    """

    text = instruction.lower()

    if (
        "0xa4(%rax)" in text
        or "0xa4(%rcx)" in text
        or "0xa4(%rdx)" in text
        or "0xa4(%rbx)" in text
        or "0xa4(%r12)" in text
        or "0xa4(%r13)" in text
        or "0xa4(%r14)" in text
        or "0xa4(%r15)" in text
        or "0xa4(%r8)" in text
        or "0xa4(%r9)" in text
    ):
        if (
            text.startswith("mov ")
            or text.startswith("movl ")
            or text.startswith("movq ")
            or text.startswith("movb ")
            or text.startswith("movw ")
            or text.startswith("vmov ")
            or text.startswith("vmovups ")
            or text.startswith("vmovdqu ")
            or text.startswith("movups ")
            or text.startswith("movdqu ")
            or text.startswith("stos")
        ):
            return True

    if "0xa0(%rax)" in text and (
        "vmovups" in text
        or "vmovdqu" in text
        or "movups" in text
        or "movdqu" in text
    ):
        # A vector store starting at A0 can cover A4.
        return True

    return False


def infer_store_width(instruction):
    text = instruction.lower()

    if (
        "vmovups %ymm" in text
        or "vmovdqu %ymm" in text
    ):
        return 32

    if (
        "vmovups %xmm" in text
        or "vmovdqu %xmm" in text
        or "movups %xmm" in text
        or "movdqu %xmm" in text
    ):
        return 16

    if "movq " in text:
        return 8

    if "movl " in text:
        return 4

    if "movw " in text:
        return 2

    if "movb " in text:
        return 1

    return None


def classify_value_source(instruction):
    text = instruction.lower()

    immediates = extract_numeric_immediates(
        instruction
    )

    if immediates:
        return {
            "class": "IMMEDIATE",
            "immediates": immediates,
        }

    if (
        "xmm0" in text
        and (
            "vmov" in text
            or "mov" in text
        )
    ):
        return {
            "class": "XMM0_SOURCE",
            "immediates": [],
        }

    if (
        re.search(
            r"%e[a-z0-9]+",
            text,
        )
    ):
        return {
            "class": "GENERAL_REGISTER",
            "immediates": [],
        }

    if (
        re.search(
            r"%r[a-z0-9]+",
            text,
        )
    ):
        return {
            "class": "GENERAL_REGISTER",
            "immediates": [],
        }

    return {
        "class": "UNKNOWN",
        "immediates": [],
    }


# ------------------------------------------------------------
# Build windows from all executable ranges
# ------------------------------------------------------------

WINDOWS = []

for start, end in EXEC_RANGES:
    cursor = start

    while cursor < end:
        window_end = min(
            cursor + WINDOW_SIZE,
            end,
        )

        WINDOWS.append(
            (
                cursor,
                window_end,
            )
        )

        if window_end >= end:
            break

        cursor += WINDOW_STEP


# ------------------------------------------------------------
# Global scan
# ------------------------------------------------------------

all_a4_writes = []
all_a4_reads = []

seen_write_keys = set()
seen_read_keys = set()

for win_start, win_end in WINDOWS:
    raw = read_va(
        win_start,
        win_end - win_start,
    )

    if not raw:
        continue

    text = disassemble(
        raw,
        win_start,
    )

    if not text:
        continue

    lines = parse_disassembly(
        text
    )

    for line in lines:
        instruction = line["instruction"]

        if is_a4_write(
            instruction
        ):
            width = infer_store_width(
                instruction
            )

            source = classify_value_source(
                instruction
            )

            owner = owner_for_va(
                line["va"]
            )

            key = (
                line["va"],
                instruction,
            )

            if key not in seen_write_keys:
                seen_write_keys.add(key)

                all_a4_writes.append(
                    {
                        "instruction_va": line["va"],
                        "instruction": instruction,
                        "width_bytes": width,
                        "value_source": source,
                        "owner": (
                            owner["name"]
                            if owner
                            else None
                        ),
                    }
                )

        # Direct reads of A4.
        text_lower = instruction.lower()

        if (
            "0xa4(%rax)" in text_lower
            or "0xa4(%rcx)" in text_lower
            or "0xa4(%rdx)" in text_lower
            or "0xa4(%rbx)" in text_lower
            or "0xa4(%r12)" in text_lower
            or "0xa4(%r13)" in text_lower
            or "0xa4(%r14)" in text_lower
            or "0xa4(%r15)" in text_lower
        ):
            if (
                text_lower.startswith("mov ")
                or text_lower.startswith("movl ")
                or text_lower.startswith("movq ")
                or text_lower.startswith("movb ")
                or text_lower.startswith("movw ")
                or text_lower.startswith("cmp ")
                or text_lower.startswith("test ")
                or text_lower.startswith("lea ")
            ):
                key = (
                    line["va"],
                    instruction,
                )

                if key not in seen_read_keys:
                    seen_read_keys.add(key)

                    all_a4_reads.append(
                        {
                            "instruction_va": line["va"],
                            "instruction": instruction,
                            "owner": (
                                owner_for_va(
                                    line["va"]
                                )["name"]
                                if owner_for_va(
                                    line["va"]
                                )
                                else None
                            ),
                        }
                    )


# ------------------------------------------------------------
# Deduplicate and sort
# ------------------------------------------------------------

all_a4_writes.sort(
    key=lambda x: (
        x["instruction_va"],
        x["instruction"],
    )
)

all_a4_reads.sort(
    key=lambda x: (
        x["instruction_va"],
        x["instruction"],
    )
)


# ------------------------------------------------------------
# Identify initialization write exactly
# ------------------------------------------------------------

init_store = None

for item in all_a4_writes:
    insn = item["instruction"].lower()

    if (
        item["instruction_va"] == 0x210
        and "vmovups %xmm0,0xa4(%rax)" in insn
    ):
        init_store = item
        break


post_init_writes = []

for item in all_a4_writes:
    if item["instruction_va"] > 0x210:
        post_init_writes.append(
            item
        )


# ------------------------------------------------------------
# Stronger producer classification
# ------------------------------------------------------------

immediate_writes = [
    item
    for item in all_a4_writes
    if item["value_source"]["class"]
    == "IMMEDIATE"
]

xmm_writes = [
    item
    for item in all_a4_writes
    if item["value_source"]["class"]
    == "XMM0_SOURCE"
]

register_writes = [
    item
    for item in all_a4_writes
    if item["value_source"]["class"]
    == "GENERAL_REGISTER"
]


# ------------------------------------------------------------
# Previous Stage 62 carry-forward
# ------------------------------------------------------------

previous_available = os.path.isdir(
    PREVIOUS_RESULTS
)

prev_static_path = os.path.join(
    PREVIOUS_RESULTS,
    "stage62_static.json",
)

previous_stage62 = {}

if os.path.isfile(prev_static_path):
    try:
        with open(
            prev_static_path,
            "r",
            encoding="utf-8",
        ) as fp:
            previous_stage62 = json.load(fp)
    except Exception:
        previous_stage62 = {}


# ------------------------------------------------------------
# Conclusions
# ------------------------------------------------------------

#
# The strongest conclusion available here:
#
# If there are no post-initialization A4 writes,
# then the field is proven to remain zero from the
# static evidence we have scanned.
#
# If there ARE later writes, we report them and do
# not call the field invariant.
#

a4_write_count = len(
    all_a4_writes
)

post_init_write_count = len(
    post_init_writes
)

a4_zero_invariant_static = (
    init_store is not None
    and post_init_write_count == 0
)

if a4_zero_invariant_static:
    zero_status = (
        "STATIC_ZERO_AFTER_INITIALIZATION"
    )
elif post_init_write_count > 0:
    zero_status = (
        "POST_INITIALIZATION_WRITES_FOUND"
    )
else:
    zero_status = (
        "INITIALIZATION_STORE_NOT_FOUND"
    )


static = {
    "stage": 63,

    "target": {
        "name": "global_context + 0xA4",
        "global_context_va": GLOBAL_CONTEXT_VA,
        "field_offset": A4_OFFSET,
        "field_va": A4_VA,
    },

    "scan": {
        "executable_ranges": [
            {
                "start": start,
                "end": end,
            }
            for start, end in EXEC_RANGES
        ],
        "window_count": len(WINDOWS),
        "window_size": WINDOW_SIZE,
        "window_step": WINDOW_STEP,
    },

    "previous_stage": {
        "stage": 62,
        "available": previous_available,
        "a4_zero_initialization_proven": (
            previous_stage62
            .get("conclusions", {})
            .get(
                "A4_ZERO_INITIALIZATION_PROVEN",
                False,
            )
        ),
    },

    "a4_writes": all_a4_writes,
    "a4_reads": all_a4_reads,

    "classification": {
        "initialization_write": init_store,
        "post_initialization_writes": post_init_writes,
        "immediate_writes": immediate_writes,
        "xmm_writes": xmm_writes,
        "register_writes": register_writes,
        "zero_status": zero_status,
    },

    "conclusions": {
        "A4_WRITE_SCAN_COMPLETED": True,

        "A4_INITIALIZATION_WRITE_FOUND":
            init_store is not None,

        "A4_POST_INITIALIZATION_WRITES_FOUND":
            post_init_write_count > 0,

        "A4_STATIC_ZERO_INVARIANT":
            a4_zero_invariant_static,

        "A4_WRITES_EXACTLY_IDENTIFIED":
            a4_write_count > 0,

        "A4_READS_FOUND":
            len(all_a4_reads) > 0,

        "INDEX_SEMANTICS_PROVEN":
            False,

        "COUNT_SEMANTICS_PROVEN":
            False,

        "EXACT_FIELD_NAME_PROVEN":
            False,

        "BACKEND_CONSUMER_IDENTIFIED":
            False,

        "SEMANTIC_PROTOTYPE_INFERRED":
            False,

        "EXECUTED_AGC":
            False,
    },

    "notes": [
        "Stage 62 proved zero initialization through VXORPS -> XMM0 -> VMOVUPS.",
        "Stage 63 scans executable segments globally for writes and reads touching global_context + 0xA4.",
        "A later write prevents treating the field as statically invariant.",
        "Absence of later writes in the scanned executable image supports a static zero-invariant conclusion.",
        "Neither zero initialization nor dispatch use alone proves the semantic field name.",
    ],
}


# ------------------------------------------------------------
# Text summary
# ------------------------------------------------------------

summary = []

summary.append(
    "AGC PS5 Stage 63 - Global +0xA4 Write / Value Provenance Audit"
)

summary.append("")
summary.append("=== TARGET ===")
summary.append(
    "global_context = 0x%X"
    % GLOBAL_CONTEXT_VA
)
summary.append(
    "field_offset = 0x%X"
    % A4_OFFSET
)
summary.append(
    "field_va = 0x%X"
    % A4_VA
)

summary.append("")
summary.append("=== WRITE COUNT ===")
summary.append(
    "total_a4_writes = %d"
    % len(all_a4_writes)
)
summary.append(
    "post_initialization_writes = %d"
    % len(post_init_writes)
)

summary.append("")
summary.append("=== A4 WRITES ===")

if all_a4_writes:
    for item in all_a4_writes:
        owner = item["owner"] or "<unknown>"
        width = item["width_bytes"]
        width_text = (
            str(width)
            if width is not None
            else "unknown"
        )

        source_class = (
            item["value_source"]["class"]
        )

        summary.append(
            "VA=0x%X width=%s source=%s owner=%s | %s"
            % (
                item["instruction_va"],
                width_text,
                source_class,
                owner,
                item["instruction"],
            )
        )
else:
    summary.append(
        "NONE"
    )

summary.append("")
summary.append("=== POST INITIALIZATION ===")

if post_init_writes:
    for item in post_init_writes:
        summary.append(
            "VA=0x%X %s"
            % (
                item["instruction_va"],
                item["instruction"],
            )
        )
else:
    summary.append(
        "NONE"
    )

summary.append("")
summary.append("=== READS ===")

if all_a4_reads:
    for item in all_a4_reads:
        owner = item["owner"] or "<unknown>"

        summary.append(
            "VA=0x%X owner=%s | %s"
            % (
                item["instruction_va"],
                owner,
                item["instruction"],
            )
        )
else:
    summary.append(
        "NONE"
    )

summary.append("")
summary.append("=== STATUS ===")
summary.append(
    "zero_status = %s"
    % zero_status
)

summary.append("")
summary.append("=== CONCLUSIONS ===")
summary.append(
    "A4_WRITE_SCAN_COMPLETED=True"
)
summary.append(
    "A4_INITIALIZATION_WRITE_FOUND=%s"
    % (
        init_store is not None
    )
)
summary.append(
    "A4_POST_INITIALIZATION_WRITES_FOUND=%s"
    % (
        post_init_write_count > 0
    )
)
summary.append(
    "A4_STATIC_ZERO_INVARIANT=%s"
    % (
        a4_zero_invariant_static
    )
)
summary.append(
    "A4_WRITES_EXACTLY_IDENTIFIED=%s"
    % (
        a4_write_count > 0
    )
)
summary.append(
    "A4_READS_FOUND=%s"
    % (
        len(all_a4_reads) > 0
    )
)
summary.append(
    "INDEX_SEMANTICS_PROVEN=False"
)
summary.append(
    "COUNT_SEMANTICS_PROVEN=False"
)
summary.append(
    "EXACT_FIELD_NAME_PROVEN=False"
)
summary.append(
    "BACKEND_CONSUMER_IDENTIFIED=False"
)
summary.append(
    "SEMANTIC_PROTOTYPE_INFERRED=False"
)
summary.append(
    "EXECUTED_AGC=False"
)

summary_text = (
    "\n".join(summary)
    + "\n"
)

with open(
    os.path.join(
        OUT_DIR,
        "a4_write_summary.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        summary_text
    )


# ------------------------------------------------------------
# Disassembly evidence artifact
# ------------------------------------------------------------

with open(
    os.path.join(
        OUT_DIR,
        "a4_write_disassembly.txt",
    ),
    "w",
    encoding="utf-8",
    newline="\n",
) as fp:
    fp.write(
        "AGC PS5 Stage 63 - +0xA4 Global Write Scan\n\n"
    )

    fp.write(
        "=== WRITES ===\n\n"
    )

    for item in all_a4_writes:
        fp.write(
            "VA=0x%X\n"
            % item["instruction_va"]
        )
        fp.write(
            "%s\n"
            % item["instruction"]
        )
        fp.write(
            "width_bytes=%s\n"
            % str(
                item["width_bytes"]
            )
        )
        fp.write(
            "value_source=%s\n"
            % item["value_source"]["class"]
        )
        fp.write(
            "owner=%s\n\n"
            % str(
                item["owner"]
            )
        )

    fp.write(
        "=== READS ===\n\n"
    )

    for item in all_a4_reads:
        fp.write(
            "VA=0x%X\n"
            % item["instruction_va"]
        )
        fp.write(
            "%s\n"
            % item["instruction"]
        )
        fp.write(
            "owner=%s\n\n"
            % str(
                item["owner"]
            )
        )


# ------------------------------------------------------------
# Machine-readable candidate file
# ------------------------------------------------------------

with open(
    os.path.join(
        OUT_DIR,
        "a4_write_candidates.json",
    ),
    "w",
    encoding="utf-8",
) as fp:
    json.dump(
        {
            "field_va": A4_VA,
            "writes": all_a4_writes,
            "reads": all_a4_reads,
            "post_initialization_writes": post_init_writes,
        },
        fp,
        indent=2,
    )


# ------------------------------------------------------------
# Main JSON
# ------------------------------------------------------------

with open(
    os.path.join(
        OUT_DIR,
        "stage63_static.json",
    ),
    "w",
    encoding="utf-8",
) as fp:
    json.dump(
        static,
        fp,
        indent=2,
    )


print(
    json.dumps(
        static,
        indent=2,
    )
)

ELF_FP.close()