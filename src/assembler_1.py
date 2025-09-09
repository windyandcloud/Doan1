# src/assembler.py
import re
import os
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Union

try:
    from .utils import sign_extend, format_bin
    from .isa_defs import *
    from .regnames import GPR_NAMES, CSR_NAMES
except ImportError:
    from utils import sign_extend, format_bin
    from isa_defs import *
    from regnames import GPR_NAMES, CSR_NAMES


@dataclass
class ParsedLine:
    line_num: int
    original_line: str
    address: int = 0
    label: Optional[str] = None
    is_instruction: bool = False
    opcode_str: Optional[str] = None
    operands: List[str] = field(default_factory=list)
    is_directive: bool = False
    directive: Optional[str] = None
    rd_str: Optional[str] = None
    rs1_str: Optional[str] = None
    rs2_str: Optional[str] = None
    imm_val: Optional[int] = None
    csr_str: Optional[str] = None


class AssemblerError(Exception):
    def __init__(self, message: str, line_num: Optional[int] = None):
        if line_num:
            super().__init__(f"Assembly Error (Line {line_num}): {message}")
        else:
            super().__init__(f"Assembly Error: {message}")


class Assembler:
    def __init__(self, base_address: int = 0x1000):
        self.base_address = base_address
        self.labels: Dict[str, int] = {}
        self.register_map: Dict[str, int] = GPR_NAMES.copy()

        self.instr_defs: Dict[str, Tuple[str, int, Optional[int], Optional[int]]] = {
            "add": ("R", OPCODE_OP, F3_ADD_SUB, F7_ZERO),
            "sub": ("R", OPCODE_OP, F3_ADD_SUB, F7_SUB),
            "sll": ("R", OPCODE_OP, F3_SLL, F7_ZERO),
            "slt": ("R", OPCODE_OP, F3_SLT, F7_ZERO),
            "sltu": ("R", OPCODE_OP, F3_SLTU, F7_ZERO),
            "xor": ("R", OPCODE_OP, F3_XOR, F7_ZERO),
            "srl": ("R", OPCODE_OP, F3_SRL_SRA, F7_ZERO),
            "sra": ("R", OPCODE_OP, F3_SRL_SRA, F7_SRA),
            "or": ("R", OPCODE_OP, F3_OR, F7_ZERO),
            "and": ("R", OPCODE_OP, F3_AND, F7_ZERO),
            "addi": ("I_ALU", OPCODE_OP_IMM, F3_ADD_SUB, None),
            "slti": ("I_ALU", OPCODE_OP_IMM, F3_SLT, None),
            "sltiu": ("I_ALU", OPCODE_OP_IMM, F3_SLTU, None),
            "xori": ("I_ALU", OPCODE_OP_IMM, F3_XOR, None),
            "ori": ("I_ALU", OPCODE_OP_IMM, F3_OR, None),
            "andi": ("I_ALU", OPCODE_OP_IMM, F3_AND, None),
            "slli": ("I_SHIFT", OPCODE_OP_IMM, F3_SLL, F7_ZERO),
            "srli": ("I_SHIFT", OPCODE_OP_IMM, F3_SRL_SRA, F7_ZERO),
            "srai": ("I_SHIFT", OPCODE_OP_IMM, F3_SRL_SRA, F7_SRA),
            "lb": ("I_LOAD", OPCODE_LOAD, F3_LB, None),
            "lh": ("I_LOAD", OPCODE_LOAD, F3_LH, None),
            "lw": ("I_LOAD", OPCODE_LOAD, F3_LW, None),
            "lbu": ("I_LOAD", OPCODE_LOAD, F3_LBU, None),
            "lhu": ("I_LOAD", OPCODE_LOAD, F3_LHU, None),
            "jalr": ("I_JALR", OPCODE_JALR, F3_ADD_SUB, None),
            "sb": ("S", OPCODE_STORE, F3_SB, None),
            "sh": ("S", OPCODE_STORE, F3_SH, None),
            "sw": ("S", OPCODE_STORE, F3_SW, None),
            "beq": ("B", OPCODE_BRANCH, F3_BEQ, None),
            "bne": ("B", OPCODE_BRANCH, F3_BNE, None),
            "blt": ("B", OPCODE_BRANCH, F3_BLT, None),
            "bge": ("B", OPCODE_BRANCH, F3_BGE, None),
            "bltu": ("B", OPCODE_BRANCH, F3_BLTU, None),
            "bgeu": ("B", OPCODE_BRANCH, F3_BGEU, None),
            "lui": ("U", OPCODE_LUI, None, None),
            "auipc": ("U", OPCODE_AUIPC, None, None),
            "jal": ("J", OPCODE_JAL, None, None),
            "ecall": ("SYS_SIMPLE", OPCODE_SYSTEM, 0b0, SYSTEM_ECALL),
            "ebreak": ("SYS_SIMPLE", OPCODE_SYSTEM, 0b0, SYSTEM_EBREAK),
            "mret": ("SYS_SIMPLE", OPCODE_SYSTEM, 0b0, SYSTEM_MRET),
            "sret": ("SYS_SIMPLE", OPCODE_SYSTEM, 0b0, SYSTEM_SRET),
            "csrrw": ("CSR", OPCODE_SYSTEM, F3_CSRRW, None),
            "csrrs": ("CSR", OPCODE_SYSTEM, F3_CSRRS, None),
            "csrrc": ("CSR", OPCODE_SYSTEM, F3_CSRRC, None),
            "csrrwi": ("CSR_I", OPCODE_SYSTEM, F3_CSRRWI, None),
            "csrrsi": ("CSR_I", OPCODE_SYSTEM, F3_CSRRSI, None),
            "csrrci": ("CSR_I", OPCODE_SYSTEM, F3_CSRRCI, None),
        }
        self.pseudo_instructions = {
            "li",
            "mv",
            "nop",
            "j",
            "jr",
            "la",
            "neg",
            "not",
            "seqz",
            "snez",
            "sltz",
            "sgtz",
            "csrr",
            "csrw",
            "csrs",
            "csrc",
            "csrwi",
            "csrsi",
            "csrci",
        }

        self.label_pattern = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*):")
        self.comment_pattern = re.compile(r"[#;].*$")
        self.directive_pattern = re.compile(r"^\s*\.(\w+)(?:\s+(.*))?")

    def assemble(self, source_code: str) -> Dict[str, Union[List[int], bytearray, int]]:
        source_lines = source_code.splitlines()
        expanded_instructions, data_fragments = self._parse_and_expand(source_lines)
        data_section_base_addr = self._resolve_addresses_and_labels(
            expanded_instructions, data_fragments
        )
        machine_code = self._encode_instructions(expanded_instructions)
        data_bytes = self._generate_data_bytes(data_fragments)
        return {
            "text_start": self.base_address,
            "text": machine_code,
            "data_start": data_section_base_addr,
            "data": data_bytes,
        }

    def assemble_file_to_file(self, input_filepath: str, output_filepath: str):
        try:
            with open(input_filepath, "r", encoding="utf-8") as f:
                source_code = f.read()
            assembled_result = self.assemble(source_code)

            # Ghi mã nhị phân ra file .bin dưới dạng nhị phân
            with open(output_filepath, "wb") as f:  # Sửa từ "w" thành "wb"
                # Ghi phần 'text' (mã lệnh)
                for inst in assembled_result["text"]:
                    f.write(
                        inst.to_bytes(4, byteorder="little")
                    )  # Ghi trực tiếp số nguyên 32-bit
                # Ghi phần 'data' nếu có
                if "data" in assembled_result:
                    data_bytes = assembled_result["data"]
                    f.write(data_bytes)  # Ghi trực tiếp bytearray

            print(f"Assembly successful. Binary file written to '{output_filepath}'.")
            return True
        except AssemblerError as e:
            print(e)
            return False
        except Exception as e_gen:
            print(f"An unexpected error occurred: {e_gen}")
            import traceback

            traceback.print_exc()
            return False

    def _parse_and_expand(
        self, source_lines: List[str]
    ) -> Tuple[List[ParsedLine], List[ParsedLine]]:
        parsed_lines = self._parse_all_lines(source_lines)
        expanded_instructions, data_fragments, current_section = [], [], ".text"
        for pline in parsed_lines:
            if pline.is_directive and pline.directive in [".text", ".data"]:
                current_section = pline.directive
                if pline.label:
                    (
                        expanded_instructions
                        if current_section == ".text"
                        else data_fragments
                    ).append(pline)
                continue

            if current_section == ".text":
                if pline.is_instruction:
                    expanded = self._expand_pseudo_instruction(pline)
                    if pline.label and expanded:
                        expanded[0].label = pline.label
                    expanded_instructions.extend(expanded)
                elif pline.is_directive or pline.label:
                    expanded_instructions.append(pline)
            else:
                data_fragments.append(pline)
        return expanded_instructions, data_fragments

    def _resolve_addresses_and_labels(
        self, instructions: List[ParsedLine], data_fragments: List[ParsedLine]
    ) -> int:
        self.labels.clear()
        pc = self.base_address
        for item in instructions:
            if item.is_directive and item.directive == ".align":
                align_val = 1 << int(item.operands[0])
                pc = (pc + align_val - 1) & ~(align_val - 1)
            if item.label:
                if item.label in self.labels:
                    raise AssemblerError(
                        f"Duplicate label '{item.label}'", item.line_num
                    )
                self.labels[item.label] = pc
            if item.is_instruction:
                item.address = pc
                pc += 8 if item.opcode_str == "la" else 4
        text_size = pc - self.base_address
        data_section_base_addr = (self.base_address + text_size + 3) & ~3
        data_offset = 0
        for item in data_fragments:
            if item.is_directive and item.directive == ".align":
                align_val = 1 << int(item.operands[0])
                data_offset = (data_offset + align_val - 1) & ~(align_val - 1)
            if item.label:
                if item.label in self.labels:
                    raise AssemblerError(
                        f"Duplicate label '{item.label}'", item.line_num
                    )
                self.labels[item.label] = data_section_base_addr + data_offset
            if item.is_directive:
                if item.directive == ".word":
                    data_offset += len(item.operands) * 4
                elif item.directive == ".byte":
                    data_offset += len(item.operands)
                elif item.directive == ".asciz":
                    data_offset += len(item.operands[0]) + 1
        return data_section_base_addr

    def _encode_instructions(self, instructions: List[ParsedLine]) -> List[int]:
        machine_code = []
        for instr in instructions:
            if instr.is_instruction:
                if instr.opcode_str == "la":
                    for expanded_instr in self._expand_la_final(instr):
                        self._populate_fields(expanded_instr)
                        machine_code.append(self._encode_instruction(expanded_instr))
                else:
                    self._populate_fields(instr)
                    machine_code.append(self._encode_instruction(instr))
        return machine_code

    def _generate_data_bytes(self, data_fragments: List[ParsedLine]) -> bytearray:
        data_bytes = bytearray()
        for item in data_fragments:
            if not item.is_directive:
                continue
            if item.directive == ".align":
                align_val = 1 << int(item.operands[0])
                padding = (-len(data_bytes) % align_val) & (align_val - 1)
                data_bytes.extend(b"\x00" * padding)
            elif item.directive == ".word":
                for arg in item.operands:
                    val = self._parse_immediate(
                        arg, item.line_num, is_label_allowed=True
                    )
                    data_bytes.extend(val.to_bytes(4, "little", signed=True))
            elif item.directive == ".byte":
                for arg in item.operands:
                    val = self._parse_immediate(arg, item.line_num)
                    data_bytes.append(val & 0xFF)
            elif item.directive == ".asciz":
                data_bytes.extend(item.operands[0].encode("ascii"))
                data_bytes.append(0)
        return data_bytes

    def _generate_memory_image(self, assembled_result: dict) -> List[str]:
        memory_map: Dict[int, int] = {}
        text_start, text_code = assembled_result["text_start"], assembled_result["text"]
        for i, inst in enumerate(text_code):
            memory_map[text_start + i * 4] = inst
        data_start, data_bytes = assembled_result["data_start"], bytearray(
            assembled_result["data"]
        )
        while len(data_bytes) % 4 != 0:
            data_bytes.append(0)
        for i in range(0, len(data_bytes), 4):
            memory_map[data_start + i] = int.from_bytes(data_bytes[i : i + 4], "little")
        if not memory_map:
            return []
        min_addr = self.base_address
        last_text_addr = text_start + len(text_code) * 4
        last_data_addr = data_start + len(data_bytes)
        max_addr = (max(last_text_addr, last_data_addr) + 3) & ~3
        return [
            format_bin(memory_map.get(addr, 0), 32)
            for addr in range(min_addr, max_addr, 4)
        ]

    def _parse_all_lines(self, source_lines: List[str]) -> List[ParsedLine]:
        parsed_lines = []
        for n, line_str in enumerate(source_lines, 1):
            line = self._preprocess_line(line_str)
            if not line:
                continue
            label, content = (
                (
                    self.label_pattern.match(line).group(1).lower(),
                    line[self.label_pattern.match(line).end() :].strip(),
                )
                if self.label_pattern.match(line)
                else (None, line)
            )
            if not content:
                if label:
                    parsed_lines.append(ParsedLine(n, line_str, label=label))
                continue
            directive_match = self.directive_pattern.match(content)
            if directive_match:
                directive, args_str = directive_match.groups()
                operands = [arg.strip() for arg in (args_str or "").split(",") if arg]
                if directive.lower() in ["asciz", "string"]:
                    string_match = re.search(r'"((?:\\.|[^"\\])*)"', args_str or "")
                    if string_match:
                        operands = [
                            string_match.group(1).encode().decode("unicode_escape")
                        ]
                parsed_lines.append(
                    ParsedLine(
                        n,
                        line_str,
                        label=label,
                        is_directive=True,
                        directive=directive.lower(),
                        operands=operands,
                    )
                )
            else:
                parts = [p.strip() for p in content.replace(",", " ").split()]
                parsed_lines.append(
                    ParsedLine(
                        n,
                        line_str,
                        label=label,
                        is_instruction=True,
                        opcode_str=parts[0].lower(),
                        operands=parts[1:],
                    )
                )
        return parsed_lines

    def _preprocess_line(self, line: str) -> Optional[str]:
        return self.comment_pattern.sub("", line).strip() or None

    def _expand_pseudo_instruction(self, p_line: ParsedLine) -> List[ParsedLine]:
        op, ops, ln = p_line.opcode_str, p_line.operands, p_line.line_num

        def create(o, os, c=""):
            return ParsedLine(
                ln,
                f"{o} {' '.join(os)}; {c}",
                is_instruction=True,
                opcode_str=o,
                operands=os,
            )

        if op == "li":
            if len(ops) != 2:
                raise AssemblerError("'li' expects 2 operands", ln)
            imm = self._parse_immediate(ops[1], ln)
            if -2048 <= imm <= 2047:
                return [create("addi", [ops[0], "zero", str(imm)], "from li")]
            lo, hi = sign_extend(imm & 0xFFF, 12), imm - sign_extend(imm & 0xFFF, 12)
            return [
                create("lui", [ops[0], str(hi >> 12)], "from li"),
                create("addi", [ops[0], ops[0], str(lo)], "from li"),
            ]
        if op == "la":
            return [p_line]
        if op == "mv":
            return [create("addi", [ops[0], ops[1], "0"], "from mv")]
        if op == "nop":
            return [create("addi", ["zero", "zero", "0"], "from nop")]
        if op == "j":
            return [create("jal", ["zero", ops[0]], "from j")]
        if op == "jr":
            return [create("jalr", ["zero", ops[0], "0"], "from jr")]
        if op == "neg":
            return [create("sub", [ops[0], "zero", ops[1]], "from neg")]
        if op == "not":
            return [create("xori", [ops[0], ops[1], "-1"], "from not")]
        if op == "seqz":
            return [create("sltiu", [ops[0], ops[1], "1"], "from seqz")]
        if op == "snez":
            return [create("sltu", [ops[0], "zero", ops[1]], "from snez")]
        if op == "csrr":
            return [create("csrrs", [ops[0], ops[1], "zero"], "from csrr")]
        if op == "csrw":
            return [create("csrrw", ["zero", ops[0], ops[1]], "from csrw")]
        if op == "csrs":
            return [create("csrrs", ["zero", ops[0], ops[1]], "from csrs")]
        if op == "csrc":
            return [create("csrrc", ["zero", ops[0], ops[1]], "from csrc")]
        if op == "csrwi":
            return [create("csrrwi", ["zero", ops[0], ops[1]], "from csrwi")]
        if op == "csrsi":
            return [create("csrrsi", ["zero", ops[0], ops[1]], "from csrsi")]
        if op == "csrci":
            return [create("csrrci", ["zero", ops[0], ops[1]], "from csrci")]
        return [p_line]

    def _expand_la_final(self, p_line: ParsedLine) -> List[ParsedLine]:
        rd, label = p_line.operands[0], p_line.operands[1].lower()
        if label not in self.labels:
            raise AssemblerError(f"Undefined label '{label}'", p_line.line_num)
        offset = self.labels[label] - p_line.address
        lo = sign_extend(offset & 0xFFF, 12)
        hi = offset - lo

        def create(o, os, addr):
            return ParsedLine(p_line.line_num, "", addr, None, True, o, os)

        return [
            create("auipc", [rd, str(hi >> 12)], p_line.address),
            create("addi", [rd, rd, str(lo)], p_line.address + 4),
        ]

    def _populate_fields(self, p: ParsedLine):
        op, ops, addr, ln = p.opcode_str, p.operands, p.address, p.line_num
        if op not in self.instr_defs:
            raise AssemblerError(f"Unknown instruction '{op}'", ln)
        fmt = self.instr_defs[op][0]
        if fmt == "R":
            p.rd_str, p.rs1_str, p.rs2_str = ops
        elif fmt in ("I_ALU", "I_SHIFT"):
            p.rd_str, p.rs1_str, p.imm_val = (
                ops[0],
                ops[1],
                self._parse_immediate(ops[2], ln),
            )
        elif fmt == "I_JALR":
            p.rd_str, p.rs1_str, p.imm_val = (
                ops[0],
                ops[1],
                self._parse_immediate(ops[2], ln),
            )
        elif fmt == "I_LOAD":
            p.rd_str, (p.imm_val, p.rs1_str) = ops[0], self._parse_mem_operand(
                ops[1], ln
            )
        elif fmt == "S":
            p.rs2_str, (p.imm_val, p.rs1_str) = ops[0], self._parse_mem_operand(
                ops[1], ln
            )
        elif fmt == "B":
            p.rs1_str, p.rs2_str, p.imm_val = (
                ops[0],
                ops[1],
                self._parse_immediate(ops[2], ln, True, addr),
            )
        elif fmt == "U":
            p.rd_str, p.imm_val = ops[0], self._parse_immediate(ops[1], ln)
        elif fmt == "J":
            p.rd_str, p.imm_val = ops[0], self._parse_immediate(ops[1], ln, True, addr)
        elif fmt == "CSR":
            p.rd_str, p.csr_str, p.rs1_str = ops
        elif fmt == "CSR_I":
            p.rd_str, p.csr_str, p.imm_val = (
                ops[0],
                ops[1],
                self._parse_immediate(ops[2], ln),
            )

    def _encode_instruction(self, p: ParsedLine) -> int:
        fmt, op, f3, f7 = self.instr_defs[p.opcode_str]
        rd = self._parse_register(p.rd_str, p.line_num) if p.rd_str else 0
        rs1 = self._parse_register(p.rs1_str, p.line_num) if p.rs1_str else 0
        rs2 = self._parse_register(p.rs2_str, p.line_num) if p.rs2_str else 0
        imm = p.imm_val if p.imm_val is not None else 0
        if fmt == "R":
            return (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
        if fmt in ("I_ALU", "I_JALR", "I_LOAD"):
            return ((imm & 0xFFF) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
        if fmt == "I_SHIFT":
            return (
                (f7 << 25)
                | ((imm & 0x1F) << 20)
                | (rs1 << 15)
                | (f3 << 12)
                | (rd << 7)
                | op
            )
        if fmt == "S":
            return (
                (((imm >> 5) & 0x7F) << 25)
                | (rs2 << 20)
                | (rs1 << 15)
                | (f3 << 12)
                | ((imm & 0x1F) << 7)
                | op
            )
        if fmt == "B":
            imm13 = sign_extend(imm, 13)
            return (
                (((imm13 >> 12) & 1) << 31)
                | (((imm13 >> 5) & 0x3F) << 25)
                | (rs2 << 20)
                | (rs1 << 15)
                | (f3 << 12)
                | (((imm13 >> 1) & 0xF) << 8)
                | (((imm13 >> 11) & 1) << 7)
                | op
            )
        if fmt == "U":
            return (imm & 0xFFFFF000) | (rd << 7) | op
        if fmt == "J":
            imm21 = sign_extend(imm, 21)
            return (
                (((imm21 >> 20) & 1) << 31)
                | (((imm21 >> 1) & 0x3FF) << 21)
                | (((imm21 >> 11) & 1) << 20)
                | (((imm21 >> 12) & 0xFF) << 12)
                | (rd << 7)
                | op
            )
        if fmt == "SYS_SIMPLE":
            return (f7 << 20) | op
        if fmt in ("CSR", "CSR_I"):
            csr = self._parse_csr_name_or_addr(p.csr_str, p.line_num)
            src = rs1 if fmt == "CSR" else (imm & 0x1F)
            return (csr << 20) | (src << 15) | (f3 << 12) | (rd << 7) | op
        raise AssemblerError(f"Unknown format '{fmt}' for encoding", p.line_num)

    def _parse_register(self, reg_str: str, line_num: int) -> int:
        reg_lower = reg_str.lower()
        if reg_lower not in self.register_map:
            raise AssemblerError(f"Invalid register '{reg_str}'", line_num)
        return self.register_map[reg_lower]

    def _parse_immediate(
        self,
        imm_str: str,
        line_num: int,
        is_label_allowed: bool = False,
        current_pc: int = 0,
    ) -> int:
        imm_lower = imm_str.lower()
        if is_label_allowed:
            if imm_lower in self.labels:
                return (
                    self.labels[imm_lower] - current_pc
                    if current_pc != 0
                    else self.labels[imm_lower]
                )
        try:
            return int(imm_lower, 0)
        except ValueError:
            raise AssemblerError(
                f"Invalid immediate or undefined label '{imm_str}'", line_num
            )

    def _parse_mem_operand(self, s: str, ln: int) -> Tuple[int, str]:
        m = re.fullmatch(r"(-?[\w\.]+)\s*\(\s*([a-zA-Z0-9_]+)\s*\)", s)
        if not m:
            raise AssemblerError(f"Invalid memory operand format '{s}'", ln)
        return self._parse_immediate(m.group(1), ln), m.group(2).lower()

    def _parse_csr_name_or_addr(self, csr_str: str, line_num: int) -> int:
        csr_lower = csr_str.lower()
        if csr_lower in CSR_NAMES:
            return CSR_NAMES[csr_lower]
        try:
            val = self._parse_immediate(csr_lower, line_num)
            if not (0 <= val <= 0xFFF):
                raise AssemblerError(f"CSR address '{csr_str}' out of range", line_num)
            return val
        except AssemblerError:
            raise AssemblerError(f"Invalid CSR name or address '{csr_str}'", line_num)


if __name__ == "__main__":
    INPUT_FILE = "test_2.s"
    OUTPUT_FILE = "program_binary.bin"
    BASE_ADDRESS = 0x1000
    project_root = (
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if "src" in __file__
        else "."
    )
    input_path = os.path.join(project_root, INPUT_FILE)
    output_path = os.path.join(project_root, OUTPUT_FILE)
    try:
        assembler = Assembler(base_address=BASE_ADDRESS)
        success = assembler.assemble_file_to_file(input_path, output_path)
        if success:
            print("\nHoàn tất! File nhị phân đã được tạo thành công.")
        else:
            print("\nThất bại! Đã có lỗi xảy ra trong quá trình hợp dịch.")
    except FileNotFoundError:
        print(f"\nLỖI: Không tìm thấy file đầu vào '{input_path}'.")
        print("Hãy chắc chắn rằng bạn đã tạo file này trong thư mục gốc của dự án.")
    except Exception as e:
        print(f"\nLỖI KHÔNG XÁC ĐỊNH: {e}")
        import traceback

        traceback.print_exc()
