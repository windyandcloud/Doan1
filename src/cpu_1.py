# src/cpu.py
import traceback
from dataclasses import dataclass
from typing import Optional, List, Dict, Union
from mem import Memory, MemSize
from reg_file import RegisterFile
from csr import CSRFile, UnimplementedCSRError, PermissionError
from regnames import get_csr_name
from utils import *
from mmu import *
from isa_defs import *
from trap_handler import common_trap_handler
from assembler_1 import Assembler, AssemblerError
from sret import *
from mret import *

@dataclass
class CPUState:
    pc: int = 0
    next_pc: int = 0
    priv_mode: PrivMode = PrivMode.MACHINE
    halt_simulation: bool = False
    exit_code: int = 0
    debug_prints: bool = False
    trap_pending: bool = False

class CPU:
    def __init__(self, rom_base_addr: int = 0x1000, rom_size_bytes: int = 0x100000):
        """Khởi tạo CPU với các thành phần cơ bản."""
        self.state = CPUState(pc=rom_base_addr, next_pc=rom_base_addr)
        self.registers = RegisterFile()
        self.csrs = CSRFile(rom_base_addr=rom_base_addr)
        self.memory = Memory(size=rom_size_bytes)
        self.mmu = MMU(self.csrs, self.memory)
        self.set_debug_mode(self.state.debug_prints)

    def set_debug_mode(self, enabled: bool):
        """Bật/tắt chế độ gỡ lỗi."""
        self.state.debug_prints = enabled
        self.csrs.debug_prints_active = enabled

    def load_program(self, assembled_result: Dict[str, Union[List[int], bytearray, int]]):
        """Nạp chương trình đã hợp dịch vào bộ nhớ."""
        self.memory.reset()
        text_section = assembled_result.get('text', [])
        text_start_addr = assembled_result.get('text_start', self.state.pc)
        if text_section:
            if self.state.debug_prints:
                print(f"DEBUG [CPU]: Đang nạp {len(text_section)} lệnh vào .text tại 0x{text_start_addr:X}")
            for i, inst_word in enumerate(text_section):
                self.memory.store(text_start_addr + (i * 4), inst_word, MemSize.WORD)
        
        data_section = assembled_result.get('data', bytearray())
        data_start_addr = assembled_result.get('data_start')
        if data_section and data_start_addr is not None:
            if self.state.debug_prints:
                print(f"DEBUG [CPU]: Đang nạp {len(data_section)} bytes vào .data tại 0x{data_start_addr:X}")
            for i, byte_val in enumerate(data_section):
                self.memory.store(data_start_addr + i, byte_val, MemSize.BYTE)
        
        self.state.pc = text_start_addr
        self.state.next_pc = text_start_addr

    def load_program_from_bin(self, bin_filepath: str, text_start: int = 0x00001000):
        """Nạp chương trình từ file .bin vào bộ nhớ."""
        try:
            with open(bin_filepath, 'rb') as f:
                binary_data = f.read()
            
            # Giả định toàn bộ file là phần 'text'
            text_size = len(binary_data)
            for i in range(0, text_size, 4):
                if i + 4 > text_size:
                    break
                instruction = int.from_bytes(binary_data[i:i+4], byteorder='little')
                self.memory.store(text_start + i, instruction, MemSize.WORD)
            
            self.state.pc = text_start
            self.state.next_pc = text_start
            print(f"Đã nạp chương trình từ file '{bin_filepath}' vào bộ nhớ tại 0x{text_start:08x}.")
        except Exception as e:
            print(f"Lỗi khi nạp file .bin: {e}")
            raise

    def _get_effective_privilege_for_memory_access(self) -> PrivMode:
        """Xác định chế độ quyền hạn hiệu quả cho truy cập bộ nhớ."""
        if self.state.priv_mode == PrivMode.MACHINE and (self.csrs.read(CSR_ADDR["mstatus"], PrivMode.MACHINE) & MSTATUS_MPRV):
            return PrivMode((self.csrs.read(CSR_ADDR["mstatus"], PrivMode.MACHINE) & MSTATUS_MPP) >> MSTATUS_MPP_SHIFT)
        return self.state.priv_mode

    def _check_and_handle_interrupts(self) -> bool:
        """Kiểm tra và xử lý ngắt trong mỗi chu kỳ."""
        if self.state.halt_simulation or self.state.trap_pending:
            return False
        
        mstatus = self.csrs.read(CSR_ADDR["mstatus"], PrivMode.MACHINE)
        mie = self.csrs.read(CSR_ADDR["mie"], PrivMode.MACHINE)
        mip = self.csrs.read(CSR_ADDR["mip"], PrivMode.MACHINE)
        mideleg = self.csrs.read(CSR_ADDR["mideleg"], PrivMode.MACHINE)
        
        interrupt_cause = 0
        can_handle_m_irq = ((mstatus & MSTATUS_MIE) != 0) or (self.state.priv_mode < PrivMode.MACHINE)
        if can_handle_m_irq:
            if (mip & MIP_MEIP) and (mie & MIE_MEIE):
                interrupt_cause = INT_M_EXTERNAL | CAUSE_INTERRUPT_FLAG
            elif (mip & MIP_MSIP) and (mie & MIE_MSIE):
                interrupt_cause = INT_M_SOFTWARE | CAUSE_INTERRUPT_FLAG
        
        if interrupt_cause == 0:
            can_handle_s_irq = ((mstatus & MSTATUS_SIE) != 0) or (self.state.priv_mode < PrivMode.SUPERVISOR)
            if can_handle_s_irq:
                delegated_mip = mip & mideleg
                delegated_mie = mie & mideleg
                if (delegated_mip & MIP_SEIP) and (delegated_mie & MIE_SEIE):
                    interrupt_cause = INT_S_EXTERNAL | CAUSE_INTERRUPT_FLAG
                elif (delegated_mip & MIP_SSIP) and (delegated_mie & MIE_SSIE):
                    interrupt_cause = INT_S_SOFTWARE | CAUSE_INTERRUPT_FLAG
        
        if interrupt_cause != 0:
            if self.state.debug_prints:
                print(f"DEBUG [CPU_IRQ]: Taking interrupt. Cause=0x{interrupt_cause:08x}")
            self.state.trap_pending = True
            common_trap_handler(self, interrupt_cause, 0)
            return True
        return False

    def _fetch_instruction(self) -> Optional[int]:
        """Lấy lệnh từ bộ nhớ."""
        current_pc = self.state.pc
        if current_pc < 0x00001000 or current_pc >= 0x00002000:
            common_trap_handler(self, CAUSE_FETCH_ACCESS, current_pc)
            return None
        try: 
            phys_addr = self.mmu.translate_address(
            current_pc, self.state.priv_mode, "FETCH", MemSize.WORD
        )
            inst_word = self.memory.load(phys_addr, MemSize.WORD)
            return inst_word
        except MMU_Error as e:
            common_trap_handler(self, e.cause, e.addr)
        except MemoryError as e:
            common_trap_handler(self, CAUSE_FETCH_ACCESS, e.addr)
            return None
        except Exception as e:
            common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, current_pc)
            return None

    def _decode_and_execute_instruction(self, inst_word: int):
        """Giải mã và thực thi lệnh."""
        opcode = inst_word & 0x7F
        rd = (inst_word >> 7) & 0x1F
        funct3 = (inst_word >> 12) & 0x7
        rs1 = (inst_word >> 15) & 0x1F
        rs2 = (inst_word >> 20) & 0x1F
        
        self.state.next_pc = self.state.pc + 4
        
        try:
            if opcode == OPCODE_LUI:
                self._execute_lui(inst_word, rd)
            elif opcode == OPCODE_AUIPC:
                self._execute_auipc(inst_word, rd)
            elif opcode == OPCODE_JAL:
                self._execute_jal(inst_word, rd)
            elif opcode == OPCODE_JALR:
                self._execute_jalr(inst_word, rd, rs1)
            elif opcode == OPCODE_BRANCH:
                self._execute_branch(inst_word, rs1, rs2, funct3)
            elif opcode == OPCODE_LOAD:
                self._execute_load(inst_word, rd, rs1, funct3)
            elif opcode == OPCODE_STORE:
                self._execute_store(inst_word, rs1, rs2, funct3)
            elif opcode == OPCODE_OP_IMM:
                self._execute_op_imm(inst_word, rd, rs1, funct3)
            elif opcode == OPCODE_OP:
                self._execute_r_type(inst_word, rd, rs1, rs2, funct3)
            elif opcode == OPCODE_SYSTEM:
                self._execute_system(inst_word, rd, rs1, funct3)
            elif opcode == OPCODE_MISC_MEM:
                if self.state.debug_prints:
                    print(f"  └─ FENCE/FENCE.I (NOP)")
            else:
                common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
        except MemoryError as e:
            common_trap_handler(self, e.cause, e.addr)
        except (PermissionError, UnimplementedCSRError) as e:
            if self.state.debug_prints:
                print(f"LỖI CSR [CPU_EXEC]: PC={format_hex(self.state.pc)}: {e}")
            common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
        except Exception as e:
            if self.state.debug_prints:
                print(f"LỖI PYTHON [CPU_EXEC]: PC={format_hex(self.state.pc)}, INST=0x{inst_word:08x}: {e}")
            traceback.print_exc()
            common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)

    def _execute_lui(self, inst_word: int, rd: int):
        """Thực thi lệnh LUI."""
        imm_u = inst_word & 0xFFFFF000
        if rd != 0:
            self.registers.write(rd, imm_u)
        if self.state.debug_prints:
            print(f"  └─ LUI x{rd}, 0x{imm_u >> 12:05x} -> x{rd}=0x{imm_u:08x}")

    def _execute_auipc(self, inst_word: int, rd: int):
        """Thực thi lệnh AUIPC."""
        imm_u = inst_word & 0xFFFFF000
        res = (self.state.pc + imm_u) & 0xFFFFFFFF
        if rd != 0:
            self.registers.write(rd, res)
        if self.state.debug_prints:
            print(f"  └─ AUIPC x{rd}, 0x{imm_u >> 12:05x} -> x{rd}=0x{res:08x}")

    def _execute_jal(self, inst_word: int, rd: int):
        """Thực thi lệnh JAL."""
        imm20 = (inst_word >> 31) & 1
        imm10_1 = (inst_word >> 21) & 0x3FF
        imm11 = (inst_word >> 20) & 1
        imm19_12 = (inst_word >> 12) & 0xFF
        imm_j = sign_extend((imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1), 21)
        if rd != 0:
            self.registers.write(rd, self.state.pc + 4)
        self.state.next_pc = (self.state.pc + imm_j) & 0xFFFFFFFF
        if self.state.debug_prints:
            print(f"  └─ JAL x{rd}, {imm_j} -> next_pc=0x{self.state.next_pc:08x}")

    def _execute_jalr(self, inst_word: int, rd: int, rs1: int):
        """Thực thi lệnh JALR."""
        imm_i = sign_extend((inst_word >> 20), 12)
        base = self.registers.read(rs1)
        target_pc = (base + imm_i) & ~1
        if rd != 0:
            self.registers.write(rd, self.state.pc + 4)
        self.state.next_pc = target_pc
        if self.state.debug_prints:
            print(f"  └─ JALR x{rd}, x{rs1}, {imm_i} -> next_pc=0x{self.state.next_pc:08x}")

    def _execute_branch(self, inst_word: int, rs1: int, rs2: int, funct3: int):
        """Thực thi lệnh nhảy có điều kiện."""
        imm = sign_extend((((inst_word >> 31) & 1) << 12) | (((inst_word >> 7) & 1) << 11) |
                          (((inst_word >> 25) & 0x3F) << 5) | (((inst_word >> 8) & 0xF) << 1), 13)
        val_rs1 = self.registers.read(rs1)
        val_rs2 = self.registers.read(rs2)
        taken = False
        op_name = "BRANCH?"
        
        if funct3 == F3_BEQ:
            op_name, taken = "BEQ", val_rs1 == val_rs2
        elif funct3 == F3_BNE:
            op_name, taken = "BNE", val_rs1 != val_rs2
        elif funct3 == F3_BLT:
            op_name, taken = "BLT", sign_extend(val_rs1, 32) < sign_extend(val_rs2, 32)
        elif funct3 == F3_BGE:
            op_name, taken = "BGE", sign_extend(val_rs1, 32) >= sign_extend(val_rs2, 32)
        elif funct3 == F3_BLTU:
            op_name, taken = "BLTU", val_rs1 < val_rs2
        elif funct3 == F3_BGEU:
            op_name, taken = "BGEU", val_rs1 >= val_rs2
        else:
            common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
            return
        
        if taken:
            self.state.next_pc = (self.state.pc + imm) & 0xFFFFFFFF
        if self.state.debug_prints:
            print(f"  └─ {op_name} x{rs1}(0x{val_rs1:x}), x{rs2}(0x{val_rs2:x}), offset={imm} -> "
                  f"{'Taken' if taken else 'Not Taken'}{f', NewPC=0x{self.state.next_pc:08x}' if taken else ''}")

    def _execute_load(self, inst_word: int, rd: int, rs1: int, funct3: int):
        """Thực thi lệnh nạp dữ liệu."""
        imm = sign_extend(inst_word >> 20, 12)
        addr = (self.registers.read(rs1) + imm) & 0xFFFFFFFF
        eff_priv = self._get_effective_privilege_for_memory_access()
        
        if funct3 == F3_LB:
            size, op_name, signed = MemSize.BYTE, "LB", True
        elif funct3 == F3_LH:
            size, op_name, signed = MemSize.HALFWORD, "LH", True
        elif funct3 == F3_LW:
            size, op_name, signed = MemSize.WORD, "LW", True
        elif funct3 == F3_LBU:
            size, op_name, signed = MemSize.BYTE, "LBU", False
        elif funct3 == F3_LHU:
            size, op_name, signed = MemSize.HALFWORD, "LHU", False
        else:
            common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
            return
        
        phys_addr = self.mmu.translate_address(addr, eff_priv, "LOAD", size)
        val = self.memory.load(phys_addr, size)
        if signed:
            val = sign_extend(val, size * 8)
        if rd != 0:
            self.registers.write(rd, val)
        if self.state.debug_prints:
            print(f"  └─ {op_name} x{rd}, {imm}(x{rs1}) | Mem[0x{phys_addr:08x}] -> x{rd}=0x{val:08x}")

    def _execute_store(self, inst_word: int, rs1: int, rs2: int, funct3: int):
        """Thực thi lệnh lưu dữ liệu."""
        imm = sign_extend(((inst_word >> 25) << 5) | ((inst_word >> 7) & 0x1F), 12)
        addr = (self.registers.read(rs1) + imm) & 0xFFFFFFFF
        val = self.registers.read(rs2)
        eff_priv = self._get_effective_privilege_for_memory_access()
        
        if funct3 == F3_SB:
            size, op_name = MemSize.BYTE, "SB"
        elif funct3 == F3_SH:
            size, op_name = MemSize.HALFWORD, "SH"
        elif funct3 == F3_SW:
            size, op_name = MemSize.WORD, "SW"
        else:
            common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
            return
        
        phys_addr = self.mmu.translate_address(addr, eff_priv, "STORE", size)
        self.memory.store(phys_addr, val, size)
        if self.state.debug_prints:
            print(f"  └─ {op_name} x{rs2}, {imm}(x{rs1}) | Mem[0x{phys_addr:08x}] = 0x{val:08x}")

    def _execute_op_imm(self, inst_word: int, rd: int, rs1: int, funct3: int):
        """Thực thi lệnh số học tức thì."""
        imm = sign_extend(inst_word >> 20, 12)
        val_rs1 = self.registers.read(rs1)
        shamt = (inst_word >> 20) & 0x1F
        funct7 = (inst_word >> 25) & 0x7F
        
        if funct3 == F3_ADD_SUB:
            op_name, res = "ADDI", (val_rs1 + imm) & 0xFFFFFFFF
        elif funct3 == F3_SLT:
            op_name, res = "SLTI", 1 if sign_extend(val_rs1, 32) < imm else 0
        elif funct3 == F3_SLTU:
            op_name, res = "SLTIU", 1 if val_rs1 < imm else 0
        elif funct3 == F3_XOR:
            op_name, res = "XORI", val_rs1 ^ imm
        elif funct3 == F3_OR:
            op_name, res = "ORI", val_rs1 | imm
        elif funct3 == F3_AND:
            op_name, res = "ANDI", val_rs1 & imm
        elif funct3 == F3_SLL:
            if funct7 != F7_ZERO:
                common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
                return
            op_name, res = "SLLI", (val_rs1 << shamt) & 0xFFFFFFFF
        elif funct3 == F3_SRL_SRA:
            if funct7 == F7_ZERO:
                op_name, res = "SRLI", val_rs1 >> shamt
            elif funct7 == F7_SRA:
                op_name, res = "SRAI", sign_extend(val_rs1, 32) >> shamt
            else:
                common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
                return
        else:
            common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
            return
        
        if rd != 0:
            self.registers.write(rd, res)
        if self.state.debug_prints:
            print(f"  └─ {op_name} x{rd}, x{rs1}, {shamt if funct3 in [F3_SLL, F3_SRL_SRA] else imm} -> x{rd}=0x{res:08x}")

    def _execute_r_type(self, inst_word: int, rd: int, rs1: int, rs2: int, funct3: int):
        """Thực thi lệnh số học kiểu R."""
        val_rs1 = self.registers.read(rs1)
        val_rs2 = self.registers.read(rs2)
        funct7 = inst_word >> 25
        
        if funct3 == F3_ADD_SUB:
            if funct7 == F7_ZERO:
                op_name, res = "ADD", (val_rs1 + val_rs2) & 0xFFFFFFFF
            elif funct7 == F7_SUB:
                op_name, res = "SUB", (val_rs1 - val_rs2) & 0xFFFFFFFF
            else:
                common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
                return
        elif funct3 == F3_SLL:
            op_name, res = "SLL", (val_rs1 << (val_rs2 & 0x1F)) & 0xFFFFFFFF
        elif funct3 == F3_SLT:
            op_name, res = "SLT", 1 if sign_extend(val_rs1, 32) < sign_extend(val_rs2, 32) else 0
        elif funct3 == F3_SLTU:
            op_name, res = "SLTU", 1 if val_rs1 < val_rs2 else 0
        elif funct3 == F3_XOR:
            op_name, res = "XOR", val_rs1 ^ val_rs2
        elif funct3 == F3_SRL_SRA:
            if funct7 == F7_ZERO:
                op_name, res = "SRL", val_rs1 >> (val_rs2 & 0x1F)
            elif funct7 == F7_SRA:
                op_name, res = "SRA", sign_extend(val_rs1, 32) >> (val_rs2 & 0x1F)
            else:
                common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
                return
        elif funct3 == F3_OR:
            op_name, res = "OR", val_rs1 | val_rs2
        elif funct3 == F3_AND:
            op_name, res = "AND", val_rs1 & val_rs2
        else:
            common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
            return
        
        if rd != 0:
            self.registers.write(rd, res)
        if self.state.debug_prints:
            print(f"  └─ {op_name} x{rd}, x{rs1}, x{rs2} -> x{rd}=0x{res:08x}")

    def _execute_system(self, inst_word: int, rd: int, rs1: int, funct3: int):
        """Thực thi lệnh hệ thống."""
        funct12 = inst_word >> 20
        if funct3 == 0b000:  # ECALL, EBREAK, xRET, WFI
            if funct12 == SYSTEM_ECALL:
                cause = {PrivMode.USER: CAUSE_USER_ECALL, PrivMode.SUPERVISOR: CAUSE_SUPERVISOR_ECALL,
                         PrivMode.MACHINE: CAUSE_MACHINE_ECALL}[self.state.priv_mode]
                common_trap_handler(self, cause, self.state.pc)
            elif funct12 == SYSTEM_EBREAK:
                common_trap_handler(self, CAUSE_BREAKPOINT, self.state.pc)
            elif funct12 == SYSTEM_MRET:
                mret(self)
            elif funct12 == SYSTEM_SRET:
                sret(self)
            elif funct12 == SYSTEM_WFI:
                if self.state.priv_mode == PrivMode.USER or (
                        self.state.priv_mode == PrivMode.SUPERVISOR and
                        (self.csrs.read(CSR_ADDR["mstatus"], PrivMode.MACHINE) & MSTATUS_TW)):
                    common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
                else:
                    if self.state.debug_prints:
                        print(f"  └─ WFI (NOP)")
            else:
                common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
        else:  # CSR instructions
            csr_addr = funct12
            try:
                old_val = self.csrs.read(csr_addr, self.state.priv_mode)
                is_imm = funct3 & 0b100
                src_val = rs1 if is_imm else self.registers.read(rs1)
                
                if funct3 & 0b011 == F3_CSRRW:
                    new_val = src_val
                elif funct3 & 0b011 == F3_CSRRS:
                    new_val = old_val | src_val
                elif funct3 & 0b011 == F3_CSRRC:
                    new_val = old_val & ~src_val
                else:
                    common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)
                    return
                
                if (is_imm and rs1 != 0) or not is_imm:
                    self.csrs.write(csr_addr, new_val, self.state.priv_mode)
                if rd != 0:
                    self.registers.write(rd, old_val)
                if self.state.debug_prints:
                    print(f"  └─ CSR instruction: {get_csr_name(csr_addr)} = 0x{new_val:08x}")
            except (PermissionError, UnimplementedCSRError) as e:
                if self.state.debug_prints:
                    print(f"  └─ CSR Exception: {e}")
                common_trap_handler(self, CAUSE_ILLEGAL_INSTRUCTION, inst_word)

    def step(self):
        """Thực hiện một chu kỳ CPU."""
        if self.state.halt_simulation:
            return
        
        trap_occurred = self._check_and_handle_interrupts()
        if not trap_occurred:
            if self.state.debug_prints:
                print(f"PC:{format_hex(self.state.pc)} M={self.state.priv_mode.name[0]} Cyc:{self.csrs.internal_cycle_counter}")
            inst_word = self._fetch_instruction()
            if inst_word is not None:
                self._decode_and_execute_instruction(inst_word)
                instructions_retired = 1 if not self.state.trap_pending else 0
                self.csrs.update_performance_counters(cycles_increment=1, instructions_retired_increment=instructions_retired)
        
        if not self.state.halt_simulation:
            self.state.pc = self.state.next_pc
        self.state.trap_pending = False

    def run(self, max_cycles: Optional[int] = None):
        """Chạy mô phỏng CPU."""
        run_cycle_count = 0
        cycle_limit = float("inf") if max_cycles is None or max_cycles <= 0 else max_cycles
        print(f"CPU_RUN Bắt đầu: PC={format_hex(self.state.pc)}, MaxCycles={max_cycles if max_cycles else 'Không giới hạn'}")
        
        try:
            while not self.state.halt_simulation and run_cycle_count < cycle_limit:
                self.step()
                run_cycle_count += 1
        except Exception as e:
            print(f"\n!!! LỖI PYTHON NGHIÊM TRỌNG TRONG CPU.RUN/STEP @ Chu kỳ {self.csrs.internal_cycle_counter} !!!")
            print(f"  PC={format_hex(self.state.pc)}, Lỗi: {e}")
            traceback.print_exc()
            self.state.halt_simulation = True
            self.state.exit_code = -99
        
        total_cycles = self.csrs.internal_cycle_counter
        total_instructions = self.csrs.internal_instret_counter
        reason = "Đạt số chu kỳ tối đa" if run_cycle_count >= cycle_limit else f"Dừng bởi halt_simulation (Mã thoát: {self.state.exit_code})"
        print(f"\nCPU_RUN Kết thúc: Lý do: {reason}.")
        print(f"  PC cuối cùng={format_hex(self.state.pc)}, Chế độ đặc quyền={self.state.priv_mode.name}")
        print(f"  Tổng chu kỳ={total_cycles}, Số lệnh hoàn thành={total_instructions}")
        if total_cycles > 0 and total_instructions > 0:
            print(f"  IPC: {total_instructions / total_cycles:.3f}")
        print(self.dump_state_verbose())

    def dump_state_verbose(self) -> str:
        """In trạng thái chi tiết của CPU."""
        lines = [
            f"=== Trạng thái CPU (Chu kỳ: {self.csrs.internal_cycle_counter}) ===",
            f"PC: {format_hex(self.state.pc)}, NextPC: {format_hex(self.state.next_pc)}, Đặc quyền: {self.state.priv_mode.name}",
            f"Đã dừng: {self.state.halt_simulation}, Mã thoát: {self.state.exit_code}",
            "\n" + self.registers.dump_to_string(),
            "\n--- CSR chính (M-mode) ---",
        ]
        key_csrs = ["mstatus", "mie", "mip", "mepc", "mcause", "mtval", "mtvec", "mideleg", "medeleg",
                    "sstatus", "sie", "sip", "sepc", "scause", "stval", "stvec", "satp", "cycle", "instret"]
        for name in key_csrs:
            addr = CSR_ADDR.get(name.lower())
            if addr is not None:
                try:
                    val = self.csrs.read(addr, PrivMode.MACHINE)
                    lines.append(f"  {name:<12}: {format_hex(val)}")
                except Exception as e:
                    lines.append(f"  {name:<12}: Lỗi ({type(e).__name__})")
        return "\n".join(lines)