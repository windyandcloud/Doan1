# csr.py
from typing import Dict
from isa_defs import *
from regnames import get_csr_name
from utils import format_hex

class UnimplementedCSRError(Exception):
    def __init__(self, csr_addr: int, message: str = "Truy cập CSR chưa được triển khai"):
        self.csr_addr = csr_addr
        self.message = f"{message}: {format_hex(csr_addr, 3)}"
        super().__init__(self.message)

class PermissionError(Exception):
    pass

class CSRFile:
    def __init__(self, rom_base_addr: int = 0x00001000):
        initial_mstatus = (PrivMode.MACHINE << MSTATUS_MPP_SHIFT)
        initial_misa = (1 << 30) | (1 << (ord('I') - ord('A')))  # RV32I
        self.registers: Dict[int, int] = {
            CSR_ADDR["mvendorid"]: 0x0, CSR_ADDR["marchid"]: 0x0, CSR_ADDR["mimpid"]: 0x0, CSR_ADDR["mhartid"]: 0x0,
            CSR_ADDR["mstatus"]: initial_mstatus, CSR_ADDR["misa"]: initial_misa,
            CSR_ADDR["medeleg"]: 0xFFFFFFFF, CSR_ADDR["mideleg"]: 0x0, CSR_ADDR["mie"]: 0x0,
            CSR_ADDR["mtvec"]: rom_base_addr, CSR_ADDR["mcounteren"]: 0x0,
            CSR_ADDR["mcountinhibit"]: 0x0,  
            CSR_ADDR["mscratch"]: 0x0, CSR_ADDR["mepc"]: 0x0, CSR_ADDR["mcause"]: 0x0,
            CSR_ADDR["mtval"]: 0x0, CSR_ADDR["mip"]: 0x0,
            CSR_ADDR["sstatus"]: 0x0, CSR_ADDR["sie"]: 0x0, CSR_ADDR["stvec"]: 0x0,
            CSR_ADDR["scounteren"]: 0x0, CSR_ADDR["sscratch"]: 0x0, CSR_ADDR["sepc"]: 0x0,
            CSR_ADDR["scause"]: 0x0, CSR_ADDR["stval"]: 0x0, CSR_ADDR["sip"]: 0x0,
            CSR_ADDR["satp"]: 0x0,
            CSR_ADDR["cycle"]: 0x0, CSR_ADDR["instret"]: 0x0, CSR_ADDR["cycleh"]: 0x0, CSR_ADDR["instreth"]: 0x0
        }
        self.internal_cycle_counter: int = 0
        self.internal_instret_counter: int = 0
        self.debug_prints_active: bool = False

    def _get_required_privilege_for_csr(self, csr_addr: int) -> PrivMode:
        return PrivMode((csr_addr >> 8) & 0x3)

    def _is_csr_readonly_by_addr(self, csr_addr: int) -> bool:
        return ((csr_addr >> 10) & 0x3) == 0b11

    def _check_read_permission(self, csr_addr: int, current_priv: PrivMode):
        required_priv = self._get_required_privilege_for_csr(csr_addr)
        if current_priv < required_priv:
            raise PermissionError(f"Đặc quyền {current_priv.name} không đủ để đọc CSR {get_csr_name(csr_addr)}")
        if csr_addr in [CSR_ADDR["sstatus"], CSR_ADDR["sie"], CSR_ADDR["sip"], CSR_ADDR["stvec"], CSR_ADDR["scounteren"], CSR_ADDR["sscratch"], CSR_ADDR["sepc"], CSR_ADDR["scause"], CSR_ADDR["stval"], CSR_ADDR["satp"]]:
            if current_priv < PrivMode.SUPERVISOR:
                raise PermissionError(f"Đặc quyền {current_priv.name} không đủ để đọc CSR S-mode {get_csr_name(csr_addr)}")

    def _check_write_permission(self, csr_addr: int, current_priv: PrivMode):
        required_priv = self._get_required_privilege_for_csr(csr_addr)
        if current_priv < required_priv:
            raise PermissionError(f"Đặc quyền {current_priv.name} không đủ để ghi CSR {get_csr_name(csr_addr)}")
        if self._is_csr_readonly_by_addr(csr_addr):
            raise PermissionError(f"Cố gắng ghi vào CSR chỉ đọc: {get_csr_name(csr_addr)}")
        if csr_addr in [CSR_ADDR["mvendorid"], CSR_ADDR["marchid"], CSR_ADDR["mimpid"], CSR_ADDR["mhartid"], CSR_ADDR["cycle"], CSR_ADDR["instret"], CSR_ADDR["cycleh"], CSR_ADDR["instreth"]]:
            raise PermissionError(f"Cố gắng ghi vào CSR chỉ đọc: {get_csr_name(csr_addr)}")
        if csr_addr in [CSR_ADDR["sstatus"], CSR_ADDR["sie"], CSR_ADDR["sip"], CSR_ADDR["stvec"], CSR_ADDR["scounteren"], CSR_ADDR["sscratch"], CSR_ADDR["sepc"], CSR_ADDR["scause"], CSR_ADDR["stval"], CSR_ADDR["satp"]]:
            if current_priv < PrivMode.SUPERVISOR:
                raise PermissionError(f"Đặc quyền {current_priv.name} không đủ để ghi CSR S-mode {get_csr_name(csr_addr)}")
        if csr_addr == CSR_ADDR["satp"] and current_priv == PrivMode.SUPERVISOR:
            mstatus = self.registers.get(CSR_ADDR["mstatus"], 0)
            if mstatus & MSTATUS_TVM:
                raise PermissionError(f"Ghi vào satp bị chặn bởi MSTATUS.TVM")

    def validate_tvec(self, value: int):
        mode = value & TVEC_MODE_MASK
        base = value & ~TVEC_MODE_MASK
        if mode > TVEC_MODE_VECTORED:
            raise ValueError(f"Chế độ TVEC không hợp lệ: {mode}")
        if mode == TVEC_MODE_VECTORED:
            if base % TVEC_BASE_ALIGN_VECTORED != 0:
                raise ValueError(f"Chế độ vectored yêu cầu căn chỉnh {TVEC_BASE_ALIGN_VECTORED}-byte")
        else:
            if base % TVEC_BASE_ALIGN_DIRECT != 0:
                raise ValueError(f"Chế độ direct yêu cầu căn chỉnh {TVEC_BASE_ALIGN_DIRECT}-byte")

    def read(self, csr_addr: int, current_priv: PrivMode) -> int:
        self._check_read_permission(csr_addr, current_priv)
        if csr_addr in [CSR_ADDR["cycle"], CSR_ADDR["cycleh"], CSR_ADDR["instret"], CSR_ADDR["instreth"]]:
            counter_val_64 = self.internal_cycle_counter if csr_addr in [CSR_ADDR["cycle"], CSR_ADDR["cycleh"]] else self.internal_instret_counter
            counter_idx = SCOUNTEREN_CY if csr_addr in [CSR_ADDR["cycle"], CSR_ADDR["cycleh"]] else SCOUNTEREN_IR
            mcounteren = self.registers.get(CSR_ADDR["mcounteren"], 0)
            scounteren = self.registers.get(CSR_ADDR["scounteren"], 0)
            if current_priv == PrivMode.SUPERVISOR and not (mcounteren & counter_idx):
                raise PermissionError(f"Truy cập bộ đếm CSR {get_csr_name(csr_addr)} bị từ chối ở S-mode")
            if current_priv == PrivMode.USER and not ((mcounteren & counter_idx) and (scounteren & counter_idx)):
                raise PermissionError(f"Truy cập bộ đếm CSR {get_csr_name(csr_addr)} bị từ chối ở U-mode")
            return (counter_val_64 >> 32) if csr_addr in [CSR_ADDR["cycleh"], CSR_ADDR["instreth"]] else (counter_val_64 & 0xFFFFFFFF)
        if csr_addr == CSR_ADDR["sstatus"]:
            return self.registers.get(CSR_ADDR["mstatus"], 0) & SSTATUS_WRITABLE_MASK
        if csr_addr == CSR_ADDR["sie"]:
            mie_val = self.registers.get(CSR_ADDR["mie"], 0)
            mideleg_val = self.registers.get(CSR_ADDR["mideleg"], 0)
            return (mie_val & mideleg_val) & SIE_MASK
        if csr_addr == CSR_ADDR["sip"]:
            mip_val = self.registers.get(CSR_ADDR["mip"], 0)
            mideleg_val = self.registers.get(CSR_ADDR["mideleg"], 0)
            return (mip_val & mideleg_val) & SIE_MASK
        if csr_addr in self.registers:
            if self.debug_prints_active:
                print(f"CSR_READ: {get_csr_name(csr_addr)} = {format_hex(self.registers[csr_addr])}")
            return self.registers[csr_addr]
        raise UnimplementedCSRError(csr_addr)

    def write(self, csr_addr: int, value: int, current_priv: PrivMode):
        self._check_write_permission(csr_addr, current_priv)
        val32 = value & 0xFFFFFFFF
        if csr_addr == CSR_ADDR["sstatus"]:
            current_mstatus = self.registers.get(CSR_ADDR["mstatus"], 0)
            new_mstatus = (current_mstatus & ~SSTATUS_WRITABLE_MASK) | (val32 & SSTATUS_WRITABLE_MASK)
            self.registers[CSR_ADDR["mstatus"]] = new_mstatus
            if self.debug_prints_active:
                print(f"CSR_WRITE: sstatus = {format_hex(val32)} -> mstatus_new={format_hex(new_mstatus)}")
            return
        if csr_addr == CSR_ADDR["sie"]:
            mideleg_val = self.registers.get(CSR_ADDR["mideleg"], 0)
            writable_mie_bits = mideleg_val & SIE_MASK
            current_mie = self.registers.get(CSR_ADDR["mie"], 0)
            new_mie = (current_mie & ~writable_mie_bits) | (val32 & writable_mie_bits)
            self.registers[CSR_ADDR["mie"]] = new_mie
            if self.debug_prints_active:
                print(f"CSR_WRITE: sie = {format_hex(val32)} -> mie_new={format_hex(new_mie)}")
            return
        if csr_addr == CSR_ADDR["sip"]:
            mideleg_val = self.registers.get(CSR_ADDR["mideleg"], 0)
            current_mip = self.registers.get(CSR_ADDR["mip"], 0)
            new_mip = current_mip
            if mideleg_val & SIP_SSIP and not (val32 & SIP_SSIP):
                new_mip &= ~SIP_SSIP
            if mideleg_val & SIP_USIP and not (val32 & SIP_USIP):
                new_mip &= ~SIP_USIP
            self.registers[CSR_ADDR["mip"]] = new_mip
            if self.debug_prints_active:
                print(f"CSR_WRITE: sip = {format_hex(val32)} -> mip_new={format_hex(new_mip)}")
            return
        actual_val_to_store = val32
        if csr_addr == CSR_ADDR["mstatus"]:
            current_mstatus = self.registers.get(CSR_ADDR["mstatus"], 0)
            actual_val_to_store = (val32 & MSTATUS_WRITABLE_MASK) | (current_mstatus & ~MSTATUS_WRITABLE_MASK)
        elif csr_addr == CSR_ADDR["misa"]:
            current_misa = self.registers.get(CSR_ADDR["misa"], 0)
            actual_val_to_store = (val32 & 0x03FFFFFF) | (current_misa & 0xC0000000)
        elif csr_addr == CSR_ADDR["mie"]:
            actual_val_to_store = val32 & MIE_MASK
        elif csr_addr == CSR_ADDR["mip"]:
            writable_mip_mask = MIP_MSIP | MIP_SSIP | MIP_USIP
            current_mip = self.registers.get(CSR_ADDR["mip"], 0)
            actual_val_to_store = (current_mip & ~writable_mip_mask) | (val32 & writable_mip_mask)
        elif csr_addr == CSR_ADDR["medeleg"]:
            actual_val_to_store = val32 & 0xFFFF
        elif csr_addr == CSR_ADDR["mideleg"]:
            actual_val_to_store = val32 & SIE_MASK
        elif csr_addr in [CSR_ADDR["mtvec"], CSR_ADDR["stvec"]]:
            self.validate_tvec(val32)
            actual_val_to_store = val32
        elif csr_addr in [CSR_ADDR["mepc"], CSR_ADDR["sepc"]]:
            if val32 & 0x3:
                raise ValueError(f"Invalid {get_csr_name(csr_addr)}: Not aligned to 4 bytes: {format_hex(val32)}")
            actual_val_to_store = val32 & ~0x3
        elif csr_addr == CSR_ADDR["satp"]:
            mode = (val32 & SATP_MODE) >> 31
            ppn = val32 & SATP_PPN
            if mode != SATP_MODE_BARE and mode != (SATP_MODE_SV32 >> 31):
                current_satp = self.registers.get(CSR_ADDR["satp"], 0)
                mode = (current_satp & SATP_MODE) >> 31
            actual_val_to_store = (mode << 31) | ppn
        elif csr_addr == CSR_ADDR["scounteren"]:
            actual_val_to_store = val32 & (SCOUNTEREN_CY | SCOUNTEREN_TM | SCOUNTEREN_IR)
        elif csr_addr == CSR_ADDR["mcountinhibit"]:
            actual_val_to_store = val32 & (COUNTEREN_CY | COUNTEREN_IR)  # Chỉ cho phép CY và IR bits
        if csr_addr in self.registers:
            self.registers[csr_addr] = actual_val_to_store
            if self.debug_prints_active:
                print(f"CSR_WRITE: {get_csr_name(csr_addr)} = {format_hex(val32)} (stored as {format_hex(actual_val_to_store)})")
        else:
            raise UnimplementedCSRError(csr_addr)

    def update_performance_counters(self, cycles_increment: int = 1, instructions_retired_increment: int = 0):
        mcountinhibit = self.registers.get(CSR_ADDR["mcountinhibit"], 0)
        if not (mcountinhibit & COUNTEREN_CY):
            self.internal_cycle_counter = (self.internal_cycle_counter + cycles_increment) & 0xFFFFFFFFFFFFFFFF
        if instructions_retired_increment > 0 and not (mcountinhibit & COUNTEREN_IR):
            self.internal_instret_counter = (self.internal_instret_counter + instructions_retired_increment) & 0xFFFFFFFFFFFFFFFF