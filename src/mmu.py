# mmu.py
from isa_defs import *
from mem import Memory, MemSize, MemoryError
import logging

logger = logging.getLogger(__name__)

class MMU_Error(Exception):
    def __init__(self, message: str, addr: int, access_type: str, cause: int):
        self.addr = addr
        self.access_type = access_type
        self.cause = cause
        super().__init__(f"{message} at 0x{addr:x} (type: {access_type}, cause: 0x{cause:x})")

class MMU:
    def __init__(self, csrs, memory: Memory):
        self.csrs = csrs
        self.memory = memory

    def _check_alignment(self, addr: int, size: MemSize, access_type: str) -> None:
        """Kiểm tra xem địa chỉ truy cập có được căn chỉnh đúng hay không."""
        if size == MemSize.HALFWORD and addr % 2 != 0:
            cause = CAUSE_MISALIGNED_LOAD if access_type == "LOAD" else CAUSE_MISALIGNED_STORE
            raise MemoryError("Misaligned halfword access", addr, f"{access_type}_MISALIGNED", cause)
        if size == MemSize.WORD and addr % 4 != 0:
            cause = CAUSE_MISALIGNED_FETCH if access_type == "FETCH" else (
                CAUSE_MISALIGNED_LOAD if access_type == "LOAD" else CAUSE_MISALIGNED_STORE)
            raise MemoryError("Misaligned word access", addr, f"{access_type}_MISALIGNED", cause)

    def _check_pte_permissions(self, pte: int, vaddr: int, access_type: str, priv_mode: PrivMode, is_leaf_pte: bool):
        """Hàm trợ giúp để kiểm tra quyền của một Page Table Entry (PTE)."""
        cause = {
            "FETCH": CAUSE_FETCH_PAGE_FAULT,
            "LOAD": CAUSE_LOAD_PAGE_FAULT,
            "STORE": CAUSE_STORE_PAGE_FAULT
        }.get(access_type, CAUSE_FETCH_ACCESS)

        is_valid = (pte & PTE_V) != 0
        is_readable = (pte & PTE_R) != 0
        is_writable = (pte & PTE_W) != 0
        is_executable = (pte & PTE_X) != 0

        if not is_valid:
            raise MemoryError("Invalid page table entry (V=0)", vaddr, f"{access_type}_PAGE_FAULT", cause)

        if not is_leaf_pte and (is_readable or is_writable or is_executable):
            raise MemoryError("PTE pointing to next-level table has R/W/X bits set", vaddr, f"{access_type}_PAGE_FAULT", cause)

        if is_leaf_pte:
            if is_writable and not is_readable:
                raise MemoryError("Invalid PTE (R=0, W=1)", vaddr, f"{access_type}_PAGE_FAULT", cause)
            
            if access_type == "FETCH" and not is_executable:
                raise MemoryError("Execute permission denied", vaddr, f"{access_type}_PAGE_FAULT", cause)
            elif access_type == "LOAD" and not is_readable:
                raise MemoryError("Read permission denied", vaddr, f"{access_type}_PAGE_FAULT", cause)
            elif access_type == "STORE" and not is_writable:
                raise MemoryError("Write permission denied", vaddr, f"{access_type}_PAGE_FAULT", cause)

            user_access_allowed = (pte & PTE_U) != 0
            mstatus = self.csrs.read(CSR_ADDR["mstatus"], PrivMode.MACHINE)
            sum_bit = (mstatus & MSTATUS_SUM) != 0

            if priv_mode == PrivMode.USER and not user_access_allowed:
                raise MemoryError("User mode access denied to supervisor page", vaddr, f"{access_type}_PAGE_FAULT", cause)
            
            if priv_mode == PrivMode.SUPERVISOR and user_access_allowed and not sum_bit:
                raise MemoryError("Supervisor mode access to user page denied (SUM=0)", vaddr, f"{access_type}_PAGE_FAULT", cause)
            
    def translate_address(self, virt_addr: int, priv_mode: PrivMode, access_type: str, size: MemSize = MemSize.WORD) -> int:

        """Dịch địa chỉ ảo sang địa chỉ vật lý, sử dụng cơ chế phân trang Sv32."""
        self._check_alignment(virt_addr, size, access_type)
        
        satp_val = self.csrs.read(CSR_ADDR["satp"], priv_mode)
        mode = (satp_val >> 31) & 0x1

        if mode == (SATP_MODE_BARE >> 31):
            return virt_addr
        
        ppn_l1_table = satp_val & SATP_PPN
        vpn1 = (virt_addr >> 22) & 0x3FF
        pte1_addr = (ppn_l1_table << 12) + (vpn1 * 4)

        try:
            pte1 = self.memory.load(pte1_addr, MemSize.WORD)
        except Exception as e:
            cause = CAUSE_LOAD_PAGE_FAULT if access_type in ["LOAD", "STORE"] else CAUSE_FETCH_PAGE_FAULT
            raise MemoryError("Page table access error (L1)", virt_addr, f"{access_type}_PAGE_FAULT", cause) from e
        
        self._check_pte_permissions(pte1, virt_addr, access_type, priv_mode, is_leaf_pte=False)

        ppn_l2_table = (pte1 >> 10) & 0x3FFFFF
        vpn0 = (virt_addr >> 12) & 0x3FF
        pte2_addr = (ppn_l2_table << 12) + (vpn0 * 4)

        try:
            pte2 = self.memory.load(pte2_addr, MemSize.WORD)
        except Exception as e:
            cause = CAUSE_LOAD_PAGE_FAULT if access_type in ["LOAD", "STORE"] else CAUSE_FETCH_PAGE_FAULT
            raise MemoryError("Page table access error (L2)", virt_addr, f"{access_type}_PAGE_FAULT", cause) from e

        self._check_pte_permissions(pte2, virt_addr, access_type, priv_mode, is_leaf_pte=True)
        
        if not (pte2 & PTE_A):
            self.memory.store(pte2_addr, pte2 | PTE_A, MemSize.WORD)
        if access_type == "STORE" and not (pte2 & PTE_D):
            self.memory.store(pte2_addr, pte2 | PTE_D, MemSize.WORD)
            
        offset = virt_addr & 0xFFF
        phys_addr_page = ((pte2 >> 10) & 0x3FFFFF) << 12
        phys_addr = phys_addr_page | offset
        
        #logger.debug(f"Translated vaddr 0x{virt_addr:x} to paddr 0x{phys_addr:x}")
        return phys_addr
    
