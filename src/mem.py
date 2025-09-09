# mem.py
from enum import IntEnum

class MemSize(IntEnum):
    """Kích thước truy cập bộ nhớ cho RV32I"""
    BYTE = 1      # 8-bit
    HALFWORD = 2  # 16-bit
    WORD = 4      # 32-bit

class MemoryError(Exception):
    """Ngoại lệ cho lỗi truy cập bộ nhớ."""
    def __init__(self, message: str, addr: int, access_type: str):
        self.addr = addr
        self.access_type = access_type
        super().__init__(f"{message} at {hex(addr)} ({access_type})")

class Memory:
    def __init__(self, size=0x1000000, page_size=4096):  # 16MB, page_size=4KB
        self.size = size
        self.page_size = page_size
        self.data = [0] * size  # Mảng byte

    def load(self, addr: int, size: MemSize) -> int:
        if not isinstance(size, MemSize):
            size = MemSize(size)
        if addr < 0 or addr + size > self.size:
            raise MemoryError("Invalid memory address", addr, f"Load{size.name}")
        result = 0
        for i in range(size):
            result |= self.data[addr + i] << (i * 8)  # Little-endian
        return result & ((1 << (size * 8)) - 1)

    def store(self, addr: int, value: int, size: MemSize):
        if not isinstance(size, MemSize):
            size = MemSize(size)
        if addr < 0 or addr + size > self.size:
            raise MemoryError("Invalid memory address", addr, f"Store{size.name}")
        for i in range(size):
            self.data[addr + i] = (value >> (i * 8)) & 0xFF  # Little-endian

    def get_raw_addr(self, addr: int) -> int:
        if addr < 0 or addr >= self.size:
            raise MemoryError("Invalid memory address", addr, "Access")
        return addr

    def reset(self):
        self.data = [0] * self.size