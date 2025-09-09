from regnames import GPR_NAMES  
from utils import format_hex
class RegisterFile:
    def __init__(self):
        self.regs = [0] * 32
        self.emulator_cycle = 0

    def read(self, index):
        if index < 0 or index >= 32:
            raise ValueError(f"Invalid register index: {index}")
        return 0 if index == 0 else self.regs[index]

    def write(self, index, value, pc=None):
        if index < 0 or index >= 32:
            raise ValueError(f"Invalid register index: {index}")
        if index != 0:
            self.regs[index] = value & 0xFFFFFFFF

    def increment_emulator_cycle(self):
        self.emulator_cycle += 1

    def dump_to_string(self) -> str:
        lines = ["--- General Purpose Registers ---"]
        for i in range(0, 32, 4):  # Hiển thị 4 thanh ghi mỗi dòng
            line = []
            for j in range(4):
                reg_idx = i + j
                # Tìm tên ABI cho thanh ghi
                reg_name = next(
                    (
                        name
                        for name, idx in GPR_NAMES.items()
                        if idx == reg_idx and not name.startswith("x")
                    ),
                    f"x{reg_idx}",
                )
                value = self.regs[reg_idx] if reg_idx != 0 else 0
                line.append(f"{reg_name:<4}: {format_hex(value, 8)}")
            lines.append("  ".join(line))
        return "\n".join(lines)

    def reset(self):
        self.regs = [0] * 32
        self.emulator_cycle = 0
