# src/main.py
from assembler_1 import Assembler
from cpu_1 import CPU

DEFAULT_ROM_BASE = 0x00001000
DEFAULT_ROM_SIZE = 0x100000

def run_simulation(asm_file_path: str, max_cycles: int, debug_cpu_enabled: bool):
    # Giai đoạn 1: Hợp dịch và tạo file .bin
    print(f"\n[Giai đoạn 1: Hợp dịch '{asm_file_path}' và tạo file .bin]")
    assembler = Assembler(base_address=DEFAULT_ROM_BASE)
    bin_file_path = "output.bin"
    if not assembler.assemble_file_to_file(asm_file_path, bin_file_path):
        print("Hợp dịch thất bại. Dừng chương trình.")
        return

    # Giai đoạn 2: Thiết lập CPU và nạp chương trình từ file .bin
    print("\n[Giai đoạn 2: Nạp chương trình từ file .bin vào CPU]")
    cpu_instance = CPU(rom_base_addr=DEFAULT_ROM_BASE, rom_size_bytes=DEFAULT_ROM_SIZE)
    cpu_instance.set_debug_mode(debug_cpu_enabled)
    cpu_instance.load_program_from_bin(bin_file_path, text_start=DEFAULT_ROM_BASE)
    print(f"✅ Chương trình đã được nạp vào bộ nhớ CPU từ file '{bin_file_path}'.")

    # Giai đoạn 3: Thực thi CPU
    print(f"\n[Giai đoạn 3: Chạy CPU (Tối đa: {max_cycles} chu kỳ)]")
    cpu_instance.run(max_cycles=max_cycles)

    # Giai đoạn 4: Hiển thị trạng thái cuối cùng
    print(f"\n[Giai đoạn 4: Mô phỏng Hoàn tất]")
    print("\n--- Trạng thái CPU cuối cùng ---")
    print(cpu_instance.dump_state_verbose())
    print("\n--- Kết thúc Phiên Giả Lập RISC-V ---")

if __name__ == "__main__":
    asm_file = "test.s"  # Thay bằng file assembly của bạn
    max_cycles = 50      # Số chu kỳ tối đa
    debug_mode = True       # Bật chế độ debug
    run_simulation(asm_file, max_cycles, debug_mode)