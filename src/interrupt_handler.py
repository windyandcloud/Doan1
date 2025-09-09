# interrupt_handler.py
from isa_defs import *
from utils import format_hex

def handle_interrupt(cpu, cause: int, tval: int):
    cause_code = cause & ~CAUSE_INTERRUPT_FLAG
    print(f"[INTERRUPT_HANDLER] Handling interrupt: Cause=0x{cause:x}, Code=0x{cause_code:x}, TVAL=0x{tval:x}, Mode={cpu.state.priv_mode.name}")

    # Xác định bit mip tương ứng với ngắt
    mip_bit = None
    if cause_code == INT_M_SOFTWARE:
        mip_bit = MIP_MSIP
    elif cause_code == INT_S_SOFTWARE:
        mip_bit = MIP_SSIP
    elif cause_code == INT_M_EXTERNAL:
        mip_bit = MIP_MEIP
    elif cause_code == INT_S_EXTERNAL:
        mip_bit = MIP_SEIP
    else:
        print(f"[INTERRUPT_HANDLER] Unknown interrupt cause code: 0x{cause_code:x}")
        return

    if mip_bit:
        mip_val = cpu.csrs.read(CSR_ADDR["mip"], PrivMode.MACHINE)
        cpu.csrs.write(CSR_ADDR["mip"], mip_val & ~mip_bit, PrivMode.MACHINE)
        print(f"[INTERRUPT_HANDLER] Cleared MIP bit 0x{mip_bit:x}, new MIP=0x{format_hex(cpu.csrs.read(CSR_ADDR['mip'], PrivMode.MACHINE))}") 
