# trap_handler.py
from isa_defs import *
from regnames import get_csr_name
from utils import format_hex
from interrupt_handler import handle_interrupt

def common_trap_handler(cpu, cause: int, tval: int):
    
    is_interrupt = (cause & CAUSE_INTERRUPT_FLAG) != 0
    cause_code = cause & ~CAUSE_INTERRUPT_FLAG
    priv_at_trap = cpu.state.priv_mode
    pc_at_trap = cpu.state.pc
    target_priv = PrivMode.MACHINE
    delegated_to_s_mode = False

    # Kiểm tra ủy quyền (mideleg cho ngắt, medeleg cho ngoại lệ)
    if priv_at_trap != PrivMode.MACHINE:
        deleg_csr = CSR_ADDR["mideleg"] if is_interrupt else CSR_ADDR["medeleg"]
        deleg_val = cpu.csrs.read(deleg_csr, PrivMode.MACHINE)
        if (deleg_val >> cause_code) & 1:
            delegated_to_s_mode = True
            target_priv = PrivMode.SUPERVISOR

    print(f"[TRAP_HANDLER] {'Interrupt' if is_interrupt else 'Exception'} Cause=0x{cause:x}, Code=0x{cause_code:x}, TVAL=0x{tval:x}, PC=0x{pc_at_trap:x}, Mode={priv_at_trap.name} → {target_priv.name} ({'Delegated to S-mode' if delegated_to_s_mode else 'Handled in M-mode'})")

    mstatus_val = cpu.csrs.read(CSR_ADDR["mstatus"], PrivMode.MACHINE)
    cpu.state.trap_pending = True

    try:
        if target_priv == PrivMode.SUPERVISOR:
            # Cập nhật mstatus cho S-mode
            mstatus_val = (mstatus_val & ~MSTATUS_SPP) | (priv_at_trap << MSTATUS_SPP_SHIFT)
            sie = (mstatus_val >> MSTATUS_SIE_SHIFT) & 1
            mstatus_val = (mstatus_val & ~MSTATUS_SPIE) | (sie << MSTATUS_SPIE_SHIFT)
            mstatus_val &= ~(1 << MSTATUS_SIE_SHIFT)
            cpu.csrs.write(CSR_ADDR["mstatus"], mstatus_val, PrivMode.MACHINE)

            # Cập nhật sepc, scause, stval
            cpu.csrs.write(CSR_ADDR["sepc"], pc_at_trap & ~0x3, target_priv)
            cpu.csrs.write(CSR_ADDR["scause"], cause, target_priv)
            cpu.csrs.write(CSR_ADDR["stval"], tval, target_priv)

            # Xác định địa chỉ trap handler
            stvec = cpu.csrs.read(CSR_ADDR["stvec"], target_priv)
            base, mode = stvec & ~TVEC_MODE_MASK, stvec & TVEC_MODE_MASK
            cpu.state.next_pc = base + (4 * cause_code) if is_interrupt and mode == TVEC_MODE_VECTORED else base
            cpu.state.priv_mode = PrivMode.SUPERVISOR

            # Xử lý ngắt (nếu có)
            if is_interrupt:
                handle_interrupt(cpu, cause, tval)

        else:  # M-mode
            # Cập nhật mstatus cho M-mode
            mstatus_val = (mstatus_val & ~MSTATUS_MPP) | (priv_at_trap << MSTATUS_MPP_SHIFT)
            mie = (mstatus_val >> MSTATUS_MIE_SHIFT) & 1
            mstatus_val = (mstatus_val & ~MSTATUS_MPIE) | (mie << MSTATUS_MPIE_SHIFT)
            mstatus_val &= ~(1 << MSTATUS_MIE_SHIFT)
            mstatus_val &= ~MSTATUS_MPRV
            cpu.csrs.write(CSR_ADDR["mstatus"], mstatus_val, PrivMode.MACHINE)

            # Cập nhật mepc, mcause, mtval
            cpu.csrs.write(CSR_ADDR["mepc"], pc_at_trap & ~0x3, PrivMode.MACHINE)
            cpu.csrs.write(CSR_ADDR["mcause"], cause, PrivMode.MACHINE)
            cpu.csrs.write(CSR_ADDR["mtval"], tval, PrivMode.MACHINE)

            # Xác định địa chỉ trap handler
            mtvec = cpu.csrs.read(CSR_ADDR["mtvec"], PrivMode.MACHINE)
            base, mode = mtvec & ~TVEC_MODE_MASK, mtvec & TVEC_MODE_MASK
            cpu.state.next_pc = base + (4 * cause_code) if is_interrupt and mode == TVEC_MODE_VECTORED else base
            cpu.state.priv_mode = PrivMode.MACHINE

            # Xử lý ngắt (nếu có)
            if is_interrupt:
                handle_interrupt(cpu, cause, tval)

    finally:
        cpu.state.trap_pending = False