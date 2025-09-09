# mret.py
from isa_defs import *
from utils import format_hex
from trap_handler import common_trap_handler

def mret(cpu):
    if cpu.state.priv_mode != PrivMode.MACHINE:
        common_trap_handler(cpu, CAUSE_ILLEGAL_INSTRUCTION, cpu.state.pc)
        return
    mstatus_val = cpu.csrs.read(CSR_ADDR["mstatus"], PrivMode.MACHINE)
    mepc_val = cpu.csrs.read(CSR_ADDR["mepc"], PrivMode.MACHINE)
    if mepc_val & 0x3:
        common_trap_handler(cpu, CAUSE_ILLEGAL_INSTRUCTION, cpu.state.pc)
        return
    target_pc = (mepc_val + 4) & 0xFFFFFFFF
    mpp_field_val = (mstatus_val & MSTATUS_MPP) >> MSTATUS_MPP_SHIFT
    new_priv_mode = PrivMode(mpp_field_val)
    cpu.state.priv_mode = new_priv_mode
    mpie_val = (mstatus_val >> MSTATUS_MPIE_SHIFT) & 0b1
    if mpie_val:
        mstatus_val |= (1 << MSTATUS_MIE_SHIFT)
    else:
        mstatus_val &= ~(1 << MSTATUS_MIE_SHIFT)
    mstatus_val |= (1 << MSTATUS_MPIE_SHIFT)
    mstatus_val = (mstatus_val & ~MSTATUS_MPP) | (PrivMode.USER << MSTATUS_MPP_SHIFT)
    if new_priv_mode != PrivMode.MACHINE:
        mstatus_val &= ~MSTATUS_MPRV
    cpu.csrs.write(CSR_ADDR["mstatus"], mstatus_val, PrivMode.MACHINE)
    cpu.state.next_pc = target_pc
    print(f"[MRET_HANDLER] Returning to {cpu.state.priv_mode.name} mode @ {format_hex(cpu.state.next_pc)}")