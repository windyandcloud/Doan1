# sret.py
from isa_defs import *
from utils import format_hex
from trap_handler import common_trap_handler

def sret(cpu):
    if cpu.state.priv_mode < PrivMode.SUPERVISOR:
        print(f"[SRET_HANDLER] Illegal instruction: SRET must be executed in S-mode or M-mode, current: {cpu.state.priv_mode.name}")
        common_trap_handler(cpu, CAUSE_ILLEGAL_INSTRUCTION, cpu.state.pc)
        return
    mstatus_val = cpu.csrs.read(CSR_ADDR["mstatus"], PrivMode.MACHINE)
    if cpu.state.priv_mode == PrivMode.SUPERVISOR and (mstatus_val & MSTATUS_TSR):
        print("[SRET_HANDLER] Illegal instruction: TSR=1 blocks SRET in S-mode")
        common_trap_handler(cpu, CAUSE_ILLEGAL_INSTRUCTION, cpu.state.pc)
        return
    sepc_val = cpu.csrs.read(CSR_ADDR["sepc"], PrivMode.SUPERVISOR)
    if sepc_val & 0x3:
        print(f"[SRET_HANDLER] Illegal instruction: SEPC not aligned to 4 bytes: {format_hex(sepc_val)}")
        common_trap_handler(cpu, CAUSE_ILLEGAL_INSTRUCTION, cpu.state.pc)
        return
    target_pc = (sepc_val + 4) & 0xFFFFFFFF
    spp_val = (mstatus_val >> MSTATUS_SPP_SHIFT) & 1
    new_priv_mode = PrivMode(spp_val)
    cpu.state.priv_mode = new_priv_mode
    spie_val = (mstatus_val >> MSTATUS_SPIE_SHIFT) & 1
    if spie_val:
        mstatus_val |= (1 << MSTATUS_SIE_SHIFT)
    else:
        mstatus_val &= ~(1 << MSTATUS_SIE_SHIFT)
    mstatus_val |= (1 << MSTATUS_SPIE_SHIFT)
    mstatus_val &= ~MSTATUS_SPP
    if new_priv_mode == PrivMode.USER:
        mstatus_val &= ~MSTATUS_MPRV
    cpu.csrs.write(CSR_ADDR["mstatus"], mstatus_val, PrivMode.MACHINE)
    cpu.state.next_pc = target_pc
    print(f"[SRET_HANDLER] Returning to {cpu.state.priv_mode.name} mode @ {format_hex(cpu.state.next_pc)}")