# src/utils.py


def sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    mask = (1 << bits) - 1
    return ((value & mask) ^ sign_bit) - sign_bit


def get_bit_field(value: int, msb: int, lsb: int) -> int:
    if msb < lsb:
        raise ValueError("MSB must be greater than or equal to LSB.")
    mask = ((1 << (msb - lsb + 1)) - 1) << lsb
    return (value & mask) >> lsb


def set_bit_field(original_value: int, field_value: int, msb: int, lsb: int) -> int:
    if msb < lsb:
        raise ValueError("MSB must be greater than or equal to LSB.")
    field_mask = ((1 << (msb - lsb + 1)) - 1) << lsb
    cleared_value = original_value & ~field_mask
    aligned_field_value = (field_value << lsb) & field_mask
    return cleared_value | aligned_field_value


def format_hex(value: int, digits: int = 8) -> str:
    if value < 0:
        value &= (1 << (digits * 4)) - 1
    return f"0x{value:0{digits}x}"


def format_bin(value: int, digits: int = 32) -> str:
    if value < 0:
        value &= (1 << digits) - 1
    return f"{value:0{digits}b}"
