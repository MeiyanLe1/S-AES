"""S-AES（简化 AES）核心算法。

算法参数：分组 16 bit、密钥 16 bit、共 2 轮（初始轮密钥加 + 第 1 完整轮 + 第 2 轮）。

约定：
1. 所有对外接口都用 ``int`` 表示 16 bit 数据，避免字节序歧义；
2. 内部把 16 bit 拆成 4 个半字节（nibble） ``(s00, s10, s01, s11)``，
   与附录 D 图 D.2(a) 一致——状态矩阵按**列**填充，第一列占高 8 位；
3. 加解密流程、S 盒、列混淆矩阵均与教材附录 D 完全一致，便于第 2 关交叉测试。
"""

from __future__ import annotations

from functools import lru_cache

__all__ = [
    "ValidationError",
    "S_BOX",
    "INV_S_BOX",
    "MIX_MATRIX",
    "INV_MIX_MATRIX",
    "expand_key",
    "encrypt_block",
    "decrypt_block",
    "encrypt_block_debug",
    "decrypt_block_debug",
    "gf_mul",
    "parse_hex_value",
    "parse_binary_value",
    "format_binary",
    "format_hex",
    "get_bit",
]


class ValidationError(ValueError):
    """用户输入不合法或数据长度不符时抛出的错误，GUI 层统一捕获后弹窗提示。"""


# --------------------------------------------------------------------------- #
# 常量表（附录 D 表 D.1 / D.2.4 / D.3）
# --------------------------------------------------------------------------- #

#: 16 项 S 盒（半字节代替盒），共 4 行 × 4 列
S_BOX: tuple[int, ...] = (
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7,
)

#: 逆 S 盒，满足 INV_S_BOX[S_BOX[x]] == x
INV_S_BOX: tuple[int, ...] = tuple(S_BOX.index(value) for value in range(16))

#: 列混淆矩阵 [[1, 4], [4, 1]]，运算在 GF(2^4) 上，模多项式 x^4 + x + 1
MIX_MATRIX: tuple[tuple[int, int], tuple[int, int]] = ((1, 4), (4, 1))

#: 逆列混淆矩阵 [[9, 2], [2, 9]]
INV_MIX_MATRIX: tuple[tuple[int, int], tuple[int, int]] = ((9, 2), (2, 9))

#: 轮常数 RC[1] = x^3 = 1000 0000，RC[2] = x^4 mod (x^4+x+1) = 0011 0000
_ROUND_CONSTANTS: tuple[int, int] = (0x80, 0x30)


# --------------------------------------------------------------------------- #
# 位与半字节的基础工具
# --------------------------------------------------------------------------- #


def _check_range(value: int, bit_width: int, name: str) -> None:
    if not isinstance(value, int):
        raise ValidationError(f"{name} 必须是整数")
    if not 0 <= value < (1 << bit_width):
        raise ValidationError(f"{name} 必须是 {bit_width} bit（0 ~ {1 << bit_width}）范围内的整数")


def split_nibbles(value: int) -> list[int]:
    """把 16 bit 整数拆成半字节列表，索引顺序为 (s00, s10, s01, s11)。"""
    return [(value >> shift) & 0xF for shift in (12, 8, 4, 0)]


def join_nibbles(nibbles: list[int]) -> int:
    """把 4 个半字节拼回 16 bit 整数，与 :func:`split_nibbles` 互逆。"""
    result = 0
    for nibble in nibbles:
        result = (result << 4) | (nibble & 0xF)
    return result


def get_bit(value: int, bit_index: int, bit_width: int = 16) -> int:
    """取第 ``bit_index`` 位（0 表示最低位），用于界面上的位点阵。"""
    return (value >> (bit_width - 1 - bit_index)) & 1


def format_binary(value: int, bit_width: int = 16, group_size: int = 4) -> str:
    """把整数格式化成带分组的二进制字符串，例如 0x2D55 -> '0010 1101 0101 0101'。"""
    bits = f"{value:0{bit_width}b}"
    return " ".join(bits[i:i + group_size] for i in range(0, bit_width, group_size))


def format_hex(value: int, bit_width: int = 16) -> str:
    """把整数格式化成固定宽度的大写十六进制字符串，例如 0x2D55 -> '2D55'。"""
    return f"{value:0{bit_width // 4}X}"


def parse_hex_value(text: str, bit_width: int = 16) -> int:
    """解析十六进制输入，容忍空格、下划线、``0x`` 前缀与大小写混写。"""
    cleaned = text.strip().replace(" ", "").replace("_", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        raise ValidationError("请输入十六进制数据")
    if any(char not in "0123456789abcdefABCDEF" for char in cleaned):
        raise ValidationError("只能包含十六进制字符 0-9 / A-F")
    if len(cleaned) > bit_width // 4:
        raise ValidationError(f"长度超出 {bit_width} bit，最多 {bit_width // 4} 个十六进制字符")
    return int(cleaned, 16)


def parse_binary_value(text: str, bit_width: int = 16) -> int:
    """解析二进制输入，允许任意空白分隔，长度不得超过位宽。"""
    cleaned = "".join(text.split())
    if not cleaned:
        raise ValidationError("请输入二进制数据")
    if any(char not in "01" for char in cleaned):
        raise ValidationError("只能包含二进制字符 0 / 1")
    if len(cleaned) > bit_width:
        raise ValidationError(f"长度超出 {bit_width} bit")
    return int(cleaned, 2)


def parse_flexible(text: str, bit_width: int = 16, require_full_width: bool = False) -> int:
    """智能解析：只含 0/1 且长度达到位宽一半以上时按二进制解析，否则按十六进制解析。"""
    cleaned = "".join(text.split()).replace("_", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        raise ValidationError("输入不能为空")
    looks_binary = all(char in "01" for char in cleaned) and len(cleaned) > bit_width // 4
    value = parse_binary_value(cleaned, bit_width) if looks_binary else parse_hex_value(cleaned, bit_width)
    if require_full_width:
        expected_digits = bit_width if looks_binary else bit_width // 4
        if len(cleaned) != expected_digits:
            unit = "位" if looks_binary else "个十六进制字符"
            raise ValidationError(f"需要恰好 {expected_digits} {unit}")
    return value


# --------------------------------------------------------------------------- #
# GF(2^4) 上的乘法：模多项式 x^4 + x + 1
# --------------------------------------------------------------------------- #


def xtime(value: int) -> int:
    """乘 x（即乘 2）：左移一位，若移出最高位则与 0b0011 异或（模 x^4+x+1 的约简）。"""
    shifted = (value << 1) & 0x1F
    if value & 0x8:
        shifted ^= 0b0011
    return shifted & 0xF


@lru_cache(maxsize=256)
def gf_mul(left: int, right: int) -> int:
    """GF(2^4) 乘法。用俄罗斯农民乘法（移位相加）实现，避免额外查表。"""
    result = 0
    a, b = left & 0xF, right & 0xF
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result & 0xF


# --------------------------------------------------------------------------- #
# 单轮变换：密钥加、半字节代替、行移位、列混淆及其逆变换
# --------------------------------------------------------------------------- #


def add_round_key(state: int, round_key: int) -> int:
    """密钥加：16 bit 逐位异或（异或的逆运算仍是它本身）。"""
    return state ^ round_key


def sub_nibbles(state: int) -> int:
    """半字节代替：4 个半字节分别查 S 盒。"""
    return join_nibbles([S_BOX[nibble] for nibble in split_nibbles(state)])


def inv_sub_nibbles(state: int) -> int:
    """逆半字节代替：查逆 S 盒。"""
    return join_nibbles([INV_S_BOX[nibble] for nibble in split_nibbles(state)])


def shift_rows(state: int) -> int:
    """行移位：状态第 2 行循环左移一个半字节。

    半字节序列 (s00, s10, s01, s11) 中第 2 行是 s10 与 s11，即交换索引 1 与 3。
    半字节移位是可逆的自反操作，因此行移位与逆行移位用同一实现。
    """
    nibbles = split_nibbles(state)
    nibbles[1], nibbles[3] = nibbles[3], nibbles[1]
    return join_nibbles(nibbles)


#: 逆行移位与行移位等价（2×2 状态只有一次半字节循环移位）
inv_shift_rows = shift_rows


def _mix_columns_with(state: int, matrix: tuple[tuple[int, int], tuple[int, int]]) -> int:
    """按给定 2×2 矩阵对每一列做乘法，列内两个半字节线性组合。"""
    s00, s10, s01, s11 = split_nibbles(state)
    return join_nibbles([
        gf_mul(matrix[0][0], s00) ^ gf_mul(matrix[0][1], s10),
        gf_mul(matrix[1][0], s00) ^ gf_mul(matrix[1][1], s10),
        gf_mul(matrix[0][0], s01) ^ gf_mul(matrix[0][1], s11),
        gf_mul(matrix[1][0], s01) ^ gf_mul(matrix[1][1], s11),
    ])


def mix_columns(state: int) -> int:
    """列混淆：每列乘以 [[1, 4], [4, 1]]。"""
    return _mix_columns_with(state, MIX_MATRIX)


def inv_mix_columns(state: int) -> int:
    """逆列混淆：每列乘以 [[9, 2], [2, 9]]。"""
    return _mix_columns_with(state, INV_MIX_MATRIX)


# --------------------------------------------------------------------------- #
# 密钥扩展：16 bit 密钥 -> 6 个字节字 -> 3 个轮密钥
# --------------------------------------------------------------------------- #


def _rot_word(word: int) -> int:
    """RotWord：交换一个字节内的高、低半字节（教材记作 RotNib）。"""
    return ((word & 0x0F) << 4) | ((word >> 4) & 0x0F)


def _sub_word(word: int) -> int:
    """SubWord：对一个字节内的两个半字节分别查 S 盒。"""
    return (S_BOX[(word >> 4) & 0xF] << 4) | S_BOX[word & 0xF]


@lru_cache(maxsize=4096)
def expand_key(key: int) -> tuple[int, int, int]:
    """扩展 16 bit 密钥，返回三元组 (K0, K1, K2)。

    偶数字 w[i] = w[i-2] ⊕ RCON[i/2] ⊕ SubWord(RotWord(w[i-1]))；
    奇数字 w[i] = w[i-2] ⊕ w[i-1]。
    ``lru_cache`` 让 CBC 长文本加密时每个分组不必重复扩展密钥。
    """
    _check_range(key, 16, "密钥")
    words = [(key >> 8) & 0xFF, key & 0xFF]
    for index in range(2, 6):
        if index % 2 == 0:
            transformed = _sub_word(_rot_word(words[index - 1]))
            words.append(words[index - 2] ^ transformed ^ _ROUND_CONSTANTS[index // 2 - 1])
        else:
            words.append(words[index - 2] ^ words[index - 1])
    return (
        (words[0] << 8) | words[1],
        (words[2] << 8) | words[3],
        (words[4] << 8) | words[5],
    )


# --------------------------------------------------------------------------- #
# 单分组加解密
# --------------------------------------------------------------------------- #


def encrypt_block(plaintext: int, key: int) -> int:
    """加密一个 16 bit 分组，返回 16 bit 密文。"""
    _check_range(plaintext, 16, "明文")
    round_key0, round_key1, round_key2 = expand_key(key)
    state = add_round_key(plaintext, round_key0)
    # 第 1 轮：半字节代替 -> 行移位 -> 列混淆 -> 密钥加
    state = add_round_key(mix_columns(shift_rows(sub_nibbles(state))), round_key1)
    # 第 2 轮：无列混淆
    state = add_round_key(shift_rows(sub_nibbles(state)), round_key2)
    return state


def decrypt_block(ciphertext: int, key: int) -> int:
    """解密一个 16 bit 分组，严格按加密的逆序执行。"""
    _check_range(ciphertext, 16, "密文")
    round_key0, round_key1, round_key2 = expand_key(key)
    state = add_round_key(ciphertext, round_key2)
    state = inv_sub_nibbles(inv_shift_rows(state))
    state = add_round_key(state, round_key1)          # 与中间轮密钥异或
    state = inv_sub_nibbles(inv_shift_rows(inv_mix_columns(state)))
    return add_round_key(state, round_key0)


def encrypt_block_debug(plaintext: int, key: int) -> dict:
    """加密并记录每个变换后的中间状态，供第 2 关交叉测试逐项比对。"""
    _check_range(plaintext, 16, "明文")
    round_keys = expand_key(key)
    steps: list[dict[str, int | str]] = []

    def record(label: str, value: int) -> int:
        steps.append({"label": label, "value": value})
        return value

    state = record("初始明文", plaintext)
    state = record("轮密钥加 K0", add_round_key(state, round_keys[0]))
    state = record("第1轮 半字节代替", sub_nibbles(state))
    state = record("第1轮 行移位", shift_rows(state))
    state = record("第1轮 列混淆", mix_columns(state))
    state = record("第1轮 轮密钥加 K1", add_round_key(state, round_keys[1]))
    state = record("第2轮 半字节代替", sub_nibbles(state))
    state = record("第2轮 行移位", shift_rows(state))
    state = record("第2轮 轮密钥加 K2（密文）", add_round_key(state, round_keys[2]))
    return {"plaintext": plaintext, "key": key, "round_keys": round_keys, "steps": steps, "ciphertext": state}


def decrypt_block_debug(ciphertext: int, key: int) -> dict:
    """解密并记录中间状态，与 :func:`encrypt_block_debug` 对称。"""
    _check_range(ciphertext, 16, "密文")
    round_keys = expand_key(key)
    steps: list[dict[str, int | str]] = []

    def record(label: str, value: int) -> int:
        steps.append({"label": label, "value": value})
        return value

    state = record("初始密文", ciphertext)
    state = record("轮密钥加 K2", add_round_key(state, round_keys[2]))
    state = record("第2轮 逆行移位", inv_shift_rows(state))
    state = record("第2轮 逆半字节代替", inv_sub_nibbles(state))
    state = record("轮密钥加 K1", add_round_key(state, round_keys[1]))
    state = record("第1轮 逆列混淆", inv_mix_columns(state))
    state = record("第1轮 逆行移位", inv_shift_rows(state))
    state = record("第1轮 逆半字节代替", inv_sub_nibbles(state))
    state = record("轮密钥加 K0（明文）", add_round_key(state, round_keys[0]))
    return {"ciphertext": ciphertext, "key": key, "round_keys": round_keys, "steps": steps, "plaintext": state}
