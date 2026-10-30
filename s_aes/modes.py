"""工作模式与字符串扩展：按 2 字节分组、填充、ASCII 字符串加解密、CBC 模式及篡改分析。

S-AES 分组只有 16 bit（2 字节），因此这里的分组工具都以 2 字节为单位工作。
"""

from __future__ import annotations

from typing import Sequence

from .core import ValidationError, decrypt_block, encrypt_block, format_hex

__all__ = [
    "BLOCK_SIZE",
    "pad",
    "unpad",
    "bytes_to_blocks",
    "blocks_to_bytes",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_ascii",
    "decrypt_ascii",
    "encrypt_cbc",
    "decrypt_cbc",
    "tamper_analysis",
    "bytes_to_display",
    "decode_text",
    "xor_bytes",
]

#: S-AES 分组大小（字节）
BLOCK_SIZE = 2


# --------------------------------------------------------------------------- #
# 分组与填充
# --------------------------------------------------------------------------- #


def pad(data: bytes) -> bytes:
    """按 2 字节分组填充（PKCS#7 变体）。

    缺 1 字节补 0x01，缺 2 字节（恰好整除）补一整组 0x02 0x02。
    补满一整组是为了让解密端总能无歧义地去掉填充，顺便隐藏「明文长度是否恰好为偶数」。
    """
    remainder = len(data) % BLOCK_SIZE
    padding_length = BLOCK_SIZE - remainder
    return data + bytes([padding_length]) * padding_length


def unpad(data: bytes) -> bytes:
    """去除 :func:`pad` 添加的填充，填充不合法时抛错（篡改密文后常会出现）。"""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValidationError("带填充的明文长度必须是 2 的整数倍")
    padding_length = data[-1]
    if padding_length not in (1, 2):
        raise ValidationError(f"填充字节非法（0x{padding_length:02X}）")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValidationError("填充内容与填充长度不一致，数据可能已被篡改")
    return data[:-padding_length]


def bytes_to_blocks(data: bytes) -> list[int]:
    """把字节串按 2 字节切成 16 bit 分组列表（大端）。"""
    if len(data) % BLOCK_SIZE != 0:
        raise ValidationError("数据长度必须是 2 的整数倍")
    return [(data[i] << 8) | data[i + 1] for i in range(0, len(data), BLOCK_SIZE)]


def blocks_to_bytes(blocks: Sequence[int]) -> bytes:
    """把 16 bit 分组列表还原为字节串。"""
    result = bytearray()
    for block in blocks:
        result.append((block >> 8) & 0xFF)
        result.append(block & 0xFF)
    return bytes(result)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """两个等长字节串逐字节异或（CBC 的链式反馈要用）。"""
    return bytes(a ^ b for a, b in zip(left, right))


# --------------------------------------------------------------------------- #
# 单分组字节接口
# --------------------------------------------------------------------------- #


def encrypt_bytes(data: bytes, key: int) -> bytes:
    """对长度恰为 2 的整数倍的数据逐组 ECB 加密（不填充）。"""
    return blocks_to_bytes([encrypt_block(block, key) for block in bytes_to_blocks(data)])


def decrypt_bytes(data: bytes, key: int) -> bytes:
    """对长度恰为 2 的整数倍的数据逐组 ECB 解密（不填充）。"""
    return blocks_to_bytes([decrypt_block(block, key) for block in bytes_to_blocks(data)])


# --------------------------------------------------------------------------- #
# 第 3 关：ASCII 字符串加解密
# --------------------------------------------------------------------------- #


def encrypt_ascii(text: str, key: int) -> dict:
    """加密字符串（UTF-8 编码，等效于 ASCII 场景），返回分组明细与多种展示形式。"""
    if not text:
        raise ValidationError("请输入要加密的文本")
    raw = text.encode("utf-8")
    padded = pad(raw)
    groups = []
    cipher_blocks = []
    for index, plain_block in enumerate(bytes_to_blocks(padded)):
        cipher_block = encrypt_block(plain_block, key)
        cipher_blocks.append(cipher_block)
        groups.append({"index": index, "plain_block": plain_block, "cipher_block": cipher_block})
    cipher_bytes = blocks_to_bytes(cipher_blocks)
    return {
        "raw": raw,
        "padded": padded,
        "groups": groups,
        "cipher_bytes": cipher_bytes,
        "cipher_hex": cipher_bytes.hex().upper(),
        "cipher_display": bytes_to_display(cipher_bytes),
        "padding_length": len(padded) - len(raw),
    }


def decrypt_ascii(cipher_bytes: bytes, key: int) -> dict:
    """解密字符串密文，返回明文分组明细与去填充后的结果。"""
    if not cipher_bytes:
        raise ValidationError("请输入要解密的十六进制密文")
    if len(cipher_bytes) % BLOCK_SIZE != 0:
        raise ValidationError("密文长度必须是 2 字节的整数倍")
    groups = []
    plain_blocks = []
    for index, cipher_block in enumerate(bytes_to_blocks(cipher_bytes)):
        plain_block = decrypt_block(cipher_block, key)
        plain_blocks.append(plain_block)
        groups.append({"index": index, "cipher_block": cipher_block, "plain_block": plain_block})
    padded_plain = blocks_to_bytes(plain_blocks)
    error_message = ""
    plain = b""
    try:
        plain = unpad(padded_plain)
    except ValidationError as error:
        error_message = str(error)
    return {
        "padded_plain": padded_plain,
        "plain_bytes": plain,
        "text": decode_text(plain) if plain else decode_text(padded_plain),
        "padding_valid": not error_message,
        "padding_error": error_message,
        "groups": groups,
    }


# --------------------------------------------------------------------------- #
# 第 5 关：CBC 密码分组链接模式
# --------------------------------------------------------------------------- #


def encrypt_cbc(plaintext: bytes, key: int, iv: int, use_padding: bool = True) -> dict:
    """CBC 加密：C_i = E_K(P_i ⊕ C_{i-1})，C_0 的「前一组」就是初始向量 IV。

    初始向量必须由加解密双方共享：双方 IV 不同，第一组明文就无法还原。
    """
    if not 0 <= iv <= 0xFFFF:
        raise ValidationError("初始向量必须是 16 bit")
    if not plaintext:
        raise ValidationError("明文不能为空")
    padded = pad(plaintext) if use_padding else plaintext
    if len(padded) % BLOCK_SIZE != 0:
        raise ValidationError("不做填充时明文长度必须是 2 字节的整数倍")

    previous_block = iv
    plain_groups: list[int] = []
    cipher_groups: list[int] = []
    detail = []
    for index, plain_block in enumerate(bytes_to_blocks(padded)):
        chained_input = plain_block ^ previous_block
        cipher_block = encrypt_block(chained_input, key)
        previous_block = cipher_block
        plain_groups.append(plain_block)
        cipher_groups.append(cipher_block)
        detail.append({"index": index, "plain_block": plain_block, "chain_block": chained_input, "cipher_block": cipher_block})
    return {
        "iv": iv,
        "padded": padded,
        "padding_length": len(padded) - len(plaintext),
        "plain_groups": plain_groups,
        "cipher_groups": cipher_groups,
        "cipher_bytes": blocks_to_bytes(cipher_groups),
        "detail": detail,
    }


def decrypt_cbc(
    cipher_groups: Sequence[int],
    key: int,
    iv: int,
    strip_padding: bool = True,
) -> dict:
    """CBC 解密：P_i = D_K(C_i) ⊕ C_{i-1}。

    ``strip_padding=False`` 时保留填充字节，用于篡改演示中「填充已损坏」的场景。
    """
    if not cipher_groups:
        raise ValidationError("密文分组不能为空")
    if not 0 <= iv <= 0xFFFF:
        raise ValidationError("初始向量必须是 16 bit")

    previous_block = iv
    plain_groups: list[int] = []
    detail = []
    for index, cipher_block in enumerate(cipher_groups):
        decrypted_block = decrypt_block(cipher_block, key)
        plain_block = decrypted_block ^ previous_block
        previous_block = cipher_block
        plain_groups.append(plain_block)
        detail.append({"index": index, "cipher_block": cipher_block, "decrypted_block": decrypted_block, "plain_block": plain_block})

    padded_plain = blocks_to_bytes(plain_groups)
    error_message = ""
    plain_bytes = padded_plain
    if strip_padding:
        try:
            plain_bytes = unpad(padded_plain)
        except ValidationError as error:
            error_message = str(error)
    return {
        "plain_groups": plain_groups,
        "padded_plain": padded_plain,
        "plain_bytes": plain_bytes,
        "padding_valid": not error_message,
        "padding_error": error_message,
        "detail": detail,
    }


def tamper_analysis(
    cipher_groups: Sequence[int],
    key: int,
    iv: int,
    group_index: int,
    new_value: int,
) -> dict:
    """篡改指定密文分组后重新解密，并给出出错分组的传播说明。

    保留原始分组以便界面左右对比，返回逐字节差异与文字解释。
    """
    if not 0 <= group_index < len(cipher_groups):
        raise ValidationError("分组下标超出范围")
    if not 0 <= new_value <= 0xFFFF:
        raise ValidationError("新的分组值必须是 16 bit")

    original_groups = list(cipher_groups)
    tampered_groups = list(cipher_groups)
    tampered_groups[group_index] = new_value
    delta = original_groups[group_index] ^ new_value

    original = decrypt_cbc(original_groups, key, iv, strip_padding=False)
    tampered = decrypt_cbc(tampered_groups, key, iv, strip_padding=False)
    original_bytes = original["padded_plain"]
    tampered_bytes = tampered["padded_plain"]

    diff_positions = [i for i, (a, b) in enumerate(zip(original_bytes, tampered_bytes)) if a != b]
    # 被改分组自身明文完全不可预测；下一分组只在被翻转的比特位上出错
    explain_lines = [
        f"篡改了第 {group_index + 1} 组密文（异或差值 {format_hex(delta, 16)}）：",
        f"· 第 {group_index + 1} 组明文整组变为乱码（该组解密结果依赖被改动的密文）。",
    ]
    if group_index + 1 < len(original_groups):
        explain_lines.append(
            f"· 第 {group_index + 2} 组明文仅在相同比特位置发生翻转（错误向后传播一组后停止）。"
        )
    explain_lines.append("· 其余分组明文不受影响，体现 CBC 模式的错误传播特性。")

    return {
        "group_index": group_index,
        "original_groups": original_groups,
        "tampered_groups": tampered_groups,
        "original_plain": original_bytes,
        "tampered_plain": tampered_bytes,
        "original_groups_plain": original["plain_groups"],
        "tampered_groups_plain": tampered["plain_groups"],
        "diff_positions": diff_positions,
        "delta": delta,
        "explanation": "\n".join(explain_lines),
    }


# --------------------------------------------------------------------------- #
# 展示辅助
# --------------------------------------------------------------------------- #


def bytes_to_display(data: bytes, placeholder: str = "·") -> str:
    """把字节串渲染成「可打印字符 + 占位符」的形式，用于展示很可能是乱码的密文。"""
    return "".join(chr(byte) if 32 <= byte <= 126 else placeholder for byte in data)


def decode_text(data: bytes) -> str:
    """把明文字节解码为字符串，非法序列用替代字符显示，保证界面不抛异常。"""
    return data.decode("utf-8", errors="replace")
