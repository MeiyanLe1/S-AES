"""多重加密：双重加密、三重加密（32 bit 密钥，EDE 结构）与中间相遇攻击。

密钥长度约定：32 bit 密钥 Key = K1 ‖ K2，高 16 位为 K1、低 16 位为 K2。
- 双重加密：C = E_K2(E_K1(P))，解密 P = D_K1(D_K2(C))
- 三重加密（K3 = K1）：C = E_K1(D_K2(E_K1(P)))，解密 P = D_K1(E_K2(D_K1(C)))
  采用「加密—解密—加密」结构，当 K1 == K2 时退化为单次 S-AES，与 3DES 的思路一致。
"""

from __future__ import annotations

import time
from typing import Callable, Sequence

from .core import ValidationError, decrypt_block, encrypt_block

__all__ = [
    "split_key_32",
    "double_encrypt",
    "double_decrypt",
    "triple_encrypt",
    "triple_decrypt",
    "meet_in_the_middle",
]

ProgressCallback = Callable[[int, int], None]


def split_key_32(key32: int) -> tuple[int, int]:
    """把 32 bit 密钥拆成 (K1, K2)。"""
    if not 0 <= key32 <= 0xFFFF_FFFF:
        raise ValidationError("密钥必须是 32 bit（00000000 ~ FFFFFFFF）")
    return (key32 >> 16) & 0xFFFF, key32 & 0xFFFF


def double_encrypt(plaintext: int, key32: int) -> int:
    """双重加密：先用 K1 加密，再用 K2 对结果加密。"""
    key1, key2 = split_key_32(key32)
    return encrypt_block(encrypt_block(plaintext, key1), key2)


def double_decrypt(ciphertext: int, key32: int) -> int:
    """双重解密：与加密逆序，先用 K2 解密，再用 K1 解密。"""
    key1, key2 = split_key_32(key32)
    return decrypt_block(decrypt_block(ciphertext, key2), key1)


def triple_encrypt(plaintext: int, key32: int) -> int:
    """三重加密（K3 = K1）：E_K1 → D_K2 → E_K1。"""
    key1, key2 = split_key_32(key32)
    return encrypt_block(decrypt_block(encrypt_block(plaintext, key1), key2), key1)


def triple_decrypt(ciphertext: int, key32: int) -> int:
    """三重解密：D_K1 → E_K2 → D_K1。"""
    key1, key2 = split_key_32(key32)
    return decrypt_block(encrypt_block(decrypt_block(ciphertext, key1), key2), key1)


def meet_in_the_middle(
    pairs: Sequence[tuple[int, int]],
    progress_callback: ProgressCallback | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> dict:
    """对双重加密发起中间相遇攻击，返回候选密钥与统计信息。

    原理：C = E_K2(E_K1(P))，令中间值 M = E_K1(P) = D_K2(C)。
    枚举全部 2^16 个 K1 计算 M 建表，再枚举 2^16 个 K2 计算 D_K2(C) 查表，
    命中即为一组候选 (K1, K2)，复杂度由 2^32 降到 2×2^16。

    参数：
        pairs: [(明文, 密文), ...]，至少一组；第一组用于建表匹配，其余用于验证。
        progress_callback: 可选进度回调，参数为 (已完成步数, 总步数)。
        cancel_check: 可选取消检查，返回 True 时提前结束（GUI 关闭窗口时使用）。
    """
    if not pairs:
        raise ValidationError("至少需要一组明密文对")
    for plaintext, ciphertext in pairs:
        if not 0 <= plaintext <= 0xFFFF or not 0 <= ciphertext <= 0xFFFF:
            raise ValidationError("明密文都必须是 16 bit 数据")

    started_at = time.perf_counter()
    # 用长度为 65536 的数组做索引表：中间值必然落在 0..65535，下标即中间值，O(1) 查找
    table: list[list[int] | None] = [None] * 0x10000
    pivot_plaintext, pivot_ciphertext = pairs[0]
    total_steps = 2 * 0x10000
    table_entries = 0

    for key1 in range(0x10000):
        middle = encrypt_block(pivot_plaintext, key1)
        bucket = table[middle]
        if bucket is None:
            table[middle] = [key1]
            table_entries += 1
        else:
            bucket.append(key1)  # 中间值碰撞时保留全部 K1，避免漏解
        if progress_callback and key1 % 0x1000 == 0:
            progress_callback(key1, total_steps)
        if cancel_check and cancel_check():
            return {"candidates": [], "elapsed": time.perf_counter() - started_at,
                    "table_entries": table_entries, "middle_hits": 0, "cancelled": True}

    candidates: list[tuple[int, int]] = []
    middle_hits = 0
    for key2 in range(0x10000):
        middle = decrypt_block(pivot_ciphertext, key2)
        bucket = table[middle]
        if bucket is not None:
            middle_hits += len(bucket)
            for key1 in bucket:
                # 用全部明密文对复核，排除中间值偶然碰撞带来的假密钥
                if all(double_encrypt(pt, (key1 << 16) | key2) == ct for pt, ct in pairs):
                    candidates.append((key1, key2))
        if progress_callback and key2 % 0x1000 == 0:
            progress_callback(0x10000 + key2, total_steps)
        if cancel_check and cancel_check():
            return {"candidates": candidates, "elapsed": time.perf_counter() - started_at,
                    "table_entries": table_entries, "middle_hits": middle_hits, "cancelled": True}

    if progress_callback:
        progress_callback(total_steps, total_steps)
    return {
        "candidates": candidates,
        "elapsed": time.perf_counter() - started_at,
        "table_entries": table_entries,
        "middle_hits": middle_hits,
        "cancelled": False,
    }
