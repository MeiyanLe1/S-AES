"""内置自测：GUI 的「算法自测」按钮与 ``python main.py --selftest`` 共用同一套检查。

每一项检查返回 (名称, 是否通过, 说明)，便于在界面上逐条展示，也可直接打印到控制台。
"""

from __future__ import annotations

import random

from .core import decrypt_block, encrypt_block, expand_key, mix_columns, shift_rows, sub_nibbles
from .modes import decrypt_ascii, decrypt_cbc, encrypt_ascii, encrypt_cbc, tamper_analysis
from .multi import double_encrypt, meet_in_the_middle, triple_decrypt, triple_encrypt


def run_self_check(include_attack: bool = True) -> list[dict]:
    """执行全部自测项，返回结果列表。"""
    results: list[dict] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        results.append({"name": name, "ok": bool(condition), "detail": detail})

    round_keys = expand_key(0x2D55)
    check("密钥扩展 2D55 → BCE9 / A34A", round_keys == (0x2D55, 0xBCE9, 0xA34A),
          f"K1={round_keys[1]:04X} K2={round_keys[2]:04X}")

    check("附录 D 中间算例（代替 / 行移位 / 列混淆）",
          sub_nibbles(0x8A1C) == 0x604C and shift_rows(0x604C) == 0x6C40 and mix_columns(0x6C40) == 0x3743,
          "8A1C→604C→6C40→3743")

    ciphertext = encrypt_block(0x6F6B, 0xA73B)
    check("已知向量 6F6B / A73B", ciphertext == 0x0738 and decrypt_block(ciphertext, 0xA73B) == 0x6F6B,
          f"密文={ciphertext:04X}")

    rng = random.Random(2026)
    samples = [(rng.getrandbits(16), rng.getrandbits(16)) for _ in range(200)]
    check("随机 200 组加解密往返", all(decrypt_block(encrypt_block(p, k), k) == p for p, k in samples))

    text = "信息安全导论 S-AES"
    ascii_report = encrypt_ascii(text, 0x2D55)
    recovered = decrypt_ascii(ascii_report["cipher_bytes"], 0x2D55)
    check("字符串加解密往返", recovered["text"] == text and recovered["padding_valid"],
          f"{len(ascii_report['groups'])} 个分组")

    plaintext = "CBC 工作模式：分组链接与错误传播演示".encode("utf-8")
    cbc_report = encrypt_cbc(plaintext, 0x2D55, 0x5A5A)
    cbc_back = decrypt_cbc(cbc_report["cipher_groups"], 0x2D55, 0x5A5A)
    check("CBC 加解密往返", cbc_back["plain_bytes"] == plaintext,
          f"{len(cbc_report['cipher_groups'])} 个分组")

    analysis = tamper_analysis(cbc_report["cipher_groups"], 0x2D55, 0x5A5A, 1,
                               cbc_report["cipher_groups"][1] ^ 0x0001)
    touched_groups = {position // 2 for position in analysis["diff_positions"]}
    check("CBC 篡改错误传播", touched_groups <= {1, 2}, f"受影响分组：{sorted(g + 1 for g in touched_groups)}")

    key32 = 0x0A5C_3E71
    triple_ok = triple_decrypt(triple_encrypt(0x1234, key32), key32) == 0x1234
    check("三重加密（EDE，K3=K1）往返", triple_ok)

    if include_attack:
        pairs = [(0x1234, double_encrypt(0x1234, key32)), (0x9ABC, double_encrypt(0x9ABC, key32))]
        attack = meet_in_the_middle(pairs)
        found = (0x0A5C, 0x3E71) in attack["candidates"]
        check("中间相遇攻击命中正确密钥", found,
              f"候选 {len(attack['candidates'])} 个，用时 {attack['elapsed']:.2f}s")

    return results
