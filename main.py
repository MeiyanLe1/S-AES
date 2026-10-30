"""S-AES 实验程序入口。

用法：
    python main.py              启动 GUI
    python main.py --selftest   只跑算法自测（不依赖 PyQt5），打印测试向量与结果
"""

from __future__ import annotations

import sys


def run_selftest() -> int:
    """命令行自测：不导入 GUI，缺失 PyQt5 也能验证算法。"""
    from s_aes.core import decrypt_block, encrypt_block, expand_key, format_binary, format_hex
    from s_aes.selftest import run_self_check

    print("=" * 64)
    print("S-AES 算法自测")
    print("=" * 64)
    key, plaintext = 0xA73B, 0x6F6B
    round_keys = expand_key(key)
    ciphertext = encrypt_block(plaintext, key)
    print(f"密钥      K  = {format_hex(key)}   ({format_binary(key)})")
    print(f"轮密钥    K0 = {format_hex(round_keys[0])}  K1 = {format_hex(round_keys[1])}  "
          f"K2 = {format_hex(round_keys[2])}")
    print(f"明文      P  = {format_hex(plaintext)}   ({format_binary(plaintext)})")
    print(f"密文      C  = {format_hex(ciphertext)}   ({format_binary(ciphertext)})")
    print(f"解密还原     = {format_hex(decrypt_block(ciphertext, key))}")
    print("-" * 64)

    results = run_self_check()
    for item in results:
        flag = "PASS" if item["ok"] else "FAIL"
        detail = f"  [{item['detail']}]" if item["detail"] else ""
        print(f"[{flag}] {item['name']}{detail}")
    passed = sum(1 for item in results if item["ok"])
    print("-" * 64)
    print(f"合计 {passed}/{len(results)} 项通过")
    return 0 if passed == len(results) else 1


def launch_gui() -> int:
    """启动图形界面。"""
    from PyQt5.QtCore import Qt
    from PyQt5.QtWidgets import QApplication

    # 高 DPI 支持必须在创建 QApplication 之前设置
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    from s_aes.gui import MainWindow, apply_theme

    application = QApplication(sys.argv)
    application.setApplicationName("S-AES 加解密实验程序")
    apply_theme(application)
    window = MainWindow()
    window.show()
    return application.exec_()


def main() -> int:
    if "--selftest" in sys.argv:
        return run_selftest()
    try:
        return launch_gui()
    except ImportError as error:
        print(f"[错误] 无法启动界面：{error}")
        print("请先安装 PyQt5：pip install PyQt5")
        print("也可以先运行算法自测：python main.py --selftest")
        return 1


if __name__ == "__main__":
    sys.exit(main())
