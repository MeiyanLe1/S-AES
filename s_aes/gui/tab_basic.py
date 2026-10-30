"""第 1 关：基本测试（16 bit 明文 + 16 bit 密钥 → 16 bit 密文），并附第 2 关交叉测试面板。"""

from __future__ import annotations

import random

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core import (
    INV_MIX_MATRIX,
    MIX_MATRIX,
    S_BOX,
    ValidationError,
    decrypt_block,
    decrypt_block_debug,
    encrypt_block,
    encrypt_block_debug,
    expand_key,
    format_binary,
    format_hex,
)
from .page_base import PageBase
from .theme import PRIMARY, SUCCESS, TEXT_MUTED, mono_font
from .widgets import BitGrid, Card, CopyButton, HexInput, ResultCard, muted_label


class BasicTab(PageBase):
    """第 1 关页面。"""

    PAGE_TITLE = "第 1 关 · 基本测试"
    PAGE_SUBTITLE = "16 bit 明文 + 16 bit 密钥 → 16 bit 密文；支持 GUI 交互式加密与解密"

    def __init__(self, status_callback=None, parent: QWidget | None = None):
        super().__init__(status_callback, parent)
        self._last_report: dict | None = None
        self._build_key_card()
        self._build_data_row()
        self._build_state_card()
        self._build_cross_test_card()
        self.layout.addStretch(1)
        # 初始化位点阵与轮密钥显示（控件创建时不会触发 valueChanged）
        self.key_grid.set_value(self.key_input.value())
        self.plain_grid.set_value(self.plain_input.value())
        self.cipher_grid.set_value(self.cipher_input.value())
        self._on_key_changed(self.key_input.value())

    # ------------------------------------------------------------------ #
    # 界面构建
    # ------------------------------------------------------------------ #
    def _build_key_card(self) -> None:
        card = Card("密钥与密钥扩展", hint="S-AES 使用 16 bit 密钥，经扩展得到 3 个 16 bit 轮密钥 K0 / K1 / K2",
                    badge_text="16 bit")
        self.layout.addWidget(card)

        row = QHBoxLayout()
        row.setSpacing(16)
        left = QVBoxLayout()
        left.setSpacing(8)
        self.key_input = HexInput("", 16, 0xA73B, "附录 D 示例密钥：A73B")
        self.key_input.valueChanged.connect(self._on_key_changed)
        left.addWidget(self.key_input)
        self.key_grid = BitGrid()
        self.key_grid.valueChanged.connect(self.key_input.set_value)
        left.addWidget(self.key_grid)
        row.addLayout(left, 3)

        actions = QVBoxLayout()
        actions.setSpacing(8)
        actions.addWidget(self._small_button("示例密钥", lambda: self.key_input.set_value(0xA73B)))
        actions.addWidget(self._small_button("随机密钥", lambda: self.key_input.set_value(random.getrandbits(16))))
        row.addLayout(actions, 1)

        self.round_key_labels: list[QLabel] = []
        round_key_box = QVBoxLayout()
        round_key_box.setSpacing(6)
        round_key_box.addWidget(muted_label("轮密钥（密钥扩展结果）", 11))
        for index in range(3):
            label = QLabel(f"K{index} = ----")
            label.setFont(mono_font(15, QFont.DemiBold))
            label.setStyleSheet(f"color: {PRIMARY};")
            self.round_key_labels.append(label)
            round_key_box.addWidget(label)
        row.addLayout(round_key_box, 2)
        card.body.addLayout(row)

    def _build_data_row(self) -> None:
        row = QHBoxLayout()
        row.setSpacing(14)

        plain_card = Card("明文 P", badge_text="16 bit")
        self.plain_input = HexInput("", 16, 0x6F6B, "附录 D 示例明文：6F6B")
        plain_card.body.addWidget(self.plain_input)
        self.plain_grid = BitGrid()
        self.plain_grid.valueChanged.connect(self.plain_input.set_value)
        self.plain_input.valueChanged.connect(self.plain_grid.set_value)
        plain_card.body.addWidget(self.plain_grid)
        plain_actions = QHBoxLayout()
        plain_actions.addWidget(self._small_button("随机明文", lambda: self.plain_input.set_value(random.getrandbits(16))))
        plain_actions.addWidget(self._small_button("清空", self.plain_input.clear))
        plain_card.body.addLayout(plain_actions)
        row.addWidget(plain_card, 1)

        middle = QVBoxLayout()
        middle.setSpacing(10)
        middle.addStretch(1)
        encrypt_button = QPushButton("加密 ↓")
        encrypt_button.setProperty("variant", "primary")
        encrypt_button.setMinimumHeight(42)
        encrypt_button.setCursor(Qt.PointingHandCursor)
        encrypt_button.clicked.connect(self.do_encrypt)
        middle.addWidget(encrypt_button)

        decrypt_button = QPushButton("↑ 解密")
        decrypt_button.setProperty("variant", "accent")
        decrypt_button.setMinimumHeight(42)
        decrypt_button.setCursor(Qt.PointingHandCursor)
        decrypt_button.clicked.connect(self.do_decrypt)
        middle.addWidget(decrypt_button)

        swap_button = QPushButton("互换 P ↔ C")
        swap_button.setProperty("variant", "ghost")
        swap_button.setCursor(Qt.PointingHandCursor)
        swap_button.clicked.connect(self._swap)
        middle.addWidget(swap_button)
        middle.addStretch(1)
        row.addLayout(middle, 0)

        cipher_card = Card("密文 C", badge_text="16 bit")
        self.cipher_input = HexInput("", 16, 0x0738, "可手动修改后点击解密")
        cipher_card.body.addWidget(self.cipher_input)
        self.cipher_grid = BitGrid()
        self.cipher_grid.valueChanged.connect(self.cipher_input.set_value)
        self.cipher_input.valueChanged.connect(self.cipher_grid.set_value)
        cipher_card.body.addWidget(self.cipher_grid)
        cipher_actions = QHBoxLayout()
        cipher_actions.addWidget(CopyButton("复制密文", lambda: self.cipher_input.edit.text().strip()))
        cipher_actions.addWidget(self._small_button("清空", self.cipher_input.clear))
        cipher_card.body.addLayout(cipher_actions)
        row.addWidget(cipher_card, 1)

        self.layout.addLayout(row)

    def _build_state_card(self) -> None:
        card = Card("轮函数中间状态", hint="逐轮展示每个变换后的 16 bit 状态，可与同学实现逐项比对",
                    badge_text="可折叠")
        self.detail_toggle = QPushButton("展开 / 收起")
        self.detail_toggle.setProperty("variant", "ghost")
        self.detail_toggle.setCursor(Qt.PointingHandCursor)
        self.detail_toggle.clicked.connect(self._toggle_detail)
        card.header_layout.addWidget(self.detail_toggle)

        self.result_card = ResultCard("最近一次运算结果")
        card.body.addWidget(self.result_card)

        self.state_table = QTableWidget(0, 3)
        self.state_table.setHorizontalHeaderLabels(["变换步骤", "十六进制", "二进制"])
        self.state_table.verticalHeader().setVisible(False)
        self.state_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.state_table.setAlternatingRowColors(True)
        self.state_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.state_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.state_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.state_table.setMinimumHeight(230)
        self.state_table.setVisible(False)
        card.body.addWidget(self.state_table)
        self.layout.addWidget(card)

    def _build_cross_test_card(self) -> None:
        card = Card("第 2 关 · 交叉测试", hint="与同学交换下列参数与向量，密文一致即说明算法流程与转换单元完全相同",
                    badge_text="标准一致性")
        grid_row = QHBoxLayout()
        grid_row.setSpacing(14)

        sbox_box = QVBoxLayout()
        sbox_box.setSpacing(4)
        sbox_box.addWidget(muted_label("替换盒 S-Box（4×4 半字节）"))
        sbox_label = QLabel("\n".join(
            "  ".join(f"{S_BOX[row * 4 + column]:X}" for column in range(4)) for row in range(4)
        ))
        sbox_label.setFont(mono_font(14))
        sbox_label.setStyleSheet(f"color: {TEXT_MUTED};")
        sbox_box.addWidget(sbox_label)
        sbox_box.addStretch(1)
        grid_row.addLayout(sbox_box)

        matrix_box = QVBoxLayout()
        matrix_box.setSpacing(4)
        matrix_box.addWidget(muted_label("列混淆矩阵 / 逆矩阵"))
        matrix_label = QLabel(
            f"[{MIX_MATRIX[0][0]} {MIX_MATRIX[0][1]}]   [{INV_MIX_MATRIX[0][0]} {INV_MIX_MATRIX[0][1]}]\n"
            f"[{MIX_MATRIX[1][0]} {MIX_MATRIX[1][1]}]   [{INV_MIX_MATRIX[1][0]} {INV_MIX_MATRIX[1][1]}]"
        )
        matrix_label.setFont(mono_font(14))
        matrix_label.setStyleSheet(f"color: {TEXT_MUTED};")
        matrix_box.addWidget(matrix_label)
        matrix_box.addWidget(muted_label("GF(2⁴) 模多项式 x⁴ + x + 1"))
        matrix_box.addStretch(1)
        grid_row.addLayout(matrix_box)

        vector_box = QVBoxLayout()
        vector_box.setSpacing(6)
        vector_box.addWidget(muted_label("参考向量（明文 6F6B / 密钥 A73B）"))
        self.vector_label = QLabel("密文 = 0738")
        self.vector_label.setFont(mono_font(14))
        self.vector_label.setStyleSheet(f"color: {SUCCESS};")
        vector_box.addWidget(self.vector_label)
        copy_button = CopyButton("复制测试向量", self._build_vector_text)
        vector_box.addWidget(copy_button)
        vector_box.addStretch(1)
        grid_row.addLayout(vector_box, 1)

        card.body.addLayout(grid_row)
        self.layout.addWidget(card)

    def _small_button(self, text: str, handler) -> QPushButton:
        button = QPushButton(text)
        button.setProperty("variant", "ghost")
        button.setCursor(Qt.PointingHandCursor)
        button.clicked.connect(handler)
        return button

    # ------------------------------------------------------------------ #
    # 交互逻辑
    # ------------------------------------------------------------------ #
    def _on_key_changed(self, key: int) -> None:
        try:
            round_keys = expand_key(key)
        except ValidationError:
            for index, label in enumerate(self.round_key_labels):
                label.setText(f"K{index} = ----")
            return
        for index, label in enumerate(self.round_key_labels):
            label.setText(f"K{index} = {format_hex(round_keys[index])}")

    def do_encrypt(self) -> None:
        try:
            plaintext = self.plain_input.value()
            key = self.key_input.value()
            ciphertext = encrypt_block(plaintext, key)
        except ValidationError as error:
            self.report_error(error)
            return
        self.cipher_input.set_value(ciphertext)
        report = encrypt_block_debug(plaintext, key)
        self._last_report = report
        self._show_report(report, "加密")
        self.report_success(f"加密完成：明文 {format_hex(plaintext)} ⊕ 密钥 {format_hex(key)} → 密文 {format_hex(ciphertext)}")

    def do_decrypt(self) -> None:
        try:
            ciphertext = self.cipher_input.value()
            key = self.key_input.value()
            plaintext = decrypt_block(ciphertext, key)
        except ValidationError as error:
            self.report_error(error)
            return
        self.plain_input.set_value(plaintext)
        report = decrypt_block_debug(ciphertext, key)
        self._last_report = report
        self._show_report(report, "解密")
        self.report_success(f"解密完成：密文 {format_hex(ciphertext)} → 明文 {format_hex(plaintext)}")

    def _show_report(self, report: dict, action: str) -> None:
        result_value = report["ciphertext"] if action == "加密" else report["plaintext"]
        self.result_card.set_result(
            format_hex(result_value),
            f"{action}结果 · 二进制 {format_binary(result_value)}",
        )
        steps = report["steps"]
        self.state_table.setRowCount(len(steps))
        for row, step in enumerate(steps):
            self.state_table.setItem(row, 0, QTableWidgetItem(str(step["label"])))
            hex_item = QTableWidgetItem(format_hex(int(step["value"])))
            hex_item.setFont(mono_font(13))
            self.state_table.setItem(row, 1, hex_item)
            self.state_table.setItem(row, 2, QTableWidgetItem(format_binary(int(step["value"]))))
        if not self.state_table.isVisible():
            self._toggle_detail()

    def _toggle_detail(self) -> None:
        self.state_table.setVisible(not self.state_table.isVisible())

    def _swap(self) -> None:
        plaintext_text = self.plain_input.edit.text()
        self.plain_input.edit.setText(self.cipher_input.edit.text())
        self.cipher_input.edit.setText(plaintext_text)
        self.status("已互换明文与密文输入")

    def _build_vector_text(self) -> str:
        try:
            plaintext = self.plain_input.value()
            key = self.key_input.value()
        except ValidationError:
            return ""
        ciphertext = encrypt_block(plaintext, key)
        round_keys = expand_key(key)
        self.vector_label.setText(f"密文 = {format_hex(ciphertext)}")
        lines = [
            "S-AES 交叉测试向量",
            f"明文 P = {format_hex(plaintext)}  ({format_binary(plaintext)})",
            f"密钥 K = {format_hex(key)}  ({format_binary(key)})",
            f"密文 C = {format_hex(ciphertext)}  ({format_binary(ciphertext)})",
            f"轮密钥 K0 = {format_hex(round_keys[0])}  K1 = {format_hex(round_keys[1])}  K2 = {format_hex(round_keys[2])}",
            "S 盒 = " + " ".join(f"{value:X}" for value in S_BOX),
            f"列混淆 = [[{MIX_MATRIX[0][0]},{MIX_MATRIX[0][1]}],[{MIX_MATRIX[1][0]},{MIX_MATRIX[1][1]}]]  "
            f"逆矩阵 = [[{INV_MIX_MATRIX[0][0]},{INV_MIX_MATRIX[0][1]}],[{INV_MIX_MATRIX[1][0]},{INV_MIX_MATRIX[1][1]}]]",
        ]
        if self._last_report and self._last_report.get("key") == key:
            lines.append("中间状态：")
            for step in self._last_report["steps"]:
                lines.append(f"  {step['label']}: {format_hex(int(step['value']))}")
        self.status("测试向量已复制到剪贴板")
        return "\n".join(lines)
