"""第 4 关：多重加密——双重加密与三重加密（32 bit 密钥，EDE 结构）。"""

from __future__ import annotations

import random

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core import ValidationError, decrypt_block, encrypt_block, format_binary, format_hex
from ..multi import double_decrypt, double_encrypt, split_key_32, triple_decrypt, triple_encrypt
from .page_base import PageBase
from .theme import ACCENT, PRIMARY, SUCCESS, TEXT_FAINT, TEXT_MUTED, mono_font, rgba
from .widgets import BitGrid, Card, HexInput, ResultCard, SegmentedControl, muted_label


class MultiTab(PageBase):
    """第 4 关页面（加密 / 解密 / 中间值展示）。"""

    PAGE_TITLE = "第 4 关 · 多重加密"
    PAGE_SUBTITLE = "分组仍为 16 bit，密钥扩展为 32 bit：Key = K1 ‖ K2；三重加密采用 K3 = K1 的 EDE 结构"

    def __init__(self, status_callback=None, parent: QWidget | None = None):
        super().__init__(status_callback, parent)
        self._mode = 0
        self._build_key_card()
        self._build_mode_card()
        self._build_flow_card()
        self._build_result_card()
        self.layout.addStretch(1)
        self.key_grid.set_value(self.key_input.value())
        self._on_key_changed(0x1F2E3D4C)

    # ------------------------------------------------------------------ #
    def _build_key_card(self) -> None:
        card = Card("32 bit 密钥", hint="高 16 位为 K1、低 16 位为 K2；双重加密两组密钥都用，三重加密复用 K1",
                    badge_text="32 bit")
        row = QHBoxLayout()
        row.setSpacing(16)
        left = QVBoxLayout()
        left.setSpacing(8)
        self.key_input = HexInput("密钥 Key (K1 ‖ K2)", 32, 0x1F2E3D4C, "示例：1F2E3D4C → K1=1F2E, K2=3D4C")
        self.key_input.valueChanged.connect(self._on_key_changed)
        left.addWidget(self.key_input)
        self.key_grid = BitGrid(32)
        self.key_grid.valueChanged.connect(self.key_input.set_value)
        left.addWidget(self.key_grid)
        row.addLayout(left, 3)

        actions = QVBoxLayout()
        actions.setSpacing(8)
        actions.addWidget(self._small_button("随机密钥", lambda: self.key_input.set_value(random.getrandbits(32))))
        actions.addWidget(self._small_button("示例密钥", lambda: self.key_input.set_value(0x1F2E3D4C)))
        row.addLayout(actions, 1)

        chips = QVBoxLayout()
        chips.setSpacing(8)
        chips.addWidget(muted_label("密钥拆分"))
        chip_row = QHBoxLayout()
        chip_row.setSpacing(8)
        self.key1_chip = self._key_chip("K1", PRIMARY)
        self.key2_chip = self._key_chip("K2", ACCENT)
        chip_row.addWidget(self.key1_chip)
        chip_row.addWidget(self.key2_chip)
        chip_row.addStretch(1)
        chips.addLayout(chip_row)
        chips.addStretch(1)
        row.addLayout(chips, 2)
        card.body.addLayout(row)
        self.layout.addWidget(card)

    def _build_mode_card(self) -> None:
        card = Card("模式与数据", badge_text="16 bit 分组")
        self.mode_control = SegmentedControl(["双重加密  C = E_K2(E_K1(P))", "三重加密  C = E_K1(D_K2(E_K1(P)))"])
        self.mode_control.changed.connect(self._on_mode_changed)
        card.body.addWidget(self.mode_control)

        data_row = QHBoxLayout()
        data_row.setSpacing(14)
        self.plain_input = HexInput("明文 P", 16, 0x1234, "十六进制或二进制")
        self.cipher_input = HexInput("密文 C", 16, 0x0000, "可手工修改后再解密")
        data_row.addWidget(self.plain_input, 1)
        data_row.addWidget(self.cipher_input, 1)
        card.body.addLayout(data_row)

        button_row = QHBoxLayout()
        button_row.setSpacing(10)
        encrypt_button = QPushButton("加密 →")
        encrypt_button.setProperty("variant", "primary")
        encrypt_button.setMinimumHeight(38)
        encrypt_button.setCursor(Qt.PointingHandCursor)
        encrypt_button.clicked.connect(self.do_encrypt)
        decrypt_button = QPushButton("← 解密")
        decrypt_button.setProperty("variant", "accent")
        decrypt_button.setMinimumHeight(38)
        decrypt_button.setCursor(Qt.PointingHandCursor)
        decrypt_button.clicked.connect(self.do_decrypt)
        button_row.addWidget(encrypt_button)
        button_row.addWidget(decrypt_button)
        button_row.addStretch(1)
        card.body.addLayout(button_row)
        self.layout.addWidget(card)

    def _build_flow_card(self) -> None:
        card = Card("运算流程", hint="每张卡片是流程中的一个加密 / 解密步骤，值为该步骤输出的 16 bit 中间状态",
                    badge_text="中间值")
        self.flow_layout = QHBoxLayout()
        self.flow_layout.setSpacing(8)
        card.body.addLayout(self.flow_layout)
        self.layout.addWidget(card)

    def _build_result_card(self) -> None:
        card = Card("结果", badge_text="32 bit 密钥")
        self.result_card = ResultCard("加 / 解密结果")
        card.body.addWidget(self.result_card)
        self.formula_label = muted_label("")
        card.body.addWidget(self.formula_label)
        self.layout.addWidget(card)

    # ------------------------------------------------------------------ #
    def _key_chip(self, title: str, color: str) -> QFrame:
        chip = QFrame()
        chip.setStyleSheet(
            f"QFrame {{ background: {rgba(color, 0.10)}; border: 1px solid {rgba(color, 0.40)};"
            "border-radius: 10px; }"
        )
        layout = QVBoxLayout(chip)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(2)
        label = QLabel(f"{title} = ----")
        label.setFont(mono_font(15, QFont.DemiBold))
        label.setStyleSheet(f"color: {color};")
        layout.addWidget(label)
        chip.value_label = label  # type: ignore[attr-defined]
        return chip

    def _small_button(self, text: str, handler) -> QPushButton:
        button = QPushButton(text)
        button.setProperty("variant", "ghost")
        button.setCursor(Qt.PointingHandCursor)
        button.clicked.connect(handler)
        return button

    def _step_chip(self, title: str, value: str, color: str = PRIMARY) -> QFrame:
        chip = QFrame()
        chip.setStyleSheet("QFrame { background: #0F1929; border: 1px solid #22314C; border-radius: 10px; }")
        layout = QVBoxLayout(chip)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(3)
        title_label = QLabel(title)
        title_label.setStyleSheet(f"color: {TEXT_FAINT}; font-size: 11px;")
        value_label = QLabel(value)
        value_label.setFont(mono_font(15, QFont.DemiBold))
        value_label.setStyleSheet(f"color: {color};")
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        return chip

    def _arrow(self) -> QLabel:
        label = QLabel("→")
        label.setStyleSheet(f"color: {TEXT_FAINT}; font-size: 18px;")
        return label

    def _clear_layout(self, layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    # ------------------------------------------------------------------ #
    def _on_key_changed(self, key32: int) -> None:
        try:
            key1, key2 = split_key_32(key32)
        except ValidationError:
            return
        self.key1_chip.value_label.setText(f"K1 = {format_hex(key1)}")
        self.key2_chip.value_label.setText(f"K2 = {format_hex(key2)}")

    def _on_mode_changed(self, index: int) -> None:
        self._mode = index
        self._clear_layout(self.flow_layout)
        self.result_card.set_placeholder("-")
        self.formula_label.setText("")

    def do_encrypt(self) -> None:
        try:
            plaintext = self.plain_input.value()
            key32 = self.key_input.value()
            key1, key2 = split_key_32(key32)
        except ValidationError as error:
            self.report_error(error)
            return

        steps: list[tuple[str, int, str]] = [("明文 P", plaintext, TEXT_MUTED)]
        if self._mode == 0:
            # 最终结果直接调用算法层函数，中间值单独计算用于可视化展示
            ciphertext = double_encrypt(plaintext, key32)
            steps.append(("E_K1", encrypt_block(plaintext, key1), PRIMARY))
            steps.append(("E_K2", ciphertext, SUCCESS))
        else:
            ciphertext = triple_encrypt(plaintext, key32)
            first = encrypt_block(plaintext, key1)
            steps.append(("E_K1", first, PRIMARY))
            steps.append(("D_K2", decrypt_block(first, key2), ACCENT))
            steps.append(("E_K1", ciphertext, SUCCESS))

        self.cipher_input.set_value(ciphertext)
        self._render_flow(steps)
        self.result_card.set_result(
            format_hex(ciphertext),
            f"密文 · 二进制 {format_binary(ciphertext)}",
            color=SUCCESS,
        )
        self.formula_label.setText(
            "双重加密：C = E_K2(E_K1(P))，解密 P = D_K1(D_K2(C))"
            if self._mode == 0
            else "三重加密（EDE，K3=K1）：C = E_K1(D_K2(E_K1(P)))，解密 P = D_K1(E_K2(D_K1(C)))"
        )
        self.report_success(f"加密完成，密文 {format_hex(ciphertext)}")

    def do_decrypt(self) -> None:
        try:
            ciphertext = self.cipher_input.value()
            key32 = self.key_input.value()
            key1, key2 = split_key_32(key32)
        except ValidationError as error:
            self.report_error(error)
            return

        steps: list[tuple[str, int, str]] = [("密文 C", ciphertext, TEXT_MUTED)]
        if self._mode == 0:
            plaintext = double_decrypt(ciphertext, key32)
            steps.append(("D_K2", decrypt_block(ciphertext, key2), PRIMARY))
            steps.append(("D_K1", plaintext, SUCCESS))
        else:
            plaintext = triple_decrypt(ciphertext, key32)
            first = decrypt_block(ciphertext, key1)
            steps.append(("D_K1", first, PRIMARY))
            steps.append(("E_K2", encrypt_block(first, key2), ACCENT))
            steps.append(("D_K1", plaintext, SUCCESS))

        self.plain_input.set_value(plaintext)
        self._render_flow(steps)
        self.result_card.set_result(
            format_hex(plaintext),
            f"明文 · 二进制 {format_binary(plaintext)}",
            color=PRIMARY,
        )
        self.report_success(f"解密完成，明文 {format_hex(plaintext)}")

    def _render_flow(self, steps: list[tuple[str, int, str]]) -> None:
        self._clear_layout(self.flow_layout)
        for index, (title, value, color) in enumerate(steps):
            if index:
                self.flow_layout.addWidget(self._arrow())
            self.flow_layout.addWidget(self._step_chip(title, format_hex(value), color), 1)
