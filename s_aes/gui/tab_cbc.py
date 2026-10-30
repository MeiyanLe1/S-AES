"""第 5 关：CBC 工作模式与密文篡改对比。"""

from __future__ import annotations

import html
import random

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..core import ValidationError, format_hex, parse_hex_value
from ..modes import blocks_to_bytes, decode_text, decrypt_cbc, encrypt_cbc, tamper_analysis
from .page_base import PageBase
from .theme import DANGER, SUCCESS, TEXT_FAINT, TEXT_MUTED, WARNING, mono_font, rgba
from .widgets import BlockChip, Card, HexInput, CopyButton, muted_label


class CbcTab(PageBase):
    """第 5 关页面。"""

    PAGE_TITLE = "第 5 关 · 密码分组链（CBC）模式"
    PAGE_SUBTITLE = "C_i = E_K(P_i ⊕ C_{i-1})，初始向量 IV 为 16 bit 且必须由通信双方共享"

    def __init__(self, status_callback=None, parent: QWidget | None = None):
        super().__init__(status_callback, parent)
        self._cipher_groups: list[int] = []
        self._original_plain_groups: list[int] = []
        self._selected_index: int | None = None
        self._chips: list[BlockChip] = []
        self._build_iv_card()
        self._build_plain_card()
        self._build_cipher_card()
        self._build_compare_card()
        self.layout.addStretch(1)

    # ------------------------------------------------------------------ #
    # 界面构建
    # ------------------------------------------------------------------ #
    def _build_iv_card(self) -> None:
        card = Card("初始向量 IV", hint="IV 无需保密，但必须与解密方共享；IV 不同则第一组明文无法还原",
                    badge_text="16 bit")
        row = QHBoxLayout()
        row.setSpacing(12)
        self.iv_input = HexInput("IV", 16, random.getrandbits(16), "可点击右侧按钮随机生成")
        row.addWidget(self.iv_input, 3)
        self.random_iv_button = QPushButton("随机生成 IV")
        self.random_iv_button.setProperty("variant", "ghost")
        self.random_iv_button.setCursor(Qt.PointingHandCursor)
        self.random_iv_button.clicked.connect(lambda: self.iv_input.set_value(random.getrandbits(16)))
        row.addWidget(self.random_iv_button, 0, Qt.AlignBottom)
        card.body.addLayout(row)
        self.layout.addWidget(card)

    def _build_plain_card(self) -> None:
        card = Card("明文与密钥", hint="较长明文会按 2 字节分组，末组不足时补填充（0x01 / 0x02 0x02）",
                    badge_text="多分组")
        row = QHBoxLayout()
        row.setSpacing(14)

        left = QVBoxLayout()
        left.setSpacing(8)
        self.plain_edit = QPlainTextEdit()
        self.plain_edit.setPlainText("信息安全导论实验：使用 S-AES 的 CBC 模式加密较长的明文消息。")
        self.plain_edit.setMinimumHeight(112)
        left.addWidget(self.plain_edit)
        self.plain_counter = muted_label("")
        left.addWidget(self.plain_counter)
        self.plain_edit.textChanged.connect(self._update_counter)
        row.addLayout(left, 3)

        right = QVBoxLayout()
        right.setSpacing(8)
        self.key_input = HexInput("密钥 K", 16, 0x2D55, "与解密方共享的 16 bit 密钥")
        right.addWidget(self.key_input)
        encrypt_button = QPushButton("加密并分组展示")
        encrypt_button.setProperty("variant", "primary")
        encrypt_button.setMinimumHeight(38)
        encrypt_button.setCursor(Qt.PointingHandCursor)
        encrypt_button.clicked.connect(self.do_encrypt)
        right.addWidget(encrypt_button)
        right.addStretch(1)
        row.addLayout(right, 2)
        card.body.addLayout(row)
        self.layout.addWidget(card)
        self._update_counter()

    def _build_cipher_card(self) -> None:
        card = Card("密文分组", hint="点击任一分组选中，然后改写它的十六进制值，即可观察解密结果如何被破坏",
                    badge_text="点击可选")
        self.chip_container = QWidget()
        self.chip_container.setObjectName("pageRoot")
        self.chip_grid = QGridLayout(self.chip_container)
        self.chip_grid.setContentsMargins(0, 0, 0, 0)
        self.chip_grid.setSpacing(8)
        card.body.addWidget(self.chip_container)

        self.cipher_summary = muted_label("尚未加密")
        card.body.addWidget(self.cipher_summary)

        tool_row = QHBoxLayout()
        tool_row.setSpacing(8)
        tool_row.addWidget(muted_label("改写为：", 12))
        self.new_value_edit = QLineEdit()
        self.new_value_edit.setFont(mono_font(13))
        self.new_value_edit.setProperty("monospace", "true")
        self.new_value_edit.setPlaceholderText("4 位十六进制，如 1A2B")
        self.new_value_edit.setMaximumWidth(160)
        tool_row.addWidget(self.new_value_edit)

        self.apply_button = QPushButton("应用篡改")
        self.apply_button.setProperty("variant", "danger")
        self.apply_button.setCursor(Qt.PointingHandCursor)
        self.apply_button.clicked.connect(self.do_tamper)
        self.apply_button.setEnabled(False)
        tool_row.addWidget(self.apply_button)

        self.flip_button = QPushButton("随机翻转一位")
        self.flip_button.setProperty("variant", "ghost")
        self.flip_button.setCursor(Qt.PointingHandCursor)
        self.flip_button.clicked.connect(self.do_random_flip)
        self.flip_button.setEnabled(False)
        tool_row.addWidget(self.flip_button)

        self.restore_button = QPushButton("恢复原密文")
        self.restore_button.setProperty("variant", "ghost")
        self.restore_button.setCursor(Qt.PointingHandCursor)
        self.restore_button.clicked.connect(self.do_restore)
        self.restore_button.setEnabled(False)
        tool_row.addWidget(self.restore_button)
        tool_row.addWidget(CopyButton("复制密文", lambda: self._cipher_hex()), 0, Qt.AlignRight)
        tool_row.addStretch(1)
        card.body.addLayout(tool_row)
        self.layout.addWidget(card)

    def _build_compare_card(self) -> None:
        card = Card("篡改前后解密结果对比", badge_text="错误传播")
        compare_row = QHBoxLayout()
        compare_row.setSpacing(14)

        left_box = QVBoxLayout()
        left_box.setSpacing(6)
        left_title = QLabel("原始明文（16 bit 分组，含填充）")
        left_title.setStyleSheet(f"color: {SUCCESS}; font-size: 12px;")
        left_box.addWidget(left_title)
        self.original_label = QLabel("—")
        self.original_label.setFont(mono_font(13))
        self.original_label.setWordWrap(True)
        self.original_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.original_label.setMinimumHeight(72)
        left_box.addWidget(self.original_label)
        compare_row.addLayout(left_box, 1)

        right_box = QVBoxLayout()
        right_box.setSpacing(6)
        right_title = QLabel("篡改后解密结果（红色分组 = 被改动的密文组）")
        right_title.setStyleSheet(f"color: {DANGER}; font-size: 12px;")
        right_box.addWidget(right_title)
        self.tampered_label = QLabel("—")
        self.tampered_label.setFont(mono_font(13))
        self.tampered_label.setWordWrap(True)
        self.tampered_label.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.tampered_label.setMinimumHeight(72)
        right_box.addWidget(self.tampered_label)
        compare_row.addLayout(right_box, 1)
        card.body.addLayout(compare_row)

        self.explain_label = muted_label("加密后点击某个密文分组并篡改，这里会给出错误传播分析。")
        card.body.addWidget(self.explain_label)
        self.layout.addWidget(card)

    # ------------------------------------------------------------------ #
    # 状态与渲染
    # ------------------------------------------------------------------ #
    def _cipher_hex(self) -> str:
        """把全部分组拼成连续十六进制串（复制用）。"""
        return "".join(format_hex(group) for group in self._cipher_groups)

    def _cipher_hex_grouped(self, limit: int = 0) -> str:
        """分组之间用空格分隔，便于长串自动换行显示。"""
        groups = [format_hex(group) for group in self._cipher_groups]
        if limit and len(groups) > limit:
            return " ".join(groups[:limit]) + " …"
        return " ".join(groups)

    def _update_counter(self) -> None:
        raw = self.plain_edit.toPlainText().encode("utf-8")
        padding = 2 - len(raw) % 2 if raw else 0
        groups = (len(raw) + padding) // 2 if raw else 0
        self.plain_counter.setText(f"{len(raw)} 字节 · 填充 {padding} 字节 · {groups} 个分组")

    def _clear_chips(self) -> None:
        for chip in self._chips:
            chip.setParent(None)
            chip.deleteLater()
        self._chips.clear()

    def _render_chips(self, tampered_index: int | None = None) -> None:
        self._clear_chips()
        columns = 6
        for index, value in enumerate(self._cipher_groups):
            chip = BlockChip(index, value)
            chip.clicked.connect(self._on_chip_clicked)
            if tampered_index is not None and index == tampered_index:
                chip.set_state("tampered")
            elif index == self._selected_index:
                chip.set_state("selected")
            self.chip_grid.addWidget(chip, index // columns, index % columns)
            self._chips.append(chip)
        self.cipher_summary.setText(
            f"共 {len(self._cipher_groups)} 组 · 密文 {self._cipher_hex_grouped(limit=24)}"
        )

    def _on_chip_clicked(self, index: int) -> None:
        self._selected_index = index
        self.new_value_edit.setText(format_hex(self._cipher_groups[index]))
        self.apply_button.setEnabled(True)
        self.flip_button.setEnabled(True)
        self._render_selection()

    def _render_selection(self) -> None:
        for index, chip in enumerate(self._chips):
            if index == self._selected_index:
                chip.set_state("selected")
            else:
                chip.set_state("normal")

    # ------------------------------------------------------------------ #
    # 交互
    # ------------------------------------------------------------------ #
    def do_encrypt(self) -> None:
        try:
            key = self.key_input.value()
            iv = self.iv_input.value()
            plaintext = self.plain_edit.toPlainText().encode("utf-8")
            report = encrypt_cbc(plaintext, key, iv)
        except ValidationError as error:
            self.report_error(error)
            return

        self._cipher_groups = list(report["cipher_groups"])
        self._original_plain_groups = list(report["plain_groups"])
        self._selected_index = None
        self.apply_button.setEnabled(False)
        self.flip_button.setEnabled(False)
        self.restore_button.setEnabled(False)
        self._render_chips()

        self.original_label.setText(self._render_groups_html(report["plain_groups"], {}))
        self.tampered_label.setText("—")
        self.explain_label.setStyleSheet(f"color: {TEXT_FAINT}; font-size: 11px;")
        self.explain_label.setText(
            f"IV = {format_hex(iv)}，密钥 = {format_hex(key)}，填充 {report['padding_length']} 字节。"
            "点击任意密文分组可进行篡改。"
        )
        self.report_success(f"CBC 加密完成：{len(self._cipher_groups)} 个分组，密文 {self._cipher_hex()}")

    def do_tamper(self) -> None:
        if self._selected_index is None:
            self.report_error(ValidationError("请先点击选择一个密文分组"))
            return
        try:
            key = self.key_input.value()
            iv = self.iv_input.value()
            new_value = parse_hex_value(self.new_value_edit.text(), 16)
        except ValidationError as error:
            self.report_error(error)
            return
        self._apply_tamper(key, iv, new_value)

    def do_random_flip(self) -> None:
        if self._selected_index is None:
            return
        try:
            key = self.key_input.value()
            iv = self.iv_input.value()
        except ValidationError as error:
            self.report_error(error)
            return
        new_value = self._cipher_groups[self._selected_index] ^ (1 << random.randrange(16))
        self.new_value_edit.setText(format_hex(new_value))
        self._apply_tamper(key, iv, new_value)

    def _apply_tamper(self, key: int, iv: int, new_value: int) -> None:
        assert self._selected_index is not None
        try:
            analysis = tamper_analysis(self._cipher_groups, key, iv, self._selected_index, new_value)
        except ValidationError as error:
            self.report_error(error)
            return

        self._pending_groups = analysis["tampered_groups"]
        self._render_chips(tampered_index=self._selected_index)
        self.original_label.setText(self._render_groups_html(analysis["original_groups_plain"], {}))
        highlight = {self._selected_index: DANGER}
        if self._selected_index + 1 < len(analysis["tampered_groups_plain"]):
            highlight[self._selected_index + 1] = WARNING  # 后一组只有对应比特被翻转
        self.tampered_label.setText(self._render_groups_html(analysis["tampered_groups_plain"], highlight))
        self.explain_label.setStyleSheet(f"color: {WARNING}; font-size: 11px;")
        self.explain_label.setText(analysis["explanation"])

        # 顺便展示「去掉填充」时是否还能得到合法明文
        try:
            recovered = decrypt_cbc(analysis["tampered_groups"], key, iv, strip_padding=True)
        except ValidationError as error:
            self.explain_label.setText(analysis["explanation"] + f"\n· 去填充失败：{error}")
            self.report_error(error)
            return
        if recovered["padding_valid"]:
            self.explain_label.setText(
                analysis["explanation"] + f"\n· 去填充后得到的「明文」：{recovered['plain_bytes'][:40]!r}"
            )
        else:
            self.explain_label.setText(
                analysis["explanation"] + f"\n· 填充校验失败：{recovered['padding_error']}"
            )
        self.restore_button.setEnabled(True)
        self.report_success(
            f"已篡改第 {self._selected_index + 1} 组，受影响字节位置：{analysis['diff_positions']}"
        )

    def do_restore(self) -> None:
        try:
            key = self.key_input.value()
            iv = self.iv_input.value()
        except ValidationError as error:
            self.report_error(error)
            return
        self._render_chips()
        self.original_label.setText(self._render_groups_html(self._original_plain_groups, {}))
        self.tampered_label.setText("—")
        self.explain_label.setStyleSheet(f"color: {TEXT_FAINT}; font-size: 11px;")
        self.explain_label.setText("已恢复篡改前的密文分组，重新解密与原始明文完全一致。")
        self.status("已恢复原始密文")

    # ------------------------------------------------------------------ #
    def _render_groups_html(self, plain_groups: list[int], highlights: dict[int, str]) -> str:
        """按 16 bit 分组渲染解密结果，被篡改影响的组用红/黄底色标出。

        组内十六进制与 UTF-8 解码后的文本同时展示：十六进制便于定位出错比特，
        解码文本便于直观看出「明文变成乱码」。
        """
        if not plain_groups:
            return "—"
        pieces: list[str] = []
        for index, block in enumerate(plain_groups):
            color = highlights.get(index, TEXT_MUTED)
            background = rgba(color, 0.22) if index in highlights else "transparent"
            pieces.append(
                f'<span style="color:{color}; background-color:{background}; '
                f'padding:1px 2px;">{format_hex(block)}</span>'
            )
        decoded = html.escape(decode_text(blocks_to_bytes(plain_groups)))
        return (
            f'<div style="line-height:21px;">{" ".join(pieces)}</div>'
            f'<div style="color:{TEXT_FAINT}; font-size:11px; margin-top:5px;">'
            f"UTF-8 解码：{decoded}</div>"
        )
