"""第 3 关：扩展功能——ASCII / UTF-8 字符串加解密（按 2 字节分组）。"""

from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core import ValidationError, format_binary, format_hex
from ..modes import BLOCK_SIZE, decrypt_ascii, encrypt_ascii, pad
from .page_base import PageBase
from .theme import DANGER, SUCCESS, mono_font
from .widgets import Card, HexInput, SegmentedControl, muted_label


def _hex_text_to_bytes(text: str) -> bytes:
    """把界面上粘贴的十六进制串转成字节串，忽略空白与常见分隔符。"""
    cleaned = "".join(ch for ch in text if ch not in " \t\r\n:-_")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        raise ValidationError("请输入十六进制密文")
    if len(cleaned) % 2 != 0:
        raise ValidationError("十六进制字符个数必须为偶数")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as error:
        raise ValidationError("存在非法的十六进制字符") from error


class AsciiTab(PageBase):
    """第 3 关页面。"""

    PAGE_TITLE = "第 3 关 · 字符串加解密"
    PAGE_SUBTITLE = "明文按 2 字节分组（16 bit），末组不足用 PKCS#7 变体填充，密文通常为乱码"

    def __init__(self, status_callback=None, parent: QWidget | None = None):
        super().__init__(status_callback, parent)
        self._build_key_card()
        self._build_text_row()
        self._build_group_card()
        self.layout.addStretch(1)

    # ------------------------------------------------------------------ #
    def _build_key_card(self) -> None:
        card = Card("密钥与填充规则",
                    hint="缺 1 字节补 0x01、缺 2 字节补一整组 0x02 0x02；解密时按末尾字节去填充，"
                         "若填充不合法说明密文被改过。",
                    badge_text="16 bit")
        row = QHBoxLayout()
        row.setSpacing(16)
        self.key_input = HexInput("密钥 K", 16, 0x2D55, "附录 D 示例密钥：2D55")
        row.addWidget(self.key_input, 2)

        info_box = QVBoxLayout()
        info_box.setSpacing(4)
        info_box.addWidget(muted_label("分组长度"))
        info_box.addWidget(QLabel(f"{BLOCK_SIZE} 字节 = 16 bit"))
        info_box.addStretch(1)
        row.addLayout(info_box, 1)
        card.body.addLayout(row)
        self.layout.addWidget(card)

    def _build_text_row(self) -> None:
        row = QHBoxLayout()
        row.setSpacing(14)

        plain_card = Card("明文（UTF-8 / ASCII 字符串）", badge_text="可多行")
        self.plain_edit = QPlainTextEdit()
        self.plain_edit.setPlaceholderText("例如：信息安全导论 S-AES 实验")
        self.plain_edit.setMinimumHeight(96)
        self.plain_edit.textChanged.connect(self._update_plain_counter)
        plain_card.body.addWidget(self.plain_edit)
        self.plain_counter = muted_label("0 字节 · 填充后 2 字节 · 1 个分组")
        plain_card.body.addWidget(self.plain_counter)
        encrypt_button = QPushButton("加密 →")
        encrypt_button.setProperty("variant", "primary")
        encrypt_button.setMinimumHeight(38)
        encrypt_button.setCursor(Qt.PointingHandCursor)
        encrypt_button.clicked.connect(self.do_encrypt)
        plain_card.body.addWidget(encrypt_button)
        row.addWidget(plain_card, 1)

        cipher_card = Card("密文 / 解密结果", badge_text="十六进制可编辑")
        self.cipher_edit = QPlainTextEdit()
        self.cipher_edit.setFont(mono_font(13))
        self.cipher_edit.setProperty("monospace", "true")
        self.cipher_edit.setPlaceholderText("加密后在此显示十六进制密文；也可粘贴密文后点解密")
        self.cipher_edit.setMinimumHeight(96)
        cipher_card.body.addWidget(self.cipher_edit)
        self.view_control = SegmentedControl(["十六进制", "字符视图"])
        self.view_control.changed.connect(self._on_view_changed)
        cipher_card.body.addWidget(self.view_control)
        self.decrypt_button = QPushButton("← 解密")
        self.decrypt_button.setProperty("variant", "accent")
        self.decrypt_button.setMinimumHeight(38)
        self.decrypt_button.setCursor(Qt.PointingHandCursor)
        self.decrypt_button.clicked.connect(self.do_decrypt)
        cipher_card.body.addWidget(self.decrypt_button)
        row.addWidget(cipher_card, 1)

        self.layout.addLayout(row)

    def _build_group_card(self) -> None:
        card = Card("分组明细", hint="每一行的 16 bit 明文分组对应一个 16 bit 密文分组（ECB 方式逐组加密）",
                    badge_text="2 字节 / 组")
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["组号", "明文 (hex)", "密文 (hex)", "明文 (binary)"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setMinimumHeight(150)
        card.body.addWidget(self.table)
        self.padding_label = muted_label("")
        card.body.addWidget(self.padding_label)
        self.layout.addWidget(card)

    # ------------------------------------------------------------------ #
    def _update_plain_counter(self) -> None:
        raw = self.plain_edit.toPlainText().encode("utf-8")
        padded = pad(raw) if raw else b""
        groups = len(padded) // BLOCK_SIZE
        self.plain_counter.setText(
            f"{len(raw)} 字节 · 填充后 {len(padded)} 字节 · {groups} 个分组"
        )

    def _on_view_changed(self, index: int) -> None:
        text = self.cipher_edit.toPlainText()
        if not text.strip():
            return
        try:
            data = _hex_text_to_bytes(text)
        except ValidationError:
            return
        if index == 0:
            self.cipher_edit.setPlainText(data.hex().upper())
        else:
            self.cipher_edit.setPlainText("".join(chr(b) if 32 <= b <= 126 else "·" for b in data))

    def do_encrypt(self) -> None:
        try:
            key = self.key_input.value()
            report = encrypt_ascii(self.plain_edit.toPlainText(), key)
        except ValidationError as error:
            self.report_error(error)
            return
        self.view_control.set_current(0)
        self.cipher_edit.setPlainText(report["cipher_hex"])
        self._fill_table(report["groups"], "plain_block", "cipher_block")
        self.padding_label.setText(
            f"已填充 {report['padding_length']} 字节（末尾 "
            f"{' '.join(f'{b:02X}' for b in report['padded'][-report['padding_length']:])}）；"
            f"字符视图：{report['cipher_display']}"
        )
        self.report_success(f"字符串加密完成：{len(report['groups'])} 个分组，密文 {report['cipher_hex']}")

    def do_decrypt(self) -> None:
        try:
            key = self.key_input.value()
            data = _hex_text_to_bytes(self.cipher_edit.toPlainText())
            report = decrypt_ascii(data, key)
        except ValidationError as error:
            self.report_error(error)
            return
        self._fill_table(report["groups"], "plain_block", "cipher_block")
        if report["padding_valid"]:
            self.plain_edit.setPlainText(report["text"])
            self.padding_label.setStyleSheet(f"color: {SUCCESS}; font-size: 11px;")
            self.padding_label.setText("填充校验通过，明文已还原")
            self.report_success("字符串解密完成，填充校验通过")
        else:
            self.plain_edit.setPlainText(report["text"])
            self.padding_label.setStyleSheet(f"color: {DANGER}; font-size: 11px;")
            self.padding_label.setText(f"填充校验失败：{report['padding_error']}（下方明文可能只是乱码）")
            self.report_error(ValidationError(f"填充校验失败：{report['padding_error']}"))

    def _fill_table(self, groups: list[dict], first_key: str, second_key: str) -> None:
        self.table.setRowCount(len(groups))
        for row, group in enumerate(groups):
            self.table.setItem(row, 0, QTableWidgetItem(str(group["index"] + 1)))
            self.table.setItem(row, 1, QTableWidgetItem(format_hex(int(group[first_key]))))
            self.table.setItem(row, 2, QTableWidgetItem(format_hex(int(group[second_key]))))
            self.table.setItem(row, 3, QTableWidgetItem(format_binary(int(group[first_key]))))
