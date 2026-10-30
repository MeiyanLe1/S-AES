"""可复用的界面控件：卡片、十六进制输入、位点阵、结果卡、分组色块等。

这些控件只负责「采集与展示」，不包含任何算法逻辑，保证关注点分离。
"""

from __future__ import annotations

from typing import Callable

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QGuiApplication
from PyQt5.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..core import ValidationError, format_binary, format_hex, parse_flexible
from .theme import DANGER, PRIMARY, SUCCESS, TEXT_FAINT, TEXT_MUTED, mono_font, rgba

__all__ = [
    "Card",
    "HexInput",
    "BitGrid",
    "ResultCard",
    "MetricTile",
    "BlockChip",
    "SegmentedControl",
    "CopyButton",
    "badge",
    "muted_label",
    "mono_label",
    "h_line",
]


# --------------------------------------------------------------------------- #
# 基础标签与卡片
# --------------------------------------------------------------------------- #


def badge(text: str, color: str = PRIMARY) -> QLabel:
    """小号徽标，用于标注位宽、步数等元信息。"""
    label = QLabel(text)
    label.setObjectName("badge")
    label.setStyleSheet(
        f"color: {color}; border: 1px solid {rgba(color, 0.4)}; background: {rgba(color, 0.12)};"
        "border-radius: 8px; padding: 1px 8px; font-size: 11px;"
    )
    return label


def muted_label(text: str, size: int = 11) -> QLabel:
    """灰色提示文字。"""
    label = QLabel(text)
    label.setStyleSheet(f"color: {TEXT_FAINT}; font-size: {size}px;")
    label.setWordWrap(True)
    return label


def mono_label(text: str = "", size: int = 13, color: str = "#E8EEF9") -> QLabel:
    """等宽数值标签，用于展示十六进制 / 二进制串。"""
    label = QLabel(text)
    label.setFont(mono_font(size))
    label.setStyleSheet(f"color: {color};")
    label.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return label


def h_line() -> QFrame:
    """1px 分隔线。"""
    line = QFrame()
    line.setFixedHeight(1)
    line.setStyleSheet("background: #22314C; border: none;")
    return line


class Card(QFrame):
    """带标题的圆角卡片容器，内容放进 ``body`` 布局。"""

    def __init__(self, title: str = "", hint: str = "", badge_text: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("card")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(16, 14, 16, 16)
        outer.setSpacing(10)

        if title:
            header = QHBoxLayout()
            header.setSpacing(8)
            title_label = QLabel(title)
            title_label.setObjectName("cardTitle")
            header.addWidget(title_label)
            if badge_text:
                header.addWidget(badge(badge_text))
            header.addStretch(1)
            self.header_layout = header
            outer.addLayout(header)
        else:
            self.header_layout = QHBoxLayout()
        if hint:
            hint_label = QLabel(hint)
            hint_label.setObjectName("cardHint")
            hint_label.setWordWrap(True)
            outer.addWidget(hint_label)

        self.body = QVBoxLayout()
        self.body.setSpacing(10)
        outer.addLayout(self.body)


# --------------------------------------------------------------------------- #
# 输入控件
# --------------------------------------------------------------------------- #


class HexInput(QWidget):
    """十六进制 / 二进制输入框，支持即时校验与位宽提示。"""

    valueChanged = pyqtSignal(int)

    def __init__(
        self,
        title: str,
        bit_width: int = 16,
        default_value: int = 0,
        hint: str = "",
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._bit_width = bit_width
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        if title:
            header = QHBoxLayout()
            header.setSpacing(8)
            label = QLabel(title)
            label.setStyleSheet("font-weight: 600;")
            header.addWidget(label)
            header.addWidget(badge(f"{bit_width} bit"))
            header.addStretch(1)
            layout.addLayout(header)

        self.edit = QLineEdit()
        self.edit.setFont(mono_font(14))
        self.edit.setProperty("monospace", "true")
        self.edit.setPlaceholderText(f"{bit_width // 4} 位十六进制，也可直接输入 {bit_width} 位二进制")
        self.edit.textChanged.connect(self._on_text_changed)
        layout.addWidget(self.edit)

        self.hint_label = QLabel(hint)
        self.hint_label.setStyleSheet(f"color: {TEXT_FAINT}; font-size: 11px;")
        layout.addWidget(self.hint_label)

        self.set_value(default_value)

    # --- 数据接口 ------------------------------------------------------- #
    def value(self, require_full_width: bool = True) -> int:
        """解析当前输入，失败时抛出 ValidationError。"""
        return parse_flexible(self.edit.text(), self._bit_width, require_full_width=require_full_width)

    def set_value(self, value: int) -> None:
        self.edit.setText(format_hex(value, self._bit_width))

    def clear(self) -> None:
        self.edit.clear()

    # --- 内部逻辑 ------------------------------------------------------- #
    def _on_text_changed(self, text: str) -> None:
        if not text.strip():
            self._set_invalid(False, "")
            return
        try:
            value = parse_flexible(text, self._bit_width, require_full_width=False)
        except ValidationError as error:
            self._set_invalid(True, str(error))
            return
        self._set_invalid(False, f"二进制：{format_binary(value, self._bit_width)}")
        self.valueChanged.emit(value)

    def _set_invalid(self, invalid: bool, message: str) -> None:
        self.edit.setProperty("invalid", "true" if invalid else "false")
        self.edit.style().unpolish(self.edit)
        self.edit.style().polish(self.edit)
        color = DANGER if invalid else TEXT_FAINT
        self.hint_label.setText(message)
        self.hint_label.setStyleSheet(f"color: {color}; font-size: 11px;")


class BitGrid(QWidget):
    """16 格位点阵，点击即可翻转对应二进制位，与输入框双向同步。"""

    valueChanged = pyqtSignal(int)

    def __init__(self, bit_width: int = 16, parent: QWidget | None = None):
        super().__init__(parent)
        self._bit_width = bit_width
        self._value = 0
        self._cells: list[QLabel] = []

        grid = QGridLayout(self)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(5)
        per_row = 8
        for index in range(bit_width):
            cell = QLabel("0")
            cell.setFixedSize(26, 26)
            cell.setAlignment(Qt.AlignCenter)
            cell.setFont(mono_font(12))
            cell.setCursor(Qt.PointingHandCursor)
            cell.mousePressEvent = lambda event, i=index: self._toggle(i)  # type: ignore[assignment]
            self._cells.append(cell)
            grid.addWidget(cell, index // per_row, index % per_row)
        self.set_value(0)

    def value(self) -> int:
        return self._value

    def set_value(self, value: int) -> None:
        self._value = value & ((1 << self._bit_width) - 1)
        self._refresh()

    def _toggle(self, index: int) -> None:
        shift = self._bit_width - 1 - index
        self._value ^= 1 << shift
        self._refresh()
        self.valueChanged.emit(self._value)

    def _refresh(self) -> None:
        for index, cell in enumerate(self._cells):
            bit = (self._value >> (self._bit_width - 1 - index)) & 1
            cell.setText(str(bit))
            if bit:
                cell.setStyleSheet(
                    f"background: {rgba(PRIMARY, 0.14)}; border: 1px solid {PRIMARY}; "
                    f"border-radius: 6px; color: {PRIMARY};"
                )
            else:
                cell.setStyleSheet("background: #0F1929; border: 1px solid #22314C; border-radius: 6px; color: #5F7690;")


class SegmentedControl(QWidget):
    """分段切换控件（如十六进制 / 字符视图）。"""

    changed = pyqtSignal(int)

    def __init__(self, options: list[str], parent: QWidget | None = None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        self._buttons: list[QPushButton] = []
        for index, option in enumerate(options):
            button = QPushButton(option)
            button.setCheckable(True)
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(lambda checked=False, i=index: self.set_current(i))
            layout.addWidget(button)
            self._buttons.append(button)
        layout.addStretch(1)
        self._current = 0
        self._paint()

    def current(self) -> int:
        return self._current

    def set_current(self, index: int) -> None:
        if index == self._current:
            self._paint()
            return
        self._current = index
        self._paint()
        self.changed.emit(index)

    def _paint(self) -> None:
        for index, button in enumerate(self._buttons):
            active = index == self._current
            button.setStyleSheet(
                "QPushButton { border-radius: 8px; padding: 6px 14px; font-size: 12px; "
                + ("background: rgba(34,211,238,0.16); border: 1px solid #22D3EE; color: #22D3EE;" if active
                   else "background: transparent; border: 1px solid #22314C; color: #93A4BE;")
                + "}"
            )


class CopyButton(QPushButton):
    """复制按钮：点击后短暂变绿提示「已复制」。"""

    def __init__(self, text: str = "复制", payload_getter: Callable[[], str] | None = None,
                 parent: QWidget | None = None):
        super().__init__(text, parent)
        self._payload_getter = payload_getter or (lambda: "")
        self.setProperty("variant", "ghost")
        self.setCursor(Qt.PointingHandCursor)
        self.clicked.connect(self._copy)

    def set_payload_getter(self, getter: Callable[[], str]) -> None:
        self._payload_getter = getter

    def _copy(self) -> None:
        payload = self._payload_getter()
        if not payload:
            return
        QGuiApplication.clipboard().setText(payload)
        self.setText("已复制 ✓")
        self.setStyleSheet(f"color: {SUCCESS}; border: 1px solid {SUCCESS}; border-radius: 8px; padding: 6px 10px;")
        QTimer.singleShot(1200, self._restore)

    def _restore(self) -> None:
        self.setText("复制")
        self.setStyleSheet("")


class MetricTile(QFrame):
    """指标小卡：上方灰色标题、下方青色数值。"""

    def __init__(self, title: str, value: str = "-", parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("metricTile")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 12)
        layout.setSpacing(2)
        label = QLabel(title)
        label.setObjectName("metricLabel")
        self._value_label = QLabel(value)
        self._value_label.setObjectName("metricValue")
        self._value_label.setFont(mono_font(17, QFont.DemiBold))
        layout.addWidget(label)
        layout.addWidget(self._value_label)

    def set_value(self, value: str, color: str | None = None) -> None:
        self._value_label.setText(value)
        self._value_label.setStyleSheet(f"color: {color};" if color else "")


class ResultCard(Card):
    """结果展示卡：大号等宽结果 + 副标题 + 复制按钮。"""

    def __init__(self, title: str = "结果", parent: QWidget | None = None):
        super().__init__(title, parent=parent)
        self._primary = QLabel("-")
        self._primary.setFont(mono_font(26, QFont.Bold))
        self._primary.setStyleSheet(f"color: {PRIMARY};")
        self._primary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._primary.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.body.addWidget(self._primary)

        self._secondary = QLabel("")
        self._secondary.setFont(mono_font(12))
        self._secondary.setStyleSheet(f"color: {TEXT_MUTED};")
        self._secondary.setWordWrap(True)
        self.body.addWidget(self._secondary)

        self.copy_button = CopyButton("复制结果", lambda: self._primary.text())
        self.header_layout.addWidget(self.copy_button)

    def set_result(self, primary: str, secondary: str = "", color: str = PRIMARY) -> None:
        self._primary.setText(primary)
        self._primary.setStyleSheet(f"color: {color};")
        self._secondary.setText(secondary)

    def set_placeholder(self, text: str = "-") -> None:
        self.set_result(text, "")


class BlockChip(QFrame):
    """CBC 密文分组色块，可选中、可标记为被篡改。"""

    clicked = pyqtSignal(int)

    def __init__(self, index: int, value: int, parent: QWidget | None = None):
        super().__init__(parent)
        self.index = index
        self._value = value
        self._state = "normal"
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(58)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(1)
        self._title = QLabel(f"组 {index + 1}")
        self._title.setStyleSheet(f"color: {TEXT_FAINT}; font-size: 10px;")
        self._value_label = QLabel(format_hex(value))
        self._value_label.setFont(mono_font(14, QFont.DemiBold))
        layout.addWidget(self._title)
        layout.addWidget(self._value_label)
        self._paint()

    def value(self) -> int:
        return self._value

    def set_value(self, value: int) -> None:
        self._value = value
        self._value_label.setText(format_hex(value))

    def set_state(self, state: str) -> None:
        """state: normal / selected / tampered。"""
        self._state = state
        self._paint()

    def mousePressEvent(self, event) -> None:  # noqa: N802 (Qt 命名)
        self.clicked.emit(self.index)

    def _paint(self) -> None:
        styles = {
            "normal": ("background: #0F1929; border: 1px solid #22314C; border-radius: 10px;", TEXT_MUTED),
            "selected": ("background: rgba(34,211,238,0.12); border: 1px solid #22D3EE; border-radius: 10px;", PRIMARY),
            "tampered": ("background: rgba(248,113,113,0.12); border: 1px solid #F87171; border-radius: 10px;", DANGER),
        }
        style, color = styles.get(self._state, styles["normal"])
        self.setStyleSheet(f"QFrame {{ {style} }}")
        self._value_label.setStyleSheet(f"color: {color};")
