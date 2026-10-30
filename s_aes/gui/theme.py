"""深色主题：配色常量、字体与全局 QSS 样式表。

界面采用「密码学实验工作站」风格：深蓝黑底 + 青色高光 + 卡片化布局，
十六进制数据统一使用等宽字体，便于逐位比对。
"""

from __future__ import annotations

from PyQt5.QtGui import QFont, QFontDatabase

# --------------------------------------------------------------------------- #
# 配色
# --------------------------------------------------------------------------- #
BACKGROUND = "#0B1220"
SURFACE = "#111A2B"
SURFACE_ALT = "#16233A"
BORDER = "#22314C"
PRIMARY = "#22D3EE"
ACCENT = "#6366F1"
TEAL = "#0EA5B7"
TEXT = "#E8EEF9"
TEXT_MUTED = "#93A4BE"
TEXT_FAINT = "#5F7690"
SUCCESS = "#34D399"
DANGER = "#F87171"
WARNING = "#FBBF24"
INFO = "#60A5FA"

#: 中文界面字体候选，逐级回退
UI_FONT_FAMILIES = ("Microsoft YaHei UI", "Microsoft YaHei", "Source Han Sans SC", "PingFang SC")
#: 等宽字体候选，用于密文与中间状态
MONO_FONT_FAMILIES = ("Cascadia Mono", "Consolas", "JetBrains Mono", "Courier New")


def _first_available(candidates: tuple[str, ...], fallback: str) -> str:
    """在候选字体中挑选本机已安装的第一个，避免界面字体缺失。"""
    installed = set(QFontDatabase().families())
    for family in candidates:
        if family in installed:
            return family
    return fallback


def rgba(color: str, alpha: float) -> str:
    """把 ``#RRGGBB`` 转成 ``rgba(r, g, b, a)``。

    Qt 会把 8 位十六进制（如 ``#22D3EE18``）解析成 ``#AARRGGBB``，
    直接拼透明度会得到完全不同的颜色，因此统一用 rgba() 表达半透明。
    """
    color = color.lstrip("#")
    red, green, blue = (int(color[index:index + 2], 16) for index in (0, 2, 4))
    return f"rgba({red}, {green}, {blue}, {alpha:.2f})"


def ui_font(size: int = 13, weight: int = QFont.Normal) -> QFont:
    """生成中文界面字体。"""
    return QFont(_first_available(UI_FONT_FAMILIES, "Sans Serif"), size, weight)


def mono_font(size: int = 13, weight: int = QFont.Normal) -> QFont:
    """生成等宽字体，用于十六进制与二进制数据展示。"""
    font = QFont(_first_available(MONO_FONT_FAMILIES, "Monospace"), size, weight)
    font.setStyleHint(QFont.Monospace)
    return font


# --------------------------------------------------------------------------- #
# QSS 样式表
# --------------------------------------------------------------------------- #
STYLESHEET = f"""
QWidget {{
    color: {TEXT};
    font-size: 13px;
}}
QMainWindow, QDialog {{
    background: {BACKGROUND};
}}
#navPanel {{
    background: {SURFACE};
    border-right: 1px solid {BORDER};
}}
#brandTitle {{
    font-size: 17px;
    font-weight: 600;
    color: {TEXT};
    letter-spacing: 1px;
}}
#brandSubtitle {{
    color: {TEXT_FAINT};
    font-size: 11px;
    letter-spacing: 0.5px;
}}
#navList {{
    background: transparent;
    border: none;
    outline: none;
}}
#navList::item {{
    padding: 11px 12px;
    margin: 3px 6px;
    border-radius: 9px;
    color: {TEXT_MUTED};
    border-left: 3px solid transparent;
}}
#navList::item:hover {{
    background: rgba(34, 211, 238, 0.08);
    color: {TEXT};
}}
#navList::item:selected {{
    background: rgba(34, 211, 238, 0.14);
    color: {PRIMARY};
    border-left: 3px solid {PRIMARY};
    font-weight: 600;
}}
#headerBar {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba(34,211,238,0.14), stop:0.55 rgba(99,102,241,0.10), stop:1 rgba(11,18,32,0));
    border-bottom: 1px solid {BORDER};
}}
#pageTitle {{
    font-size: 22px;
    font-weight: 600;
}}
#pageSubtitle {{
    color: {TEXT_MUTED};
    font-size: 12px;
}}
#card, #metricTile {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 12px;
}}
#cardTitle {{
    font-size: 14px;
    font-weight: 600;
    color: {TEXT};
}}
#cardHint {{
    color: {TEXT_FAINT};
    font-size: 11px;
}}
#badge {{
    color: {PRIMARY};
    background: rgba(34, 211, 238, 0.12);
    border: 1px solid rgba(34, 211, 238, 0.35);
    border-radius: 8px;
    padding: 1px 8px;
    font-size: 11px;
}}
#metricLabel {{
    color: {TEXT_FAINT};
    font-size: 11px;
    letter-spacing: 0.5px;
}}
#metricValue {{
    color: {PRIMARY};
    font-size: 18px;
    font-weight: 600;
}}
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {{
    background: {SURFACE_ALT};
    border: 1px solid {BORDER};
    border-radius: 9px;
    padding: 7px 10px;
    selection-background-color: {TEAL};
    selection-color: #04121B;
}}
QLineEdit:hover, QTextEdit:hover, QPlainTextEdit:hover, QComboBox:hover {{
    border: 1px solid {TEAL};
}}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{
    border: 1px solid {PRIMARY};
}}
QLineEdit[monospace="true"], QTextEdit[monospace="true"], QPlainTextEdit[monospace="true"] {{
    font-family: "Cascadia Mono", "Consolas", monospace;
    letter-spacing: 1px;
}}
QLineEdit[invalid="true"] {{
    border: 1px solid {DANGER};
}}
QComboBox QAbstractItemView {{
    background: {SURFACE_ALT};
    border: 1px solid {BORDER};
    selection-background-color: rgba(34, 211, 238, 0.2);
    outline: none;
}}
QPushButton {{
    background: {SURFACE_ALT};
    border: 1px solid {BORDER};
    border-radius: 9px;
    padding: 8px 16px;
    color: {TEXT};
}}
QPushButton:hover {{
    border: 1px solid {TEAL};
    background: #1B2B45;
}}
QPushButton:pressed {{
    background: #14203A;
}}
QPushButton:disabled {{
    color: {TEXT_FAINT};
    border-color: #1B2740;
}}
QPushButton[variant="primary"] {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                stop:0 {PRIMARY}, stop:1 {TEAL});
    color: #04121B;
    border: none;
    font-weight: 600;
}}
QPushButton[variant="primary"]:hover {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                stop:0 #67E8F9, stop:1 #22D3EE);
}}
QPushButton[variant="accent"] {{
    background: rgba(99, 102, 241, 0.22);
    border: 1px solid {ACCENT};
    color: #C7D2FE;
}}
QPushButton[variant="accent"]:hover {{
    background: rgba(99, 102, 241, 0.34);
}}
QPushButton[variant="ghost"] {{
    background: transparent;
    border: 1px solid {BORDER};
    color: {TEXT_MUTED};
    padding: 6px 10px;
}}
QPushButton[variant="ghost"]:hover {{
    color: {PRIMARY};
    border: 1px solid {PRIMARY};
}}
QPushButton[variant="danger"] {{
    background: rgba(248, 113, 113, 0.16);
    border: 1px solid {DANGER};
    color: #FCA5A5;
}}
QPushButton[variant="danger"]:hover {{
    background: rgba(248, 113, 113, 0.28);
}}
QTableWidget, QTableView {{
    background: {SURFACE};
    alternate-background-color: #0F1929;
    border: 1px solid {BORDER};
    border-radius: 10px;
    gridline-color: #1B2740;
    selection-background-color: rgba(34, 211, 238, 0.18);
    selection-color: {TEXT};
}}
QHeaderView::section {{
    background: {SURFACE_ALT};
    color: {TEXT_MUTED};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 6px 8px;
    font-size: 12px;
}}
QTableCornerButton::section {{
    background: {SURFACE_ALT};
    border: none;
}}
QScrollArea {{
    border: none;
    background: transparent;
}}
QScrollArea > QWidget > QWidget {{
    background: transparent;
}}
QStackedWidget {{
    background: {BACKGROUND};
}}
#pageRoot {{
    background: transparent;
}}
QScrollBar:vertical {{
    background: transparent;
    width: 10px;
    margin: 4px 2px;
}}
QScrollBar::handle:vertical {{
    background: #24344F;
    border-radius: 5px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {TEAL};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: transparent;
    height: 10px;
    margin: 2px 4px;
}}
QScrollBar::handle:horizontal {{
    background: #24344F;
    border-radius: 5px;
    min-width: 30px;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}
QProgressBar {{
    background: {SURFACE_ALT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    height: 10px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 {TEAL}, stop:0.6 {PRIMARY}, stop:1 {ACCENT});
    border-radius: 5px;
}}
QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 10px;
    background: {SURFACE};
    top: -1px;
}}
QTabBar::tab {{
    background: transparent;
    color: {TEXT_MUTED};
    padding: 7px 16px;
    margin-right: 4px;
    border: 1px solid transparent;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}}
QTabBar::tab:selected {{
    color: {PRIMARY};
    background: rgba(34, 211, 238, 0.1);
    border: 1px solid rgba(34, 211, 238, 0.3);
    border-bottom: 1px solid {SURFACE};
}}
QTabBar::tab:hover {{
    color: {TEXT};
}}
QStatusBar {{
    background: {SURFACE};
    border-top: 1px solid {BORDER};
    color: {TEXT_MUTED};
}}
QStatusBar::item {{
    border: none;
}}
QToolTip {{
    background: {SURFACE_ALT};
    color: {TEXT};
    border: 1px solid {PRIMARY};
    padding: 4px 8px;
    border-radius: 6px;
}}
QListWidget#pairList {{
    background: {SURFACE_ALT};
    border: 1px solid {BORDER};
    border-radius: 9px;
}}
QCheckBox {{
    color: {TEXT_MUTED};
    spacing: 7px;
}}
QCheckBox::indicator {{
    width: 15px;
    height: 15px;
    border-radius: 4px;
    border: 1px solid {BORDER};
    background: {SURFACE_ALT};
}}
QCheckBox::indicator:checked {{
    background: {PRIMARY};
    border: 1px solid {PRIMARY};
}}
QSplitter::handle {{
    background: {BORDER};
}}
"""


def apply_theme(application) -> None:
    """把主题应用到 QApplication（字体 + 样式表）。"""
    application.setStyleSheet(STYLESHEET)
    application.setFont(ui_font())
