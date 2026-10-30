"""主窗口：左侧关卡导航 + 顶部标题栏 + 分页内容区。"""

from __future__ import annotations

from PyQt5.QtCore import QEasingCurve, QPropertyAnimation, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import (
    QApplication,
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from ..selftest import run_self_check
from .tab_ascii import AsciiTab
from .tab_basic import BasicTab
from .tab_cbc import CbcTab
from .tab_mitm import MitmTab
from .tab_multi import MultiTab
from .theme import BORDER, PRIMARY, TEXT_FAINT, mono_font


class MainWindow(QMainWindow):
    """实验程序主窗口。"""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("S-AES 加解密实验程序 · 信息安全导论")
        self.resize(1180, 780)
        self.setMinimumSize(980, 660)

        self._pages: list[QWidget] = []
        self._animation: QPropertyAnimation | None = None

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_nav_panel())
        root.addWidget(self._build_content_area(), 1)
        self.setCentralWidget(central)

        self.statusBar().showMessage("就绪：S-AES 分组 16 bit，密钥 16 bit（多重加密 32 bit）")
        self.nav_list.setCurrentRow(0)

    # ------------------------------------------------------------------ #
    # 界面骨架
    # ------------------------------------------------------------------ #
    def _build_nav_panel(self) -> QWidget:
        panel = QWidget()
        panel.setObjectName("navPanel")
        panel.setFixedWidth(248)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 20, 0, 16)
        layout.setSpacing(6)

        brand_box = QVBoxLayout()
        brand_box.setContentsMargins(20, 0, 20, 12)
        brand_box.setSpacing(2)
        title = QLabel("S-AES")
        title.setObjectName("brandTitle")
        title.setFont(QFont(title.font().family(), 20, QFont.Bold))
        subtitle = QLabel("信息安全导论 · 简化 AES 实验")
        subtitle.setObjectName("brandSubtitle")
        brand_box.addWidget(title)
        brand_box.addWidget(subtitle)
        layout.addLayout(brand_box)

        self.nav_list = QListWidget()
        self.nav_list.setObjectName("navList")
        self.nav_list.setCursor(Qt.PointingHandCursor)
        self.nav_list.setFrameShape(QFrame.NoFrame)
        for text in (
            "①  基本加解密",
            "②  字符串加密 · 第 3 关",
            "③  多重加密 · 第 4 关",
            "④  中间相遇攻击",
            "⑤  密码分组链 CBC",
        ):
            self.nav_list.addItem(text)
        self.nav_list.currentRowChanged.connect(self._on_nav_changed)
        layout.addWidget(self.nav_list, 1)

        footer = QLabel("分组 16 bit\n密钥 16 / 32 bit\n2 轮 · S 盒 4×4")
        footer.setStyleSheet(f"color: {TEXT_FAINT}; font-size: 11px; padding: 8px 20px;")
        layout.addWidget(footer)
        return panel

    def _build_content_area(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setObjectName("headerBar")
        header.setFixedHeight(74)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(22, 12, 22, 12)
        header_layout.setSpacing(16)

        text_box = QVBoxLayout()
        text_box.setSpacing(2)
        self.page_title = QLabel("")
        self.page_title.setObjectName("pageTitle")
        self.page_subtitle = QLabel("")
        self.page_subtitle.setObjectName("pageSubtitle")
        text_box.addWidget(self.page_title)
        text_box.addWidget(self.page_subtitle)
        header_layout.addLayout(text_box, 1)

        param_label = QLabel("P/C 16 bit · K 16 bit")
        param_label.setFont(mono_font(12))
        param_label.setStyleSheet(
            f"color: {PRIMARY}; border: 1px solid {BORDER}; border-radius: 10px; padding: 4px 10px;"
        )
        header_layout.addWidget(param_label)

        self_check_button = QPushButton("算法自测")
        self_check_button.setProperty("variant", "ghost")
        self_check_button.setCursor(Qt.PointingHandCursor)
        self_check_button.clicked.connect(self._run_self_check)
        header_layout.addWidget(self_check_button)
        layout.addWidget(header)

        self.stack = QStackedWidget()
        self._add_page(BasicTab(self._set_status))
        self._add_page(AsciiTab(self._set_status))
        self._add_page(MultiTab(self._set_status))
        self._add_page(MitmTab(self._set_status))
        self._add_page(CbcTab(self._set_status))
        layout.addWidget(self.stack, 1)
        return content

    def _add_page(self, page: QWidget) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(page)
        self._pages.append(page)
        self.stack.addWidget(scroll)

    # ------------------------------------------------------------------ #
    # 交互
    # ------------------------------------------------------------------ #
    def _on_nav_changed(self, index: int) -> None:
        if not 0 <= index < len(self._pages):
            return
        self.stack.setCurrentIndex(index)
        page = self._pages[index]
        self.page_title.setText(getattr(page, "PAGE_TITLE", ""))
        self.page_subtitle.setText(getattr(page, "PAGE_SUBTITLE", ""))
        self._fade_in(self.stack.currentWidget())
        self._set_status(f"已切换到 {getattr(page, 'PAGE_TITLE', '')}")

    def _fade_in(self, widget: QWidget) -> None:
        """页面切换时的淡入动画，让界面感觉更连贯。"""
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        animation = QPropertyAnimation(effect, b"opacity", self)
        animation.setDuration(180)
        animation.setStartValue(0.25)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.OutCubic)
        animation.finished.connect(lambda: widget.setGraphicsEffect(None))
        self._animation = animation
        animation.start()

    def _set_status(self, text: str) -> None:
        self.statusBar().showMessage(text, 8000)

    def _run_self_check(self) -> None:
        self._set_status("正在执行算法自测…（含一次完整的中间相遇攻击，约 2 秒）")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            results = run_self_check()
        finally:
            QApplication.restoreOverrideCursor()
        passed = sum(1 for item in results if item["ok"])
        lines = [
            f"{'✓' if item['ok'] else '✗'}  {item['name']}" + (f"   ({item['detail']})" if item["detail"] else "")
            for item in results
        ]
        box = QMessageBox(self)
        box.setWindowTitle("算法自测")
        box.setText(f"{passed} / {len(results)} 项通过")
        box.setDetailedText("\n".join(lines))
        box.setIcon(QMessageBox.Information if passed == len(results) else QMessageBox.Warning)
        box.exec_()
        self._set_status(f"算法自测完成：{passed}/{len(results)} 项通过")

    def closeEvent(self, event) -> None:  # noqa: N802 (Qt 命名)
        # 关闭窗口前结束后台攻击线程，避免线程仍在运行时进程残留
        for page in self._pages:
            stop = getattr(page, "stop_thread", None)
            if callable(stop):
                stop()
        super().closeEvent(event)
