"""各关卡页面的公共基类：统一的错误提示与状态栏通知。"""

from __future__ import annotations

from typing import Callable

from PyQt5.QtWidgets import QMessageBox, QVBoxLayout, QWidget

from ..core import ValidationError


class PageBase(QWidget):
    """页面基类。

    子类只需在 ``__init__`` 中调用 ``super().__init__(status_callback)`` 并往
    ``self.layout`` 里堆控件；输入错误统一走 :meth:`report_error`，不会让程序崩溃。
    """

    PAGE_TITLE = "页面"
    PAGE_SUBTITLE = ""

    def __init__(self, status_callback: Callable[[str], None] | None = None, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("pageRoot")
        self.setAutoFillBackground(False)
        self._status_callback = status_callback or (lambda text: None)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(22, 18, 22, 22)
        self.layout.setSpacing(14)

    # ------------------------------------------------------------------ #
    def status(self, text: str) -> None:
        """把提示信息送到主窗口状态栏。"""
        self._status_callback(text)

    def report_error(self, error: Exception) -> None:
        """统一的错误出口：状态栏 + 弹窗提示。"""
        message = str(error) if isinstance(error, ValidationError) else f"{type(error).__name__}: {error}"
        self.status(message)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("输入有误")
        box.setText(message)
        box.setStandardButtons(QMessageBox.Ok)
        box.exec_()

    def report_success(self, text: str) -> None:
        self.status(text)
