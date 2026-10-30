"""GUI 子包：深色主题、复用控件与各关卡页面。

只有本子包依赖 PyQt5，``s_aes.core`` / ``s_aes.multi`` / ``s_aes.modes`` 均为纯标准库实现，
因此即使未安装 PyQt5 也可以用 ``python main.py --selftest`` 直接验证算法。
"""

from .main_window import MainWindow
from .theme import apply_theme

__all__ = ["MainWindow", "apply_theme"]
