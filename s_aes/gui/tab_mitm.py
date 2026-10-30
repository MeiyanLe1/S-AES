"""第 4.2 关：中间相遇攻击（对双重加密，复杂度从 2^32 降到 2×2^16）。"""

from __future__ import annotations

import random

from PyQt5.QtCore import QThread, Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QListWidget,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core import ValidationError, format_hex
from ..multi import double_encrypt, meet_in_the_middle
from .page_base import PageBase
from .theme import DANGER, SUCCESS, WARNING, mono_font
from .widgets import Card, HexInput, MetricTile, muted_label


class AttackThread(QThread):
    """后台执行中间相遇攻击，避免 2×65536 次运算阻塞界面。"""

    progress = pyqtSignal(int, int)
    finished_with_result = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, pairs: list[tuple[int, int]], parent=None):
        super().__init__(parent)
        self._pairs = list(pairs)
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:  # noqa: D102 (QThread 约定)
        try:
            result = meet_in_the_middle(
                self._pairs,
                progress_callback=lambda done, total: self.progress.emit(done, total),
                cancel_check=lambda: self._cancelled,
            )
        except Exception as error:  # noqa: BLE001 - 后台线程任何异常都要回传界面
            self.failed.emit(str(error))
            return
        self.finished_with_result.emit(result)


class MitmTab(PageBase):
    """第 4.2 关页面。"""

    PAGE_TITLE = "第 4.2 关 · 中间相遇攻击"
    PAGE_SUBTITLE = "已知明密文对，求双重加密的 32 bit 密钥 Key = K1 ‖ K2"

    def __init__(self, status_callback=None, parent: QWidget | None = None):
        super().__init__(status_callback, parent)
        self._pairs: list[tuple[int, int]] = []
        self._thread: AttackThread | None = None
        self._build_pair_card()
        self._build_result_card()
        self.layout.addStretch(1)

    # ------------------------------------------------------------------ #
    def _build_pair_card(self) -> None:
        card = Card("明密文对", hint="攻击只需要 1 组对即可得到候选密钥；多加几组可以快速筛掉偶然命中的假密钥",
                    badge_text="2^16 × 2")

        input_row = QHBoxLayout()
        input_row.setSpacing(12)
        self.plain_input = HexInput("已知明文 P", 16, 0x1234)
        self.cipher_input = HexInput("对应密文 C", 16, 0x0000)
        input_row.addWidget(self.plain_input, 1)
        input_row.addWidget(self.cipher_input, 1)
        add_button = QPushButton("添加 / 更新")
        add_button.setProperty("variant", "primary")
        add_button.setCursor(Qt.PointingHandCursor)
        add_button.clicked.connect(self._on_add_pair)
        input_row.addWidget(add_button, 0, Qt.AlignBottom)
        card.body.addLayout(input_row)

        list_row = QHBoxLayout()
        list_row.setSpacing(12)
        self._list = _PairListWidget(self._pairs)
        self._list.setMinimumHeight(120)
        list_row.addWidget(self._list, 1)

        side = QVBoxLayout()
        side.setSpacing(8)
        side.addWidget(self._small_button("生成样例对", self._generate_sample))
        side.addWidget(self._small_button("删除选中", self._remove_selected))
        side.addWidget(self._small_button("清空全部", self._clear_pairs))
        side.addStretch(1)
        list_row.addLayout(side, 0)
        card.body.addLayout(list_row)

        action_row = QHBoxLayout()
        action_row.setSpacing(10)
        self.start_button = QPushButton("开始中间相遇攻击")
        self.start_button.setProperty("variant", "primary")
        self.start_button.setMinimumHeight(40)
        self.start_button.setCursor(Qt.PointingHandCursor)
        self.start_button.clicked.connect(self._start_attack)
        action_row.addWidget(self.start_button, 2)

        self.cancel_button = QPushButton("取消")
        self.cancel_button.setProperty("variant", "danger")
        self.cancel_button.setMinimumHeight(40)
        self.cancel_button.setEnabled(False)
        self.cancel_button.setCursor(Qt.PointingHandCursor)
        self.cancel_button.clicked.connect(self._cancel_attack)
        action_row.addWidget(self.cancel_button, 1)
        card.body.addLayout(action_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        card.body.addWidget(self.progress_bar)
        card.body.addWidget(muted_label(
            "原理：C = E_K2(E_K1(P))，中间值 M = E_K1(P) = D_K2(C)。先枚举全部 K1 建立「M → K1」表，"
            "再枚举全部 K2 计算 D_K2(C) 查表，命中即为候选密钥。"
        ))
        self.layout.addWidget(card)

    def _build_result_card(self) -> None:
        card = Card("攻击结果", badge_text="候选密钥")
        metric_row = QHBoxLayout()
        metric_row.setSpacing(10)
        self.metric_elapsed = MetricTile("耗时 (秒)")
        self.metric_table = MetricTile("索引表项")
        self.metric_candidates = MetricTile("候选密钥数")
        for tile in (self.metric_elapsed, self.metric_table, self.metric_candidates):
            metric_row.addWidget(tile, 1)
        card.body.addLayout(metric_row)

        self.result_table = QTableWidget(0, 4)
        self.result_table.setHorizontalHeaderLabels(["#", "K1", "K2", "32 bit 密钥 Key"])
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.result_table.setMinimumHeight(170)
        card.body.addWidget(self.result_table)

        self.summary_label = muted_label("尚未运行攻击")
        card.body.addWidget(self.summary_label)
        self.layout.addWidget(card)

    def _small_button(self, text: str, handler) -> QPushButton:
        button = QPushButton(text)
        button.setProperty("variant", "ghost")
        button.setCursor(Qt.PointingHandCursor)
        button.clicked.connect(handler)
        return button

    # ------------------------------------------------------------------ #
    def _on_add_pair(self) -> None:
        try:
            plaintext = self.plain_input.value()
            ciphertext = self.cipher_input.value()
        except ValidationError as error:
            self.report_error(error)
            return
        for index, (existing_plain, _) in enumerate(self._pairs):
            if existing_plain == plaintext:
                self._pairs[index] = (plaintext, ciphertext)
                break
        else:
            self._pairs.append((plaintext, ciphertext))
        self._list.refresh_pairs(self._pairs)
        self.report_success(f"已加入明密文对 P={format_hex(plaintext)} → C={format_hex(ciphertext)}")

    def _append_pair(self, plaintext: int, ciphertext: int) -> None:
        self._pairs.append((plaintext, ciphertext))

    def _generate_sample(self) -> None:
        key32 = random.getrandbits(32)
        plaintexts = random.sample(range(0x10000), 2)
        self._pairs = [(plaintext, double_encrypt(plaintext, key32)) for plaintext in plaintexts]
        self._list.refresh_pairs(self._pairs)
        self.status(f"已生成样例：真实密钥 {format_hex(key32, 32)}（仅用于验证攻击结果，攻击过程并不使用它）")

    def _remove_selected(self) -> None:
        row = self._list.currentRow()
        if 0 <= row < len(self._pairs):
            self._pairs.pop(row)
            self._list.refresh_pairs(self._pairs)

    def _clear_pairs(self) -> None:
        self._pairs.clear()
        self._list.refresh_pairs(self._pairs)

    # ------------------------------------------------------------------ #
    def _start_attack(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            return
        if not self._pairs:
            self.report_error(ValidationError("请先添加至少一组明密文对"))
            return
        self.start_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.result_table.setRowCount(0)
        self.summary_label.setText("正在枚举 2^16 个 K1 建立索引表，请稍候…")
        self.status("中间相遇攻击开始")

        self._thread = AttackThread(list(self._pairs), self)
        self._thread.progress.connect(self._on_progress)
        self._thread.finished_with_result.connect(self._on_finished)
        self._thread.failed.connect(self._on_failed)
        self._thread.start()

    def _cancel_attack(self) -> None:
        if self._thread is not None:
            self._thread.cancel()
            self.summary_label.setText("正在取消…")

    def _on_progress(self, done: int, total: int) -> None:
        self.progress_bar.setValue(int(done * 100 / total))

    def _on_finished(self, result: dict) -> None:
        self.start_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.progress_bar.setValue(100 if not result.get("cancelled") else self.progress_bar.value())
        candidates = result["candidates"]
        self.metric_elapsed.set_value(f"{result['elapsed']:.2f}")
        self.metric_table.set_value(str(result["table_entries"]))
        self.metric_candidates.set_value(str(len(candidates)),
                                         SUCCESS if len(candidates) == 1 else WARNING)

        self.result_table.setRowCount(len(candidates))
        for row, (key1, key2) in enumerate(candidates):
            key32 = (key1 << 16) | key2
            values = [str(row + 1), format_hex(key1), format_hex(key2), format_hex(key32, 32)]
            for column, text in enumerate(values):
                item = QTableWidgetItem(text)
                if column:
                    item.setFont(mono_font(13))
                self.result_table.setItem(row, column, item)

        if result.get("cancelled"):
            self.summary_label.setText("攻击已取消")
            self.status("中间相遇攻击已取消")
            return
        if not candidates:
            self.summary_label.setStyleSheet(f"color: {DANGER}; font-size: 11px;")
            self.summary_label.setText("没有找到候选密钥，请检查明密文对是否来自同一组双重加密密钥")
            self.status("攻击结束：未找到候选密钥")
            return
        self.summary_label.setStyleSheet(f"color: {SUCCESS}; font-size: 11px;")
        self.summary_label.setText(
            f"建表 {result['table_entries']} 项后，查表命中 {result['middle_hits']} 次（含碰撞），"
            f"再逐一用全部 {len(self._pairs)} 组明密文对复核，最终得到 {len(candidates)} 组可用密钥。"
        )
        self.status(f"攻击成功：找到 {len(candidates)} 组候选密钥，耗时 {result['elapsed']:.2f}s")

    def _on_failed(self, message: str) -> None:
        self.start_button.setEnabled(True)
        self.cancel_button.setEnabled(False)
        self.report_error(RuntimeError(message))

    # ------------------------------------------------------------------ #
    def stop_thread(self) -> None:
        """窗口关闭时结束后台线程。"""
        if self._thread is not None and self._thread.isRunning():
            self._thread.cancel()
            self._thread.wait(3000)


class _PairListWidget(QListWidget):
    """展示明密文对列表的小控件。"""

    def __init__(self, pairs: list[tuple[int, int]], parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("pairList")
        self.refresh_pairs(pairs)

    def refresh_pairs(self, pairs: list[tuple[int, int]]) -> None:
        self.clear()
        for index, (plaintext, ciphertext) in enumerate(pairs):
            item_text = f"{index + 1}.  P = {format_hex(plaintext)}   →   C = {format_hex(ciphertext)}"
            self.addItem(item_text)
        if not pairs:
            self.addItem("（空）请添加明密文对，或点击「生成样例对」")
