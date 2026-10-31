"""主窗口和扫描流程。"""
from datetime import datetime
from dataclasses import asdict
from pathlib import Path
import sys

from PySide6.QtCore import QTimer, QUrl, Qt
from PySide6.QtGui import QDesktopServices, QIcon, QKeySequence, QShortcut
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QButtonGroup,
    QFileDialog, QFrame, QHBoxLayout, QHeaderView, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSplitter, QStackedWidget,
    QTableView, QVBoxLayout, QWidget, QLineEdit)

from .models import ScanOptions, parse_target
from .reports import export_report
from .privacy import safe_text
from .results import FindingsFilter, ResultsModel
from .scanner import ScanSummary
from .theme import apply_theme
from .widgets import ScanSetup, label
from .worker import AuditWorker


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('APIKey Leak · 授权仓库自查')
        screen = QApplication.primaryScreen()
        available = screen.availableGeometry() if screen else None
        width = max(320, available.width() - 48) if available else 1380
        height = max(320, available.height() - 64) if available else 920
        self.setMinimumSize(min(1060, width), min(700, height))
        self.resize(min(1380, width), min(920, height))
        icon = Path(__file__).resolve().parent.parent / 'app.ico'
        if icon.exists():
            self.setWindowIcon(QIcon(str(icon)))
        self._worker = None
        self._busy = False
        self._job = ''
        self._closing = False
        self._scan_state = 'not_started'
        self._scan_options = {}
        self.summary = ScanSummary()
        self._build()
        self._update_controls()

    def _build(self):
        root = QWidget()
        root.setObjectName('root')
        self.setCentralWidget(root)
        horizontal = QHBoxLayout(root)
        horizontal.setContentsMargins(0, 0, 0, 0)
        horizontal.setSpacing(0)
        sidebar = QFrame()
        sidebar.setObjectName('sidebar')
        sidebar.setFixedWidth(176)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(18, 28, 18, 24)
        side.setSpacing(8)
        side.addWidget(label('KEY / AUDIT', 'eyebrow'))
        side.addWidget(label('APIKey\nLeak', 'brand'))
        side.addSpacing(36)
        self.nav_group = QButtonGroup(self)
        for n, text in enumerate(('仓库自查', '运行日志', '使用说明')):
            button = QPushButton(text)
            button.setObjectName('nav')
            button.setCheckable(True)
            button.setChecked(n == 0)
            self.nav_group.addButton(button, n)
            side.addWidget(button)
        side.addStretch()
        side.addWidget(label('LOCAL DETECTION', 'eyebrow'))
        side.addWidget(label('仅特征识别\n不调用发现的密钥\n不保存 GitHub Token', 'muted', True))
        horizontal.addWidget(sidebar)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(24, 24, 24, 20)
        layout.setSpacing(16)
        header = QHBoxLayout()
        heading = QVBoxLayout()
        heading.addWidget(label('REPOSITORY / SECURITY', 'eyebrow'))
        heading.addWidget(label('让密钥留在仓库之外', 'title'))
        header.addLayout(heading)
        header.addStretch()
        self.state_label = label('就绪 · 等待选择仓库', 'muted')
        header.addWidget(self.state_label)
        layout.addLayout(header)
        layout.addWidget(label('定向自查 · 先选择获授权仓库，再检查默认分支当前快照。所有结果默认脱敏。', 'notice', True))
        self.error_label = label('', 'error', True)
        self.error_label.hide()
        layout.addWidget(self.error_label)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.setup = ScanSetup()
        self.setup.setMinimumWidth(340)
        splitter.addWidget(self.setup)
        self.pages = QStackedWidget()
        self.pages.addWidget(self._results_page())
        self.logs = QPlainTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setMaximumBlockCount(2000)
        self.logs.setPlaceholderText('后台任务的进度与错误会显示在这里。不包含完整密钥或 Token。')
        self.logs.setAccessibleName('扫描运行日志')
        self.pages.addWidget(self.logs)
        help_text = QPlainTextEdit()
        help_text.setReadOnly(True)
        help_text.setPlainText(
            '定向仓库自查\n\n'
            '1. 选择“指定用户”或“指定仓库”，填写 GitHub 用户名 / 仓库主页链接。\n'
            '2. 点击加载；用户模式从公开仓库列表中勾选目标。私有仓库请用指定仓库模式。\n'
            '3. GitHub Token 可选。私有仓库需要有 Contents 读取权限的 Token。\n'
            '4. 选择检测厂商，确认拥有扫描授权，再点击“开始自查”。\n\n'
            '结果如何理解\n\n'
            '结果是疑似泄漏的特征匹配，不代表密钥有效。通用格式需要同一行的厂商赋值上下文；'
            '无法确定厂商的 sk- 密钥会标记“厂商待确认”。可能有误报与漏报。\n'
            '同一密钥的不同文件位置会分别保留，指纹用于汇总去重。不会请求厂商接口、模型或余额。\n'
            '发现疑似泄漏后，应由仓库所有者在厂商控制台撤销/轮换密钥，并移除代码及历史中的泄漏。\n\n'
            '范围与性能\n\n'
            '仅扫描默认分支当前提交，内容和源码链接锁定同一提交；不扫描历史、子模块或其他分支。\n'
            '默认跳过构建/依赖目录、常见二进制、超过 1 MB 的文件及非 UTF-8 文件。'
            '超过 32768 字符的单行不检测；这会跳过部分压缩生成内容。\n'
            '下载按同一仓库的 blob 指纹去重，并发默认 4。取消不会丢掉已经显示的结果。\n'
            '取消、错误或有跳过项时，结果不是完整无泄漏证明。导出包含所有已显示结果，不只筛选行。\n\n'
            '网络与隐私\n\n'
            '无 Token 时 GitHub 请求限额较低。限流和权限错误会显式提示，不会伪装成“无发现”。\n'
            'GitHub Token 隐藏输入，仅在内存中使用，不写入配置或报告；关闭窗口时清空输入。\n'
            '读取遵循 HTTP_PROXY / HTTPS_PROXY / NO_PROXY。代理端口不可用时请先修正环境变量。\n'
            '仓库已重命名导致 API 重定向时，请改填最新的仓库名称。\n\n'
            '快捷键\n\nCtrl+F：筛选结果    Ctrl+C：复制选中行的脱敏记录    Esc：取消后台任务\n'
            '双击结果：确认后在浏览器中打开源码定位链接。')
        self.pages.addWidget(help_text)
        splitter.addWidget(self.pages)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([365, 760])
        splitter.setChildrenCollapsible(False)
        layout.addWidget(splitter, 1)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setAccessibleName('扫描进度')
        layout.addWidget(self.progress)
        footer = QHBoxLayout()
        self.status_text = label('加载用户仓库或指定仓库后，勾选授权即可开始。', 'muted', True)
        footer.addWidget(self.status_text, 1)
        self.cancel_button = QPushButton('取消任务')
        self.cancel_button.setObjectName('danger')
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel)
        footer.addWidget(self.cancel_button)
        self.start_button = QPushButton('开始自查')
        self.start_button.setObjectName('primary')
        self.start_button.setMinimumWidth(132)
        self.start_button.clicked.connect(self.start_scan)
        footer.addWidget(self.start_button)
        layout.addLayout(footer)
        horizontal.addWidget(body, 1)
        self.nav_group.idClicked.connect(self.pages.setCurrentIndex)
        self.setup.load_requested.connect(self.load_repositories)
        self.setup.changed.connect(self._update_controls)
        QShortcut(QKeySequence('Ctrl+F'), self, activated=self._focus_search)
        QShortcut(QKeySequence('Ctrl+C'), self.table, activated=self.copy_selected)
        QShortcut(QKeySequence('Escape'), self, activated=self.cancel)

    def _results_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 0, 0, 0)
        layout.setSpacing(16)
        metrics = QHBoxLayout()
        self.scanned_label = self._metric(metrics, '已扫描文件', '0')
        self.found_label = self._metric(metrics, '疑似密钥 / 去重', '0 / 0')
        self.issue_label = self._metric(metrics, '失败 / 跳过', '0 / 0')
        layout.addLayout(metrics)
        tools = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText('筛选厂商、仓库或文件…  Ctrl+F')
        self.search.setAccessibleName('筛选扫描结果')
        self.search.setClearButtonEnabled(True)
        tools.addWidget(self.search, 1)
        self.export_button = QPushButton('导出报告')
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export)
        tools.addWidget(self.export_button)
        layout.addLayout(tools)
        self.model = ResultsModel(self)
        self.proxy = FindingsFilter(self)
        self.proxy.setSourceModel(self.model)
        self.search.textChanged.connect(self._filter)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(2, Qt.SortOrder.AscendingOrder)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAccessibleName('疑似泄漏位置，所有片段已脱敏')
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(43)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((190, 135, 160, 180, 58, 190)):
            self.table.setColumnWidth(column, width)
        self.table.doubleClicked.connect(self.open_source)
        self.result_stack = QStackedWidget()
        self.result_stack.addWidget(self.table)
        self.empty_state = QWidget()
        empty = QVBoxLayout(self.empty_state)
        empty.setContentsMargins(32, 32, 32, 32)
        empty.addStretch()
        empty.addWidget(label('⌕', 'title'), alignment=Qt.AlignmentFlag.AlignHCenter)
        self.empty_title = label('从一个获授权的仓库开始', 'section')
        self.empty_description = label('在左侧加载用户仓库，或直接指定 owner/repo。\n扫描结果会保留文件与行号，不显示完整密钥。', 'muted', True)
        self.empty_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        empty.addWidget(self.empty_title)
        empty.addWidget(self.empty_description)
        empty.addStretch()
        self.result_stack.addWidget(self.empty_state)
        self.result_stack.setCurrentIndex(1)
        layout.addWidget(self.result_stack, 1)
        self.result_count = label('0 条记录 · 仅特征匹配，不代表密钥有效', 'muted')
        layout.addWidget(self.result_count)
        return page

    @staticmethod
    def _metric(layout, title, value):
        card = QFrame()
        card.setObjectName('card')
        body = QVBoxLayout(card)
        body.setContentsMargins(16, 12, 16, 12)
        body.addWidget(label(title, 'muted'))
        number = label(value, 'metric')
        body.addWidget(number)
        layout.addWidget(card, 1)
        return number

    def _focus_search(self):
        self.nav_group.button(0).setChecked(True)
        self.pages.setCurrentIndex(0)
        self.search.setFocus()

    def _filter(self, text):
        self.proxy.setFilterFixedString(text)
        self._refresh_results()

    def _refresh_results(self):
        count = self.proxy.rowCount()
        self.result_stack.setCurrentIndex(0 if count else 1)
        self.result_count.setText(f'{count} / {self.model.rowCount()} 条记录 · 仅特征匹配，不代表密钥有效')
        self.export_button.setEnabled(bool(self.model.rowCount()))
        if not count and self.search.text():
            self.empty_title.setText('没有匹配当前筛选的记录')
            self.empty_description.setText('清除筛选词可查看全部结果。')
        elif not count and self._busy and self._job == 'scan':
            self.empty_title.setText('正在检查仓库快照…')
            self.empty_description.setText('发现疑似泄漏后会实时显示。你可以随时取消，界面不会等待网络。')

    def _update_controls(self):
        ready = (not self._busy and self.setup.authorized.isChecked()
                 and bool(self.setup.selected_repositories()) and bool(self.setup.selected_providers()))
        self.start_button.setEnabled(ready)

    def set_busy(self, busy, job=''):
        self._busy = busy
        self._job = job
        self.setup.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.cancel_button.setText('取消任务')
        if busy:
            self.error_label.hide()
            self.progress.setRange(0, 0)
            self.state_label.setText('正在自查' if job == 'scan' else '正在加载仓库')
        else:
            self.progress.setRange(0, 100)
        self._update_controls()

    def _error(self, message):
        self.error_label.setText(safe_text(message))
        self.error_label.show()
        self._log(message)

    def _log(self, message):
        self.logs.appendPlainText(f'{datetime.now():%H:%M:%S}  {safe_text(message)}')

    def load_repositories(self):
        if self._busy:
            return
        mode = self.setup.mode.currentData()
        try:
            target = parse_target(self.setup.target.text(), mode)
        except ValueError as exc:
            self._error(str(exc))
            self.setup.target.setFocus()
            return
        self.setup.set_repositories([])
        self._log(f'加载{"用户公开仓库" if mode == "user" else "指定仓库"}：{target}')
        self._launch(AuditWorker('list' if mode == 'user' else 'repository',
                                self.setup.token.text(), target=target))

    def start_scan(self):
        if self._busy:
            return
        try:
            options = ScanOptions(self.setup.selected_providers(), self.setup.concurrency.value(),
                                  self.setup.max_file_kb.value() * 1024, self.setup.authorized.isChecked())
            repositories = self.setup.selected_repositories()
            if not repositories:
                raise ValueError('请先加载并勾选至少一个仓库')
        except ValueError as exc:
            self._error(str(exc))
            return
        self.model.clear()
        self.search.clear()
        self.summary = ScanSummary()
        self._update_summary()
        self._scan_state = 'running'
        self._scan_options = {'concurrency': options.concurrency, 'max_file_bytes': options.max_file_bytes}
        self.empty_title.setText('正在检查仓库快照…')
        self.empty_description.setText('结果只做离线匹配；不会验证密钥或查询余额。')
        self._focus_search()
        self._log(f'开始授权自查：{len(repositories)} 个仓库，{len(options.providers)} 个厂商，并发 {options.concurrency}')
        self._launch(AuditWorker('scan', self.setup.token.text(), repositories=repositories, options=options))
        self._refresh_results()

    def _launch(self, worker):
        self._worker = worker
        self.set_busy(True, worker.job)
        self.status_text.setText('后台读取 GitHub；Esc 或“取消任务”可中止。')
        worker.events.connect(self._events)
        worker.completed.connect(self._completed)
        worker.failed.connect(self._failed)
        worker.cancelled.connect(self._cancelled)
        worker.finished.connect(self._finished)
        worker.start()

    def _events(self, events):
        for event in events:
            self.handle_event(event)

    def handle_event(self, event):
        kind = event['kind']
        if kind == 'findings':
            self.model.append_findings(event['items'])
            self.found_label.setText(f'{self.model.rowCount()} / {self.model.unique_count}')
            self._refresh_results()
        elif kind == 'progress':
            self.summary = event['summary']
            self._update_summary()
        elif kind == 'log':
            self._log(event['message'])
            self.status_text.setText(safe_text(event['message']))

    def _update_summary(self):
        s = self.summary
        self.scanned_label.setText(f'{s.files_scanned:,}')
        self.found_label.setText(f'{self.model.rowCount()} / {self.model.unique_count}')
        self.issue_label.setText(f'{s.files_failed + s.repositories_failed} / {s.files_skipped}')
        if s.files_total:
            self.progress.setRange(0, s.files_total)
            self.progress.setValue(s.files_scanned + s.files_failed + s.files_skipped)
        self.status_text.setText(f'文件 {s.files_scanned + s.files_failed + s.files_skipped:,} / {s.files_total:,} · '
                                 f'仓库完成 {s.repositories_done} · 耗时 {s.elapsed:.1f}s')

    def _completed(self, payload):
        if self._job in ('list', 'repository'):
            self.setup.set_repositories(payload)
            self.state_label.setText('仓库已加载')
            self.status_text.setText(f'已加载 {len(payload)} 个仓库；请勾选目标并确认授权。')
            if not payload:
                self._error('没有可见的公开仓库。私有仓库请使用指定仓库模式，并填写有读取权限的 Token。')
        else:
            self.summary = payload
            self._update_summary()
            partial = bool(payload.repositories_failed or payload.files_failed)
            self._scan_state = 'partial' if partial else 'completed'
            self.state_label.setText('部分完成 · 请查看日志' if partial else '自查完成')
            self.empty_title.setText('当前范围未发现疑似密钥' if not partial else '未得到完整扫描结果')
            self.empty_description.setText('仅表示已读取文件中没有匹配；跳过文件和未扫描历史不在结论范围内。'
                                           if not partial else '部分仓库或文件读取失败，请查看运行日志，修正权限或网络后重试。')
            self._log(f'自查结束：{payload.files_scanned} 文件，{self.model.unique_count} 个去重疑似密钥，'
                      f'{payload.files_failed} 文件失败，{payload.repositories_failed} 仓库失败')
            if partial:
                self._error('扫描部分完成：存在读取失败项。已收到的脱敏结果可导出；详细原因见运行日志。')

    def _failed(self, message):
        if self._job == 'scan':
            self._scan_state = 'failed'
        self.state_label.setText('任务失败 · 结果已保留')
        self.status_text.setText('请修正问题后重试，已显示的结果可导出。')
        self.empty_title.setText('任务未完成')
        self.empty_description.setText('请查看错误提示与运行日志；不能将本次结果视为“无泄漏”。')
        self._error(message)

    def _cancelled(self):
        if self._job == 'scan':
            self._scan_state = 'cancelled'
        self.state_label.setText('已取消 · 部分结果已保留')
        self.status_text.setText('已停止后台任务。当前结果仅覆盖取消前已扫描的文件。')
        self.empty_title.setText('扫描已取消')
        self.empty_description.setText('当前结果不是完整扫描结论；可以重新开始。')
        self._log('用户取消任务，保留已显示的脱敏结果')

    def _finished(self):
        worker = self._worker
        finished_job = self._job
        self._worker = None
        self.set_busy(False)
        if finished_job == 'scan':
            s = self.summary
            self.progress.setRange(0, max(1, s.files_total))
            self.progress.setValue(s.files_scanned + s.files_failed + s.files_skipped)
        else:
            self.progress.setValue(0)
        self._refresh_results()
        if worker:
            worker.deleteLater()
        if self._closing:
            QTimer.singleShot(0, self.close)

    def cancel(self):
        if self._worker and self._worker.isRunning():
            self._worker.request_cancel()
            self.cancel_button.setText('正在停止…')
            self.cancel_button.setEnabled(False)
            self.status_text.setText('正在取消并关闭网络连接；已显示结果会保留。')

    def selected_findings(self):
        indexes = self.table.selectionModel().selectedRows()
        return [self.model.items[self.proxy.mapToSource(index).row()] for index in indexes]

    def copy_selected(self):
        items = self.selected_findings()
        if items:
            QApplication.clipboard().setText('\n'.join(f'{f.provider}\t{f.masked}\t{f.repository}\t{f.path}:{f.line}\t{f.fingerprint}' for f in items))
            self.status_text.setText(f'已复制 {len(items)} 条脱敏记录。')

    def open_source(self, index):
        if not index.isValid():
            return
        item = self.model.items[self.proxy.mapToSource(index).row()]
        if not item.url:
            self.status_text.setText('文件或仓库名称包含疑似敏感片段，已脱敏并禁用直达链接。请在仓库中手动定位。')
            return
        answer = QMessageBox.question(self, '打开仓库源码',
            '源码页面可能显示完整敏感信息。请仅在有权访问的环境中查看。\n\n是否在浏览器中定位该文件？',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if answer == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl(item.url))

    def export(self):
        if not self.model.items:
            return
        path, selected = QFileDialog.getSaveFileName(self, '导出全部脱敏记录',
            f'key-audit-{datetime.now():%Y%m%d-%H%M%S}.json',
            'JSON 报告 (*.json);;CSV 表格 (*.csv);;文本报告 (*.txt)')
        if not path:
            return
        if not Path(path).suffix:
            path += '.csv' if 'CSV' in selected else '.txt' if '文本' in selected else '.json'
        try:
            export_report(path, tuple(self.model.items), coverage={
                **asdict(self.summary), **self._scan_options, 'state': self._scan_state})
        except (OSError, ValueError) as exc:
            self._error(f'导出失败：{exc}')
        else:
            self.status_text.setText(f'已导出 {self.model.rowCount()} 条脱敏记录：{safe_text(Path(path).name)}')

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._closing = True
            self.cancel()
            event.ignore()
            return
        self.setup.token.clear()
        event.accept()


def main():
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName('APIKey Leak Audit')
    apply_theme(app)
    window = MainWindow()
    window.show()
    return app.exec()
