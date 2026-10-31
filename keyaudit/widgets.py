"""扫描范围、仓库列表和检测选项。"""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFormLayout, QFrame,
                               QGridLayout, QHBoxLayout, QLabel, QLineEdit,
                               QListWidget, QListWidgetItem, QPushButton,
                               QScrollArea, QSpinBox, QVBoxLayout, QWidget)

from .providers import Provider
from .privacy import safe_text


def label(text, name='', wrap=False):
    widget = QLabel(text)
    if name:
        widget.setObjectName(name)
    widget.setWordWrap(wrap)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    return widget


def link_button(text, callback):
    button = QPushButton(text)
    button.setObjectName('link')
    button.clicked.connect(callback)
    return button


class ScanSetup(QWidget):
    changed = Signal()
    load_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._repositories = []
        self._setting = False
        self.provider_checks = {}
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(16)
        scroll.setWidget(content)
        outer.addWidget(scroll)

        target_card, target_layout = self.card('扫描范围')
        self.mode = QComboBox()
        self.mode.addItem('指定用户 · 选择其公开仓库', 'user')
        self.mode.addItem('指定仓库 · 直接扫描', 'repository')
        self.mode.setAccessibleName('扫描模式')
        target_layout.addWidget(self.mode)
        self.target = QLineEdit()
        self.target.setClearButtonEnabled(True)
        self.target.setAccessibleName('GitHub 用户或仓库')
        self.target.setPlaceholderText('用户名或 https://github.com/用户名')
        self.target.returnPressed.connect(self.load_requested)
        target_layout.addWidget(self.target)
        self.token = QLineEdit()
        self.token.setEchoMode(QLineEdit.EchoMode.Password)
        self.token.setPlaceholderText('GitHub Token（可选，仅保存在内存）')
        self.token.setAccessibleName('GitHub Token，仅保存在内存')
        self.token.setToolTip('公开仓库可不填；私有仓库需使用有读取权限的 Token。支持 classic / fine-grained Token。')
        target_layout.addWidget(self.token)
        self.load_button = QPushButton('加载用户仓库')
        self.load_button.clicked.connect(self.load_requested)
        target_layout.addWidget(self.load_button)
        self.scope_hint = label('用户模式仅列出公开仓库；私有仓库请切换指定仓库模式。', 'muted', True)
        target_layout.addWidget(self.scope_hint)
        layout.addWidget(target_card)

        repository_card, repository_layout = self.card('待扫描仓库')
        actions = QHBoxLayout()
        self.repository_count = label('尚未加载', 'muted')
        actions.addWidget(self.repository_count)
        actions.addStretch()
        actions.addWidget(link_button('全选', lambda: self.select_repositories(True)))
        actions.addWidget(link_button('清空', lambda: self.select_repositories(False)))
        repository_layout.addLayout(actions)
        self.repo_search = QLineEdit()
        self.repo_search.setPlaceholderText('筛选仓库名称…')
        self.repo_search.setAccessibleName('筛选仓库')
        self.repo_search.textChanged.connect(self._filter_repositories)
        repository_layout.addWidget(self.repo_search)
        self.repo_list = QListWidget()
        self.repo_list.setAccessibleName('勾选获授权的待扫描仓库')
        self.repo_list.setMinimumHeight(130)
        self.repo_list.setMaximumHeight(210)
        self.repo_list.itemChanged.connect(self._selection_changed)
        repository_layout.addWidget(self.repo_list)
        layout.addWidget(repository_card)

        provider_card, provider_layout = self.card('检测厂商')
        provider_actions = QHBoxLayout()
        provider_actions.addWidget(label('仅做离线特征识别', 'muted'))
        provider_actions.addStretch()
        provider_actions.addWidget(link_button('全选', lambda: self.select_providers(True)))
        provider_actions.addWidget(link_button('清空', lambda: self.select_providers(False)))
        provider_layout.addLayout(provider_actions)
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(10)
        for n, provider in enumerate(Provider):
            check = QCheckBox(provider.value.replace('Google AI (Gemini)', 'Google AI').replace('HuggingFace', 'Hugging Face'))
            check.setChecked(True)
            check.toggled.connect(self.changed)
            check.setToolTip(provider.value)
            grid.addWidget(check, n // 2, n % 2)
            self.provider_checks[provider] = check
        provider_layout.addLayout(grid)
        layout.addWidget(provider_card)

        advanced_card, advanced_layout = self.card('性能与授权')
        form = QFormLayout()
        self.concurrency = QSpinBox()
        self.concurrency.setRange(1, 16)
        self.concurrency.setValue(4)
        self.concurrency.setAccessibleName('下载并发数')
        self.max_file_kb = QSpinBox()
        self.max_file_kb.setRange(1, 8192)
        self.max_file_kb.setValue(1024)
        self.max_file_kb.setSuffix(' KB')
        self.max_file_kb.setAccessibleName('单文件大小限制')
        form.addRow('并发下载', self.concurrency)
        form.addRow('单文件上限', self.max_file_kb)
        advanced_layout.addLayout(form)
        self.authorized = QCheckBox('我拥有所选仓库的扫描授权')
        self.authorized.setToolTip('仅用于自有仓库或明确获授权的安全自查。')
        self.authorized.toggled.connect(self.changed)
        advanced_layout.addWidget(self.authorized)
        advanced_layout.addWidget(label('只扫描默认分支当前快照；不扫描历史，不验证密钥，不查询余额。', 'muted', True))
        layout.addWidget(advanced_card)
        layout.addStretch()
        self.target.textChanged.connect(self._invalidate)
        self.token.textChanged.connect(self._invalidate)
        self.mode.currentIndexChanged.connect(self._mode_changed)

    @staticmethod
    def card(title):
        frame = QFrame()
        frame.setObjectName('card')
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        layout.addWidget(label(title, 'section'))
        return frame, layout

    def _mode_changed(self):
        user = self.mode.currentData() == 'user'
        self.target.setPlaceholderText('用户名或 https://github.com/用户名' if user else 'owner/repo 或 https://github.com/owner/repo')
        self.load_button.setText('加载用户仓库' if user else '读取指定仓库')
        self.scope_hint.setText('用户模式仅列出公开仓库；私有仓库请切换指定仓库模式。' if user
                                else '读取仓库默认分支；私有仓库需要有读取权限的 Token。')
        self._invalidate()

    def _invalidate(self):
        self._repositories = []
        self.repo_list.clear()
        self._selection_changed()

    def set_repositories(self, repositories):
        self._setting = True
        self._repositories = list(repositories)
        self.repo_list.clear()
        for repo in self._repositories:
            suffix = ' · 已归档' if repo.archived else ''
            item = QListWidgetItem(safe_text(repo.full_name) + suffix)
            item.setData(Qt.ItemDataRole.UserRole, repo)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            item.setToolTip(safe_text(f'{repo.full_name}\n默认分支：{repo.default_branch}\n') + ('私有仓库' if repo.private else '公开仓库'))
            self.repo_list.addItem(item)
        self._setting = False
        self._filter_repositories(self.repo_search.text())
        self._selection_changed()

    def _filter_repositories(self, text):
        for n in range(self.repo_list.count()):
            item = self.repo_list.item(n)
            item.setHidden(text.casefold() not in item.text().casefold())

    def _selection_changed(self):
        if self._setting:
            return
        self.repository_count.setText(f'已选 {len(self.selected_repositories())} / {self.repo_list.count()}')
        self.changed.emit()

    def selected_repositories(self):
        return [self.repo_list.item(n).data(Qt.ItemDataRole.UserRole)
                for n in range(self.repo_list.count())
                if self.repo_list.item(n).checkState() == Qt.CheckState.Checked]

    def select_repositories(self, checked):
        self._setting = True
        for n in range(self.repo_list.count()):
            self.repo_list.item(n).setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        self._setting = False
        self._selection_changed()

    def selected_providers(self):
        return tuple(p for p, check in self.provider_checks.items() if check.isChecked())

    def select_providers(self, checked):
        for check in self.provider_checks.values():
            check.setChecked(checked)
        self.changed.emit()
