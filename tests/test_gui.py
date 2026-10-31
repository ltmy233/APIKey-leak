import asyncio
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import time
import unittest
from unittest.mock import patch

from PySide6.QtCore import Qt, QTimer, QRect
from PySide6.QtTest import QTest, QSignalSpy
from PySide6.QtWidgets import QApplication

from keyaudit.app import MainWindow
from keyaudit.models import Finding, Repository
from keyaudit.models import FileEntry
from keyaudit.results import ResultsModel, FindingsFilter
from keyaudit.scanner import ScanSummary
from keyaudit.worker import AuditWorker
from keyaudit.providers import Provider
from keyaudit.models import ScanOptions


APP = QApplication.instance() or QApplication([])
FINDING = Finding('OpenAI', 'sk-pro…7Zq9', 'a' * 64, 'owner/repo', '.env', 3, 'main')


class ModelTests(unittest.TestCase):
    def test_filter_matches_file_provider_and_repository(self):
        model = ResultsModel()
        model.append_findings([FINDING, Finding('DeepSeek', 'sk-Q8…8Gv2', 'b' * 64,
                                              'owner/second', 'settings.py', 8, 'main')])
        proxy = FindingsFilter()
        proxy.setSourceModel(model)
        for query, expected in (('openai', 1), ('settings', 1), ('owner/', 2), ('absent', 0)):
            proxy.setFilterFixedString(query)
            self.assertEqual(proxy.rowCount(), expected)

    def test_model_keeps_evidence_for_duplicate_fingerprint_and_sorts_numeric_lines(self):
        model = ResultsModel()
        model.append_findings([FINDING, Finding('OpenAI', 'sk-pro…7Zq9', 'a' * 64,
                                              'owner/repo', 'config.py', 20, 'main')])
        self.assertEqual(model.rowCount(), 2)
        self.assertEqual(model.unique_count, 1)
        self.assertEqual(model.data(model.index(1, 4), Qt.ItemDataRole.UserRole), 20)
        model.clear()
        self.assertEqual(model.rowCount(), 0)
        self.assertEqual(model.unique_count, 0)


class WindowTests(unittest.TestCase):
    def setUp(self):
        self.window = MainWindow()
        self.window.show()
        APP.processEvents()

    def tearDown(self):
        self.window.close()
        APP.processEvents()

    def test_authorization_and_repository_selection_gate_start(self):
        self.assertFalse(self.window.start_button.isEnabled())
        self.window.setup.set_repositories([Repository('owner/repo')])
        self.window.setup.authorized.setChecked(True)
        APP.processEvents()
        self.assertTrue(self.window.start_button.isEnabled())
        self.window.setup.select_repositories(False)
        self.assertFalse(self.window.start_button.isEnabled())

    def test_changing_target_or_mode_discards_stale_repository_selection(self):
        self.window.setup.set_repositories([Repository('owner/repo')])
        self.window.setup.target.setText('different-user')
        self.assertEqual(self.window.setup.selected_repositories(), [])
        self.window.setup.set_repositories([Repository('owner/repo')])
        self.window.setup.mode.setCurrentIndex(1)
        self.assertEqual(self.window.setup.selected_repositories(), [])

    def test_no_selected_provider_disables_scan(self):
        self.window.setup.set_repositories([Repository('owner/repo')])
        self.window.setup.authorized.setChecked(True)
        self.window.setup.select_providers(False)
        self.assertFalse(self.window.start_button.isEnabled())

    def test_busy_state_keeps_cancel_available_and_configuration_locked(self):
        self.window.set_busy(True, 'scan')
        self.assertFalse(self.window.setup.isEnabled())
        self.assertFalse(self.window.start_button.isEnabled())
        self.assertTrue(self.window.cancel_button.isEnabled())
        self.window.set_busy(False)
        self.assertFalse(self.window.cancel_button.isEnabled())

    def test_findings_update_table_counter_and_empty_state(self):
        self.window.handle_event({'kind': 'findings', 'items': [FINDING]})
        self.assertEqual(self.window.model.rowCount(), 1)
        self.assertIn('1', self.window.found_label.text())
        self.window.search.setText('no-matching-result')
        APP.processEvents()
        self.assertEqual(self.window.proxy.rowCount(), 0)
        self.assertTrue(self.window.empty_state.isVisible())

    def test_token_is_hidden_not_saved_and_cleared_on_close(self):
        self.window.setup.token.setText('synthetic-token')
        self.assertEqual(self.window.setup.token.echoMode(), self.window.setup.token.EchoMode.Password)
        self.window.close()
        self.assertEqual(self.window.setup.token.text(), '')

    def test_cancelled_scan_keeps_actual_progress_instead_of_claiming_full_completion(self):
        self.window.set_busy(True, 'scan')
        self.window.summary = ScanSummary(files_total=40, files_scanned=10)
        self.window._cancelled()
        self.window._finished()
        self.assertEqual(self.window.progress.maximum(), 40)
        self.assertEqual(self.window.progress.value(), 10)

    def test_initial_window_fits_high_dpi_desktop_with_titlebar_margin(self):
        class Screen:
            def availableGeometry(self):
                return QRect(0, 0, 1707, 912)

        with patch('keyaudit.app.QApplication.primaryScreen', return_value=Screen()):
            window = MainWindow()
        try:
            self.assertLessEqual(window.height(), 848)
            self.assertLessEqual(window.width(), 1659)
        finally:
            window.close()


class SlowClient:
    def __init__(self, token):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        pass

    async def list_repositories(self, owner):
        await asyncio.sleep(0.3)
        return [Repository(owner + '/demo')]


class FixtureClient(SlowClient):
    async def get_repository(self, name):
        await asyncio.sleep(0.02)
        return Repository(name)

    async def files(self, repository):
        return 'commit123', [FileEntry('.env', 'blob123', 120)]

    async def read_blob(self, repository, sha, limit):
        await asyncio.sleep(0.05)
        return 'OPENAI_API_KEY="sk-proj-' + 'N7zP4vR2mK8qT6aB' * 5 + '"'


class FixtureWindow(MainWindow):
    def _launch(self, worker):
        worker.client_factory = FixtureClient
        super()._launch(worker)


def wait_until(predicate, timeout_ms=3000):
    deadline = time.monotonic() + timeout_ms / 1000
    while not predicate() and time.monotonic() < deadline:
        APP.processEvents()
        QTest.qWait(10)
    APP.processEvents()
    return predicate()


class WorkerTests(unittest.TestCase):
    def test_unexpected_value_error_never_exposes_untrusted_response_text(self):
        secret = 'sk-proj-' + 'Q7nT8kV2mW6zR9pB' * 5
        class MalformedClient(SlowClient):
            async def list_repositories(self, owner):
                raise ValueError('invalid literal: ' + secret)
        worker = AuditWorker('list', '', target='owner', client_factory=MalformedClient)
        failed = QSignalSpy(worker.failed)
        worker.start()
        self.assertTrue(wait_until(worker.isFinished))
        self.assertEqual(failed.count(), 1)
        self.assertNotIn(secret, failed.at(0)[0])

    def test_dense_detection_cancels_promptly_without_waiting_for_whole_blob(self):
        secret = 'sk-proj-' + 'Q7nT8kV2mW6zR9pB' * 5
        text = (' '.join([secret] * 360) + '\n') * 32
        class DenseClient(SlowClient):
            async def files(self, repository):
                return 'commit', [FileEntry('.env', 'sha', len(text))]
            async def read_blob(self, repository, sha, limit):
                return text
        worker = AuditWorker('scan', '', repositories=[Repository('owner/repo')],
            options=ScanOptions(tuple(Provider), authorized=True), client_factory=DenseClient)
        cancelled = QSignalSpy(worker.cancelled)
        worker.start()
        QTest.qWait(100)
        started = time.monotonic()
        worker.request_cancel()
        # Always wait for cleanup before asserting, avoiding QThread destruction on failure.
        finished = wait_until(worker.isFinished, 15000)
        elapsed = time.monotonic() - started
        self.assertTrue(finished)
        self.assertEqual(cancelled.count(), 1)
        self.assertLess(elapsed, 1.5)

    def test_loading_repositories_does_not_block_gui_heartbeat(self):
        worker = AuditWorker('list', '', target='owner', client_factory=SlowClient)
        completed = QSignalSpy(worker.completed)
        ticks = []
        timer = QTimer()
        timer.timeout.connect(lambda: ticks.append(1))
        timer.start(20)
        worker.start()
        self.assertTrue(wait_until(worker.isFinished))
        timer.stop()
        self.assertGreaterEqual(len(ticks), 3)
        self.assertEqual(completed.count(), 1)
        self.assertEqual(completed.at(0)[0][0].full_name, 'owner/demo')

    def test_immediate_cancel_exits_cleanly_and_drops_token(self):
        worker = AuditWorker('list', 'synthetic-token', target='owner', client_factory=SlowClient)
        cancelled = QSignalSpy(worker.cancelled)
        completed = QSignalSpy(worker.completed)
        worker.start()
        worker.request_cancel()
        self.assertTrue(wait_until(worker.isFinished))
        self.assertEqual(cancelled.count(), 1)
        self.assertEqual(completed.count(), 0)
        self.assertEqual(worker.token, '')


class ClickFlowTests(unittest.TestCase):
    def test_repository_load_scan_filter_and_copy_through_real_controls(self):
        window = FixtureWindow()
        window.show()
        try:
            window.setup.mode.setCurrentIndex(1)
            window.setup.target.setText('owner/demo')
            QTest.mouseClick(window.setup.load_button, Qt.MouseButton.LeftButton)
            self.assertTrue(wait_until(lambda: not window._busy))
            self.assertEqual(len(window.setup.selected_repositories()), 1)
            window.setup.authorized.setChecked(True)
            QTest.mouseClick(window.start_button, Qt.MouseButton.LeftButton)
            self.assertTrue(wait_until(lambda: not window._busy))
            self.assertEqual(window.model.rowCount(), 1)
            self.assertIn('完成', window.state_label.text())
            self.assertEqual(window.summary.files_scanned, 1)
            window.search.setText('openai')
            self.assertEqual(window.proxy.rowCount(), 1)
            window.table.selectRow(0)
            window.copy_selected()
            self.assertIn('owner/demo', APP.clipboard().text())
            self.assertNotIn('N7zP4vR2mK8qT6aB', APP.clipboard().text())
            self.assertTrue(window.export_button.isEnabled())
        finally:
            window.close()
            APP.processEvents()

    def test_closing_while_loading_waits_for_cancel_before_destroying_window(self):
        window = MainWindow()
        window.show()
        worker = AuditWorker('list', 'synthetic-token', target='owner', client_factory=SlowClient)
        window._launch(worker)
        window.close()
        self.assertTrue(wait_until(lambda: not window.isVisible()))
        self.assertIsNone(window._worker)
        self.assertEqual(window.setup.token.text(), '')

    def test_ten_thousand_rows_filter_without_creating_per_cell_widgets(self):
        window = MainWindow()
        try:
            items = [Finding('OpenAI', 'sk-pro…3Wq7', f'{n:064x}', 'owner/demo',
                             f'config/{n}.env', n + 1, 'commit') for n in range(10000)]
            window.handle_event({'kind': 'findings', 'items': items})
            self.assertEqual(window.model.rowCount(), 10000)
            window.search.setText('config/9999.env')
            self.assertEqual(window.proxy.rowCount(), 1)
        finally:
            window.close()


if __name__ == '__main__':
    unittest.main()
