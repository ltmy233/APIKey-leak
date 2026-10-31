"""后台线程的事件循环和界面消息转发。"""
import asyncio
import threading
import time

from PySide6.QtCore import QThread, Signal

from .github import GitHubClient, GitHubError
from .scanner import scan


class AuditWorker(QThread):
    events = Signal(object)
    completed = Signal(object)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, job, token, *, target='', repositories=(), options=None,
                 client_factory=GitHubClient, parent=None):
        super().__init__(parent)
        self.job = job
        self.token = token
        self.target = target
        self.repositories = repositories
        self.options = options
        self.client_factory = client_factory
        self._cancel = threading.Event()
        self._loop = None
        self._task = None
        self._pending_findings = []
        self._pending_logs = []
        self._progress = None
        self._last_emit = time.monotonic()

    def request_cancel(self):
        self._cancel.set()
        loop, task = self._loop, self._task
        if loop is not None and task is not None:
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                pass  # 任务可能已结束，事件循环也随之关闭。

    def _emit(self, event):
        kind = event['kind']
        if kind == 'findings':
            self._pending_findings.extend(event['items'])
        elif kind == 'log':
            self._pending_logs.append(event)
        else:
            self._progress = event
        if (time.monotonic() - self._last_emit >= 0.08
                or len(self._pending_findings) >= 250 or len(self._pending_logs) >= 50):
            self._flush()

    def _flush(self):
        events, self._pending_logs = self._pending_logs, []
        if self._pending_findings:
            events.append({'kind': 'findings', 'items': self._pending_findings})
            self._pending_findings = []
        if self._progress:
            events.append(self._progress)
            self._progress = None
        if events:
            self.events.emit(events)
        self._last_emit = time.monotonic()

    async def _run_job(self):
        async with self.client_factory(self.token) as client:
            if self.job == 'list':
                return await client.list_repositories(self.target)
            if self.job == 'repository':
                return [await client.get_repository(self.target)]
            if self.job == 'scan':
                return await scan(client, self.repositories, self.options, self._emit)
            raise ValueError('未知后台任务')

    def run(self):
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            self._task = loop.create_task(self._run_job())
            if self._cancel.is_set():
                self._task.cancel()
            result = loop.run_until_complete(self._task)
            self._flush()
            if self._cancel.is_set():
                self.cancelled.emit()
            else:
                self.completed.emit(result)
        except asyncio.CancelledError:
            self._flush()
            self.cancelled.emit()
        except GitHubError as exc:
            self._flush()
            self.failed.emit(str(exc))
        except Exception:
            self._flush()
            # 异常可能包含响应原文，只显示固定提示。
            self.failed.emit('后台任务发生异常。请检查网络与依赖后重试；已收到的脱敏结果仍可导出。')
        finally:
            self.token = ''
            remaining = asyncio.all_tasks(loop)
            for task in remaining:
                task.cancel()
            if remaining:
                loop.run_until_complete(asyncio.gather(*remaining, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            self._task = None
            self._loop = None
            loop.close()
