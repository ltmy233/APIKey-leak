"""并发扫描、去重和覆盖统计。"""
import asyncio
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
import time

from .github import GitHubError
from .rules import detect_async
from .privacy import safe_text
from .scope import IGNORED_DIRS


BINARY_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg', '.mp3', '.mp4',
                   '.woff', '.woff2', '.ttf', '.zip', '.gz', '.7z', '.rar', '.pdf', '.exe',
                   '.dll', '.so', '.pyc', '.class', '.jar', '.sqlite', '.db', '.lock'}


@dataclass
class ScanSummary:
    repositories_done: int = 0
    repositories_failed: int = 0
    files_total: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    findings: int = 0
    elapsed: float = 0


def eligible(entry, limit):
    path = PurePosixPath(entry.path)
    return (entry.size <= limit and not IGNORED_DIRS.intersection(path.parts[:-1])
            and path.suffix.lower() not in BINARY_SUFFIXES)


async def scan(client, repositories, options, emit):
    summary = ScanSummary()
    started = time.monotonic()
    seen_repos = set()

    def progress():
        summary.elapsed = time.monotonic() - started
        emit({'kind': 'progress', 'summary': replace(summary)})

    for repo in repositories:
        if repo.full_name.casefold() in seen_repos:
            continue
        seen_repos.add(repo.full_name.casefold())
        emit({'kind': 'log', 'message': safe_text(f'读取目录树：{repo.full_name} / {repo.default_branch}')})
        try:
            ref, entries = await client.files(repo)
        except GitHubError as exc:
            if exc.stop_scan:
                raise
            summary.repositories_failed += 1
            emit({'kind': 'log', 'message': safe_text(f'{repo.full_name}：{exc}')})
            progress()
            continue
        summary.files_total += len(entries)
        groups = {}
        for entry in entries:
            if eligible(entry, options.max_file_bytes):
                groups.setdefault(entry.sha, []).append(entry)
            else:
                summary.files_skipped += 1
        jobs = iter(groups.items())
        progress()

        async def consume():
            for sha, paths in jobs:
                try:
                    text = await client.read_blob(repo, sha, options.max_file_bytes)
                    if text is None:
                        summary.files_skipped += len(paths)
                    else:
                        # 相同 blob 只检测一次，结果仍保留各文件路径。
                        findings = await detect_async(text, repo.full_name, '', ref, options.providers)
                        del text
                        for entry in paths:
                            for offset in range(0, len(findings), 250):
                                items = [replace(f, path=entry.path) for f in findings[offset:offset + 250]]
                                summary.findings += len(items)
                                emit({'kind': 'findings', 'items': items})
                                if offset + 250 < len(findings):
                                    progress()
                                    await asyncio.sleep(0)
                            summary.files_scanned += 1
                            progress()
                            await asyncio.sleep(0)
                except GitHubError as exc:
                    if exc.stop_scan:
                        raise
                    summary.files_failed += len(paths)
                    emit({'kind': 'log', 'message': safe_text(f'{repo.full_name} / {paths[0].path}：{exc}')})
                progress()
                await asyncio.sleep(0)

        tasks = [asyncio.create_task(consume(), name=f'audit-download-{n}')
                 for n in range(min(options.concurrency, len(groups)))]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        summary.repositories_done += 1
        progress()
    progress()
    return summary
