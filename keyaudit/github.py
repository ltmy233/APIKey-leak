"""GitHub 元数据和文件读取。"""
import asyncio
import base64
import binascii
from collections import deque
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import re
import time
from urllib.parse import quote, urlsplit

import aiohttp

from .models import FileEntry, Repository, parse_target
from .scope import IGNORED_DIRS


class GitHubError(Exception):
    """可直接显示给用户的请求错误。"""

    def __init__(self, message, *, stop_scan=False):
        super().__init__(message)
        self.stop_scan = stop_scan


def _repo(data):
    try:
        if not isinstance(data, dict) or not isinstance(data['full_name'], str):
            raise TypeError
        size = _count(data.get('size', 0))
        branch = data.get('default_branch') or 'main'
        if not isinstance(branch, str):
            raise TypeError
        return Repository(parse_target(data['full_name'], 'repository'), branch,
                          bool(data.get('private')), bool(data.get('archived')), size)
    except (TypeError, ValueError, KeyError):
        raise GitHubError('GitHub 仓库元数据格式不正确，请检查网络或代理响应') from None


def _count(value):
    if type(value) is not int or value < 0:
        raise GitHubError('GitHub 返回了不正确的文件大小元数据')
    return value


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9]{1,64}', value):
        raise GitHubError('GitHub 返回了不正确的提交或文件标识')
    return value


def _tree(data):
    if not isinstance(data, dict) or not isinstance(data.get('tree'), list):
        raise GitHubError('GitHub 目录树响应格式不正确')
    for entry in data['tree']:
        if (not isinstance(entry, dict) or not isinstance(entry.get('path'), str)
                or not entry['path'] or not isinstance(entry.get('type'), str)):
            raise GitHubError('GitHub 文件条目格式不正确')
        _sha(entry.get('sha'))
        _count(entry.get('size', 0))
    return data


class GitHubClient:
    def __init__(self, token='', *, base_url='https://api.github.com'):
        parsed = urlsplit(base_url)
        local = parsed.hostname in ('127.0.0.1', 'localhost', '::1')
        if (base_url != 'https://api.github.com' and not
                (local and parsed.scheme == 'http' and not parsed.username
                 and not parsed.password and not parsed.query and not parsed.fragment
                 and parsed.path in ('', '/'))):
            raise ValueError('仅支持 GitHub 官方 API 或本地测试服务')
        self.base_url = base_url.rstrip('/')
        self.token = token.strip()
        if any(ch.isspace() or ord(ch) < 32 for ch in self.token):
            raise ValueError('GitHub Token 不能包含空格或换行')
        self.session = None

    async def __aenter__(self):
        headers = {'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28',
                   'User-Agent': 'APIKey-Leak-Authorized-Audit/2.0'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        self.session = aiohttp.ClientSession(
            headers=headers, trust_env=True,
            timeout=aiohttp.ClientTimeout(total=25, connect=10),
            connector=aiohttp.TCPConnector(limit=16, limit_per_host=8))
        return self

    async def __aexit__(self, *exc):
        await self.session.close()
        self.token = ''

    async def request(self, path, params=None, *, limit=24 * 1024 * 1024):
        if not path.startswith('/') or path.startswith('//') or '://' in path:
            raise ValueError('API 路径不正确')
        for attempt in range(3):
            try:
                async with self.session.get(self.base_url + path, params=params,
                                            allow_redirects=False) as response:
                    status = response.status
                    if status in (403, 429):
                        delay = self._rate_delay(response.headers)
                        if status == 429 or delay is not None:
                            delay = delay if delay is not None else 60
                            if delay > 20 or attempt == 2:
                                raise GitHubError(f'GitHub 限流（HTTP {status}），约 {delay:.0f} 秒后重试；已保留收到的结果', stop_scan=True)
                            await asyncio.sleep(max(delay, 0.1))
                            continue
                    if status == 401:
                        raise GitHubError('GitHub HTTP 401：Token 无效或已过期，请重新填写', stop_scan=True)
                    if status == 403:
                        raise GitHubError('GitHub HTTP 403：权限不足或触发限制，请检查仓库访问权限')
                    if status == 404:
                        raise GitHubError('GitHub HTTP 404：用户、仓库或分支不存在，或 Token 无权访问')
                    if status == 409:
                        raise GitHubError('GitHub HTTP 409：仓库为空或没有可扫描的默认分支')
                    if status in (408, 429) or status >= 500:
                        if attempt < 2:
                            await asyncio.sleep(0.5 * (2 ** attempt))
                            continue
                    if status != 200:
                        raise GitHubError(f'GitHub 请求失败（HTTP {status}），未将其视为“未发现密钥”')
                    payload = bytearray()
                    async for chunk in response.content.iter_chunked(65536):
                        payload.extend(chunk)
                        if len(payload) > limit:
                            raise GitHubError('GitHub 响应超过安全大小限制，请缩小扫描范围')
                    try:
                        return json.loads(payload)
                    except (ValueError, UnicodeError) as exc:
                        raise GitHubError('GitHub 返回了无法解析的响应，请检查代理或网络') from exc
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                if attempt == 2:
                    raise GitHubError('连接 GitHub 失败：请检查网络、HTTPS_PROXY 或代理端口，已重试 3 次', stop_scan=True) from exc
                await asyncio.sleep(0.5 * (2 ** attempt))
        raise GitHubError('GitHub 请求重试次数已用尽')

    @staticmethod
    def _rate_delay(headers):
        retry = headers.get('Retry-After')
        if retry is not None:
            try:
                return max(0, float(retry))
            except ValueError:
                try:
                    return max(0, (parsedate_to_datetime(retry) - datetime.now(timezone.utc)).total_seconds())
                except (TypeError, ValueError):
                    return 60
        if headers.get('X-RateLimit-Remaining') == '0':
            try:
                return max(1, float(headers['X-RateLimit-Reset']) - time.time() + 1)
            except (KeyError, ValueError):
                return 60
        return None

    async def get_repository(self, name):
        name = parse_target(name, 'repository')
        return _repo(await self.request('/repos/' + name))

    async def list_repositories(self, owner):
        owner = parse_target(owner, 'user')
        found = {}
        for page in range(1, 101):
            batch = await self.request(f'/users/{owner}/repos',
                                       {'per_page': 100, 'page': page, 'sort': 'full_name', 'type': 'owner'})
            if not isinstance(batch, list):
                raise GitHubError('GitHub 仓库列表格式不正确')
            for data in batch:
                item = _repo(data)
                found[item.full_name.casefold()] = item
            if len(batch) < 100:
                return sorted(found.values(), key=lambda item: item.full_name.casefold())
        raise GitHubError('仓库超过 10000 个，请使用指定仓库模式缩小范围')

    async def files(self, repository):
        # 固定提交，避免扫描期间分支更新导致内容和定位链接不一致。
        name = parse_target(repository.full_name, 'repository')
        ref = quote(repository.default_branch, safe='')
        commit = await self.request(f'/repos/{name}/commits/{ref}')
        try:
            sha = _sha(commit['sha'])
            root = _sha(commit['commit']['tree']['sha'])
        except (KeyError, TypeError):
            raise GitHubError('GitHub 提交响应格式不正确') from None
        base = f'/repos/{name}/git/trees/'
        recursive = _tree(await self.request(base + quote(root, safe=''), {'recursive': '1'}))
        entries = []
        if not recursive.get('truncated'):
            entries = [FileEntry(e['path'], e['sha'], _count(e.get('size', 0)))
                       for e in recursive.get('tree', [])
                       if e.get('type') == 'blob' and e.get('mode') != '120000']
        else:
            pending = deque([('', root)])
            visited = 0
            tree_cache = {}
            while pending:
                prefix, tree_sha = pending.popleft()
                if tree_sha not in tree_cache:
                    tree_cache[tree_sha] = _tree(await self.request(base + quote(tree_sha, safe='')))
                tree = tree_cache[tree_sha]
                if tree.get('truncated'):
                    raise GitHubError('GitHub 单级目录树被截断，无法保证完整扫描；请缩小仓库范围')
                for e in tree.get('tree', []):
                    visited += 1
                    if visited > 100000:
                        raise GitHubError('仓库目录项超过 100000，请缩小范围')
                    path = prefix + e['path']
                    if e.get('type') == 'tree':
                        if not IGNORED_DIRS.intersection(path.split('/')):
                            pending.append((path + '/', e['sha']))
                    elif e.get('type') == 'blob' and e.get('mode') != '120000':
                        entries.append(FileEntry(path, e['sha'], _count(e.get('size', 0))))
        if len(entries) > 100000:
            raise GitHubError('仓库文件超过 100000，请缩小范围')
        return sha, entries

    async def read_blob(self, repository, sha, limit):
        name = parse_target(repository.full_name, 'repository')
        data = await self.request(f'/repos/{name}/git/blobs/{quote(sha, safe="")}', limit=limit * 2 + 65536)
        if data.get('encoding') != 'base64':
            raise GitHubError('GitHub 返回了不支持的文件编码')
        try:
            raw = base64.b64decode(''.join(data['content'].split()), validate=True)
        except (ValueError, KeyError, binascii.Error) as exc:
            raise GitHubError('GitHub 文件内容解码失败') from exc
        if len(raw) > limit or b'\x00' in raw:
            return None
        try:
            return raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            return None
