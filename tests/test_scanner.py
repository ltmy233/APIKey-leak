import asyncio
import base64
from collections import Counter
import unittest

from aiohttp import web

from keyaudit.github import GitHubClient, GitHubError
from keyaudit.models import FileEntry, Repository, ScanOptions
from keyaudit.providers import Provider
from keyaudit.scanner import scan


SECRET = 'sk-proj-' + 'Q8rT4yUi9Op6As2D' * 5


class GitHubTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = Counter()
        self.headers = []
        self.truncated = False
        self.slow_blob = False
        self.failure = None
        self.malformed = False
        self.repeated_trees = False
        self.blob_started = asyncio.Event()
        app = web.Application()
        app.router.add_get('/{tail:.*}', self.handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '127.0.0.1', 0)
        await self.site.start()
        self.base = 'http://127.0.0.1:' + str(self.site._server.sockets[0].getsockname()[1])

    async def asyncTearDown(self):
        await self.runner.cleanup()

    async def handle(self, request):
        key = request.path
        self.requests[key] += 1
        self.headers.append(dict(request.headers))
        if key == '/users/owner/repos':
            page = int(request.query.get('page', 1))
            count = 100 if page == 1 else 1
            return web.json_response([{'full_name': f'owner/r{(page - 1) * 100 + n}',
                'default_branch': 'main', 'private': False, 'archived': False, 'size': 10}
                for n in range(count)])
        if key == '/repos/owner/missing':
            return web.json_response({'message': 'Not Found'}, status=404)
        if key == '/repos/owner/repo':
            return web.json_response({'full_name': 'owner/repo', 'default_branch': 'main',
                                      'private': False, 'archived': False, 'size': SECRET if self.malformed else 10})
        if key.endswith('/commits/main'):
            return web.json_response({'sha': 'commit1', 'commit': {'tree': {'sha': 'root'}}})
        if key.endswith('/git/trees/root'):
            if self.truncated and request.query.get('recursive'):
                return web.json_response({'tree': [], 'truncated': True})
            if self.truncated:
                if self.repeated_trees:
                    return web.json_response({'tree': [
                        {'path': 'node_modules', 'type': 'tree', 'sha': 'ignoredroot', 'mode': '040000'},
                        {'path': 'src1', 'type': 'tree', 'sha': 'dir1', 'mode': '040000'},
                        {'path': 'src2', 'type': 'tree', 'sha': 'dir1', 'mode': '040000'},
                    ], 'truncated': False})
                return web.json_response({'tree': [{'path': 'config', 'type': 'tree', 'sha': 'dir1', 'mode': '040000'}], 'truncated': False})
            return web.json_response({'tree': [
                {'path': '.env', 'sha': 'blob1', 'size': 120, 'mode': '100644', 'type': 'blob'},
                {'path': 'copy.env', 'sha': 'blob1', 'size': 120, 'mode': '100644', 'type': 'blob'},
                {'path': 'node_modules/lib.js', 'sha': 'ignored', 'size': 20, 'mode': '100644', 'type': 'blob'},
                {'path': 'image.png', 'sha': 'image', 'size': 20, 'mode': '100644', 'type': 'blob'},
                {'path': 'oversize.txt', 'sha': 'huge', 'size': 2000000, 'mode': '100644', 'type': 'blob'},
            ], 'truncated': False})
        if key.endswith('/git/trees/dir1'):
            return web.json_response({'tree': [{'path': '.env', 'sha': 'blob1', 'size': 120, 'mode': '100644', 'type': 'blob'}], 'truncated': False})
        if key.endswith('/git/blobs/blob1'):
            self.blob_started.set()
            if self.slow_blob:
                await asyncio.sleep(0.4)
            if self.failure:
                return web.json_response({'message': 'forbidden'}, status=self.failure)
            content = base64.b64encode(('OPENAI_API_KEY="' + SECRET + '"').encode()).decode()
            return web.json_response({'encoding': 'base64', 'content': content, 'size': 106})
        if key == '/rate':
            return web.json_response({'message': 'limited'}, status=429, headers={'Retry-After': '300'})
        if key == '/retry':
            if self.requests[key] < 3:
                return web.json_response({}, status=503)
            return web.json_response({'ok': True})
        if key == '/redirect':
            raise web.HTTPFound('/should-not-follow')
        return web.json_response({'message': 'unexpected route'}, status=404)

    async def test_repository_list_is_paginated(self):
        async with GitHubClient('', base_url=self.base) as client:
            repos = await client.list_repositories('owner')
        self.assertEqual(len(repos), 101)
        self.assertIn('owner/r100', [r.full_name for r in repos])
        self.assertEqual(self.requests['/users/owner/repos'], 2)

    async def test_missing_repo_is_not_reported_as_empty_scan(self):
        async with GitHubClient('', base_url=self.base) as client:
            with self.assertRaisesRegex(GitHubError, '404'):
                await client.get_repository('owner/missing')

    async def test_malformed_repository_metadata_uses_controlled_error(self):
        self.malformed = True
        async with GitHubClient('', base_url=self.base) as client:
            with self.assertRaises(GitHubError) as caught:
                await client.get_repository('owner/repo')
        self.assertNotIn(SECRET, str(caught.exception))

    async def test_truncated_tree_prunes_dependencies_and_reuses_tree_shas(self):
        self.truncated = True
        self.repeated_trees = True
        events = []
        async with GitHubClient('', base_url=self.base) as client:
            summary = await scan(client, [Repository('owner/repo')],
                                ScanOptions((Provider.OPENAI,), authorized=True), events.append)
        self.assertEqual(summary.files_scanned, 2)
        self.assertEqual(self.requests['/repos/owner/repo/git/trees/dir1'], 1)
        self.assertEqual(self.requests['/repos/owner/repo/git/trees/ignoredroot'], 0)
        findings = [f for e in events if e['kind'] == 'findings' for f in e['items']]
        self.assertEqual({f.path for f in findings}, {'src1/.env', 'src2/.env'})

    async def test_scan_downloads_blob_once_but_retains_both_paths(self):
        events = []
        async with GitHubClient('synthetic-token', base_url=self.base) as client:
            summary = await scan(client, [Repository('owner/repo')],
                                 ScanOptions((Provider.OPENAI,), authorized=True), events.append)
        findings = [f for e in events if e['kind'] == 'findings' for f in e['items']]
        self.assertEqual({f.path for f in findings}, {'.env', 'copy.env'})
        self.assertEqual(self.requests['/repos/owner/repo/git/blobs/blob1'], 1)
        self.assertEqual(summary.files_scanned, 2)
        self.assertEqual(summary.files_skipped, 3)
        self.assertEqual(summary.files_failed, 0)
        self.assertTrue(all(f.ref == 'commit1' for f in findings))
        self.assertNotIn(SECRET, repr(events))
        self.assertTrue(all(h.get('Authorization') == 'Bearer synthetic-token' for h in self.headers))

    async def test_truncated_recursive_tree_falls_back_to_tree_walk(self):
        self.truncated = True
        events = []
        async with GitHubClient('', base_url=self.base) as client:
            summary = await scan(client, [Repository('owner/repo')],
                                 ScanOptions((Provider.OPENAI,), authorized=True), events.append)
        self.assertEqual(summary.files_scanned, 1)
        self.assertEqual(self.requests['/repos/owner/repo/git/trees/root'], 2)
        findings = [f for e in events if e['kind'] == 'findings' for f in e['items']]
        self.assertEqual(findings[0].path, 'config/.env')

    async def test_blob_failure_is_counted_and_logged_not_silently_swallowed(self):
        self.failure = 403
        events = []
        async with GitHubClient('', base_url=self.base) as client:
            summary = await scan(client, [Repository('owner/repo')],
                                 ScanOptions((Provider.OPENAI,), authorized=True), events.append)
        self.assertEqual(summary.files_failed, 2)
        self.assertTrue(any(e['kind'] == 'log' and '403' in e['message'] for e in events))

    async def test_invalid_auth_aborts_scan_instead_of_repeating_for_every_file(self):
        self.failure = 401
        events = []
        async with GitHubClient('expired-token', base_url=self.base) as client:
            with self.assertRaisesRegex(GitHubError, '401'):
                await scan(client, [Repository('owner/repo')],
                           ScanOptions((Provider.OPENAI,), authorized=True), events.append)
        self.assertEqual(self.requests['/repos/owner/repo/git/blobs/blob1'], 1)

    async def test_rate_limited_blob_aborts_scan_instead_of_trying_remaining_files(self):
        self.failure = 429
        async with GitHubClient('', base_url=self.base) as client:
            with self.assertRaisesRegex(GitHubError, '限流'):
                await asyncio.wait_for(scan(client, [Repository('owner/repo')],
                    ScanOptions((Provider.OPENAI,), authorized=True), lambda _: None), 2)

    async def test_cancelling_scan_leaves_no_download_tasks(self):
        self.slow_blob = True
        async with GitHubClient('', base_url=self.base) as client:
            task = asyncio.create_task(scan(client, [Repository('owner/repo')],
                ScanOptions((Provider.OPENAI,), authorized=True), lambda _: None))
            await asyncio.wait_for(self.blob_started.wait(), 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await asyncio.sleep(0)
            leftovers = [t for t in asyncio.all_tasks() if t.get_name().startswith('audit-download-')]
            self.assertEqual(leftovers, [])

    async def test_long_rate_limit_is_actionable_not_an_unbounded_sleep(self):
        async with GitHubClient('', base_url=self.base) as client:
            with self.assertRaisesRegex(GitHubError, '300'):
                await asyncio.wait_for(client.request('/rate'), 1)

    async def test_transient_server_failure_retries_then_succeeds(self):
        async with GitHubClient('', base_url=self.base) as client:
            self.assertEqual(await client.request('/retry'), {'ok': True})
        self.assertEqual(self.requests['/retry'], 3)

    async def test_redirect_is_not_followed_with_credentials(self):
        async with GitHubClient('synthetic-token', base_url=self.base) as client:
            with self.assertRaises(GitHubError):
                await client.request('/redirect')
        self.assertEqual(self.requests['/should-not-follow'], 0)

    def test_authorization_and_bounds_are_required(self):
        for kwargs in ({}, {'authorized': True, 'concurrency': 0},
                       {'authorized': True, 'max_file_bytes': 0}):
            with self.assertRaises(ValueError):
                ScanOptions((Provider.OPENAI,), **kwargs)

    def test_non_github_remote_api_base_is_rejected(self):
        with self.assertRaises(ValueError):
            GitHubClient('token', base_url='https://evil.test')

    def test_local_test_endpoint_rejects_token_leaking_fragments(self):
        for url in ('http://localhost:1234/#fragment', 'http://localhost:1234/?q=1'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                GitHubClient('token', base_url=url)


class DuplicateExpansionTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelling_first_duplicate_event_stops_remaining_expansion(self):
        class Client:
            async def files(self, repository):
                return 'commit1', [FileEntry(f'copy/{n}.env', 'blob1', 120) for n in range(1000)]

            async def read_blob(self, repository, sha, limit):
                return SECRET

        events = []
        requested = False

        def emit(event):
            nonlocal requested
            if event['kind'] == 'findings':
                events.append(event)
                if not requested:
                    requested = True
                    asyncio.get_running_loop().call_soon(task.cancel)

        task = asyncio.create_task(scan(Client(), [Repository('owner/repo')],
            ScanOptions((Provider.OPENAI,), authorized=True), emit))
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertGreater(len(events), 0)
        self.assertLess(len(events), 10)
        self.assertEqual([t for t in asyncio.all_tasks() if t.get_name().startswith('audit-download-')], [])

    async def test_redacted_first_path_does_not_disable_clean_sibling_link(self):
        class Client:
            async def files(self, repository):
                return 'commit1', [FileEntry(SECRET + '.env', 'blob1', 120),
                                   FileEntry('config.env', 'blob1', 120)]

            async def read_blob(self, repository, sha, limit):
                return SECRET

        events = []
        summary = await scan(Client(), [Repository('owner/repo')],
            ScanOptions((Provider.OPENAI,), authorized=True), events.append)
        items = [f for e in events if e['kind'] == 'findings' for f in e['items']]
        self.assertEqual(summary.files_scanned, 2)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].url, '')
        self.assertTrue(items[1].url.endswith('/config.env#L1'))
        self.assertNotIn(SECRET, repr(events))


if __name__ == '__main__':
    unittest.main()
