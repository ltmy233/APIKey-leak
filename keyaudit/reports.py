"""报告导出和 CSV 公式转义。"""
import csv
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from .privacy import safe_text


FIELDS = ('provider', 'masked', 'fingerprint', 'repository', 'path', 'line', 'confidence', 'url')
COVERAGE_FIELDS = ('state', 'files_total', 'files_scanned', 'files_skipped', 'files_failed',
                   'repositories_done', 'repositories_failed', 'concurrency', 'max_file_bytes')


def _csv_safe(value):
    if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@', '\t', '\r', '\n')):
        return "'" + value
    return value


def export_report(path, findings, *, coverage=None):
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix not in ('.json', '.csv', '.txt'):
        raise ValueError('请选择 JSON、CSV 或 TXT 文件')
    rows = [{**asdict(item), 'url': item.url} for item in findings]
    source = coverage or {'state': 'unspecified'}
    coverage = {k: (v if type(v) in (int, float, bool) else safe_text(v))
                for k, v in source.items() if k in COVERAGE_FIELDS}
    coverage.setdefault('state', 'unspecified')
    fd, temporary = tempfile.mkstemp(prefix='.audit-', suffix=suffix, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8-sig' if suffix == '.csv' else 'utf-8', newline='') as handle:
            if suffix == '.json':
                json.dump({'scope': 'authorized repositories / current default branch',
                           'validation': 'offline only; no credentials tested',
                           'created_at': datetime.now(timezone.utc).isoformat(),
                           'coverage': coverage,
                           'coverage_note': '仅覆盖已读取的默认分支当前文件；取消、失败、跳过项及历史不构成无泄漏证明。',
                           'findings': rows}, handle, ensure_ascii=False, indent=2)
            elif suffix == '.csv':
                fields = (*FIELDS, *('scan_' + k for k in COVERAGE_FIELDS))
                writer = csv.DictWriter(handle, fields, extrasaction='ignore')
                writer.writeheader()
                for row in rows:
                    writer.writerow({**{k: _csv_safe(row[k]) for k in FIELDS},
                                     **{'scan_' + k: _csv_safe(coverage.get(k, '')) for k in COVERAGE_FIELDS}})
            else:
                handle.write('授权仓库密钥自查报告 · 仅特征匹配，未验证密钥\n')
                handle.write('扫描范围：仅已读取的当前文件，取消、失败或跳过项不构成无泄漏证明。\n')
                handle.write('覆盖统计：' + json.dumps(coverage, ensure_ascii=False) + '\n')
                for row in rows:
                    handle.write(f"\n[{row['provider']}] {row['masked']}\n{row['repository']} / {row['path']}:{row['line']}\nSHA-256: {row['fingerprint']}\n{row['url']}\n")
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
