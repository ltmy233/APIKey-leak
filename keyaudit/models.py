"""扫描目标、文件条目和结果记录。"""
from dataclasses import dataclass
import re
from urllib.parse import quote, urlsplit
from .privacy import safe_text


def parse_target(text: str, mode: str) -> str:
    if mode not in ('user', 'repository'):
        raise ValueError('未知扫描模式')
    value = text.strip()
    if value.startswith('github.com/'):
        value = 'https://' + value
    if '://' in value:
        url = urlsplit(value)
        if (url.scheme != 'https' or url.netloc.lower() != 'github.com'
                or url.query or url.fragment):
            raise ValueError('请输入 https://github.com 上的用户或仓库链接')
        value = url.path.strip('/')
    else:
        value = value.rstrip('/')
    if mode == 'repository' and value.endswith('.git'):
        value = value[:-4]
    parts = value.split('/')
    owner_ok = bool(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?', parts[0]))
    if not owner_ok or '--' in parts[0]:
        raise ValueError('GitHub 用户名格式不正确')
    if mode == 'user' and len(parts) == 1:
        return value
    if (mode == 'repository' and len(parts) == 2
            and re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', parts[1])
            and parts[1] not in ('.', '..')):
        return value
    raise ValueError('用户模式填写用户名；仓库模式填写 owner/repo 或仓库主页链接')


@dataclass(frozen=True)
class Repository:
    full_name: str
    default_branch: str = 'main'
    private: bool = False
    archived: bool = False
    size: int = 0


@dataclass(frozen=True)
class FileEntry:
    path: str
    sha: str
    size: int


@dataclass(frozen=True)
class Finding:
    provider: str
    masked: str
    fingerprint: str
    repository: str
    path: str
    line: int
    ref: str
    confidence: str = '特征匹配（未验证）'
    metadata_redacted: bool = False

    def __post_init__(self):
        redacted = self.metadata_redacted
        for name in ('provider', 'masked', 'repository', 'path', 'ref', 'confidence'):
            original = getattr(self, name)
            # 提交 SHA 需要原样保留，供源码定位使用。
            if name == 'ref' and re.fullmatch(r'[a-fA-F0-9]{40}', original):
                continue
            clean = safe_text(original)
            if name in ('repository', 'path', 'ref') and original != clean:
                redacted = True
            object.__setattr__(self, name, clean)
        object.__setattr__(self, 'metadata_redacted', redacted)

    @property
    def url(self) -> str:
        if self.metadata_redacted:
            return ''
        return (f'https://github.com/{self.repository}/blob/'
                f'{quote(self.ref, safe="")}/{quote(self.path, safe="/")}#L{self.line}')


@dataclass(frozen=True)
class ScanOptions:
    providers: tuple
    concurrency: int = 4
    max_file_bytes: int = 1024 * 1024
    authorized: bool = False

    def __post_init__(self):
        if not self.authorized:
            raise ValueError('请先确认拥有所选仓库的扫描授权')
        if not self.providers:
            raise ValueError('请至少选择一个厂商')
        if not 1 <= self.concurrency <= 16:
            raise ValueError('并发数必须在 1–16 之间')
        if not 1024 <= self.max_file_bytes <= 8 * 1024 * 1024:
            raise ValueError('文件大小限制必须在 1 KB–8 MB 之间')
