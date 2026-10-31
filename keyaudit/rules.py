"""密钥格式匹配和厂商上下文判断。"""
from functools import lru_cache
import asyncio
import hashlib
import io
import re

from .models import Finding
from .providers import Provider, PROVIDERS


CONTEXT = {
    Provider.OPENAI: r'openai', Provider.DEEPSEEK: r'deepseek',
    Provider.ANTHROPIC: r'anthropic|claude', Provider.GOOGLE_AI: r'gemini|google',
    Provider.HUGGINGFACE: r'hugging.?face|hf_token', Provider.XAI: r'xai|grok',
    Provider.COHERE: r'cohere|co_api_key', Provider.REPLICATE: r'replicate',
    Provider.TOGETHER: r'together', Provider.MISTRAL: r'mistral',
    Provider.GROQ: r'groq', Provider.PERPLEXITY: r'perplexity|pplx',
    Provider.JINA: r'jina', Provider.VOYAGE: r'voyage',
    Provider.FIREWORKS: r'fireworks', Provider.DEEPINFRA: r'deepinfra',
    Provider.NOVITA: r'novita', Provider.SILICONFLOW: r'siliconflow',
    Provider.AI21: r'ai21',
}
GENERIC = {Provider.COHERE, Provider.TOGETHER, Provider.MISTRAL,
           Provider.DEEPINFRA, Provider.NOVITA, Provider.AI21}
PREFIXES = (
    ('sk-ant-', Provider.ANTHROPIC), ('sk-proj-', Provider.OPENAI),
    ('sk-svcacct-', Provider.OPENAI), ('hf_', Provider.HUGGINGFACE),
    ('xai-', Provider.XAI), ('gsk_', Provider.GROQ),
    ('pplx-', Provider.PERPLEXITY), ('jina_', Provider.JINA),
    ('fw_', Provider.FIREWORKS), ('r8_', Provider.REPLICATE),
    ('pa-', Provider.VOYAGE), ('AIza', Provider.GOOGLE_AI),
)
PLACEHOLDER = re.compile(r'your[_-]|example|placeholder|test[_-]?key|xxx|abc123|qwerty', re.I)
ASSIGNMENT = re.compile(r'(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)[\x27\x22]?\s*[:=]\s*[\x27\x22]?\s*$')


@lru_cache(maxsize=19)
def _patterns(provider):
    return tuple(re.compile(r'(?<![A-Za-z0-9_-])(?:' + pattern + r')(?![A-Za-z0-9_-])')
                 for pattern in PROVIDERS[provider].patterns)


def _line_findings(text, repository, path, ref, providers):
    selected = tuple(dict.fromkeys(providers))
    for line_number, line in enumerate(io.StringIO(text), 1):
        findings = []
        # 跳过压缩文件的超长行，限制正则匹配耗时。
        if len(line) > 32768:
            yield []
            continue
        candidates = {}
        for provider in selected:
            if provider in GENERIC and not re.search(CONTEXT[provider], line, re.I):
                continue
            for pattern in _patterns(provider):
                for match in pattern.finditer(line):
                    key = match.group()
                    if (len(key) > 512 or PLACEHOLDER.search(key)
                            or len(set(key.removeprefix('sk-proj-').removeprefix('sk-'))) < 5):
                        continue
                    prefix_owner = next((p for prefix, p in PREFIXES if key.startswith(prefix)), None)
                    if prefix_owner is not None and prefix_owner != provider:
                        continue
                    # 通用格式须匹配赋值上下文，减少普通哈希的误报。
                    before = line[max(0, match.start() - 180):match.start()]
                    assignment = ASSIGNMENT.search(before)
                    context = bool(assignment and re.search(CONTEXT[provider], assignment['name'], re.I))
                    if provider in GENERIC and not (context and assignment):
                        continue
                    candidates.setdefault((match.start(), match.end(), key), []).append((provider, context))
        farthest_end = -1
        for (start, end, key), owners in sorted(candidates.items(), key=lambda pair: (pair[0][0], -pair[0][1])):
            # 长格式已匹配时，不重复记录其中的短片段。
            if end <= farthest_end:
                continue
            farthest_end = end
            contextual = [p for p, matched in owners if matched]
            named = contextual or [p for p, _ in owners]
            if key.startswith('sk-') and not key.startswith(('sk-ant-', 'sk-proj-', 'sk-svcacct-')) and not contextual:
                label = 'SK 兼容密钥（厂商待确认）'
            else:
                label = named[0].value
            fingerprint = hashlib.sha256(key.encode('utf-8')).hexdigest()
            findings.append(Finding(label, key[:6] + '…' + key[-4:], fingerprint,
                                    repository, path, line_number, ref))
        yield findings


def detect(text, repository, path, ref, providers):
    return [finding for batch in _line_findings(text, repository, path, ref, providers)
            for finding in batch]


async def detect_async(text, repository, path, ref, providers):
    findings = []
    for batch in _line_findings(text, repository, path, ref, providers):
        findings.extend(batch)
        # 每行检查一次取消，避免等到整份文件处理结束。
        await asyncio.sleep(0)
    return findings
