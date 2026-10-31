"""CLI 和桌面端共用的厂商配置。"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

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
