#!/usr/bin/env python3
"""checkers.py — чекеры API: (1) жив ли ключ, (2) ЧТО этот API умеет.

Зачем: сканер нашёл 3042 записи, но «живых» всего 10 — потому что проверять было
нечем. Здесь реестр чекеров: для каждого сервиса настоящий эндпоинт, схема авторизации
и категория возможностей (text/video/audio/embed/search/agent/osint/infra).

Приоритет (по указанию заказчика): НЕ gemini/openai/anthropic (там миллионы ключей и
429), а редкие и «дорогие» направления — azure, bedrock, deepinfra, exa, видео, аудио,
агенты, OSINT.

Правила:
  * 200            -> alive
  * 401/403        -> dead (ключ реальный, но протух/отозван)
  * 404/5xx/timeout-> unknown (эндпоинт может отличаться — НЕ считаем мёртвым)
  * pair/endpoint  -> ключу нужна пара (bedrock: secret+region; azure: свой endpoint)

Запуск:
  python3 tools/checkers.py list                 # что умеем проверять
  python3 tools/checkers.py verify --limit 60    # проверить неверифицированные
  python3 tools/checkers.py verify --services deepinfra,exa,azure,bedrock
"""
from __future__ import annotations

import base64
import csv
import os
import re
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
KEYS = ROOT / "ALL-FOUND-KEYS.json"
REPORT = ROOT / "verification-report.jsonl"
VALID = ROOT / "keys-valid.csv"
MEM = ROOT / "agent_memory"
MEM.mkdir(exist_ok=True)
UA = "secrethunter/2 (+https://github.com/kimocoder/testsploit)"

# ---------------------------------------------------------------- реестр чекеров
CHECKS: dict[str, dict] = {}


def reg(name, url, auth, ok=(200,), cat="text", note="", kind="single",
        method="GET", body=None, headers=None, dead=(401, 403), deep=None,
        body_ok=None, body_bad=None, credits_bad=None, alt=None):
    """deep: второй пробник (POST к эндпоинту, который ТРЕБУЕТ ключ) — защита от
    публичных /models, которые отдают 200 даже на мусор.
    body_ok/body_bad: правила по телу ответа (regex), если сервис прячет ошибку в JSON."""
    CHECKS[name] = dict(url=url, auth=auth, ok=tuple(ok), cat=cat, note=note,
                        kind=kind, method=method, body=body, headers=headers or {},
                        dead=tuple(dead), deep=deep,
                        body_ok=body_ok, body_bad=body_bad, credits_bad=credits_bad,
                        alt=list(alt or []))


B = ("header", "Authorization", "Bearer ")
K = ("header", "x-api-key", "")
# --- LLM-роутеры и вендоры текста
reg("openai", "https://api.openai.com/v1/models", B, cat="text")
reg("anthropic", "https://api.anthropic.com/v1/models", K, cat="text",
    headers={"anthropic-version": "2023-06-01"})
reg("google", "https://generativelanguage.googleapis.com/v1beta/models", ("query", "key"),
    cat="text/vision/audio", note="gemini: массовые ключи, частый 429", dead=(400, 401, 403),
    body_bad=r'API key not valid|API_KEY_INVALID',
    credits_bad=r'Quota exceeded|RESOURCE_EXHAUSTED|rate ?limit',
    deep={"url": "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={value}",
          "method": "POST", "body": {"contents": [{"parts": [{"text": "ok"}]}]},
          "auth": ("none",), "ok": (200,), "dead": (400, 401, 403)})
reg("groq", "https://api.groq.com/openai/v1/models", B, cat="text/audio",
    alt=["https://api.groq.com/openai/v1/chat/completions"])
reg("deepseek", "https://api.deepseek.com/models", B, cat="text")
reg("mistral", "https://api.mistral.ai/v1/models", B, cat="text/embed")
reg("cohere", "https://api.cohere.com/v1/models", B, cat="text/embed/rerank")
reg("xai", "https://api.x.ai/v1/models", B, cat="text")
reg("together", "https://api.together.xyz/v1/models", B, cat="text/video")
reg("fireworks", "https://api.fireworks.ai/inference/v1/models", B, cat="text")
reg("cerebras", "https://api.cerebras.ai/v1/models", B, cat="text",
    alt=["https://api.cerebras.ai/v1/chat/completions"])
reg("sambanova", "https://api.sambanova.ai/v1/models", B, cat="text",
    deep={"url": "https://api.sambanova.ai/v1/chat/completions", "method": "POST", "body": {'model': 'Meta-Llama-3.1-8B-Instruct', 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 1}, "auth": B, "ok": (200,), "dead": (401, 403)})
reg("novita", "https://api.novita.ai/v3/openai/models", B, cat="text/video",
    deep={"url": "https://api.novita.ai/v3/openai/chat/completions", "method": "POST", "body": {'model': 'meta-llama/llama-3.1-8b-instruct', 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 1}, "auth": B, "ok": (200,), "dead": (401, 403)})
reg("hyperbolic", "https://api.hyperbolic.xyz/v1/models", B, cat="text/image")
reg("nebius", "https://api.studio.nebius.ai/v1/models", B, cat="text")
reg("siliconflow", "https://api.siliconflow.cn/v1/models", B, cat="text/image")
reg("moonshot", "https://api.moonshot.cn/v1/models", B, cat="text")
reg("zai", "https://api.z.ai/api/paas/v4/models", B, cat="text")
reg("dashscope", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/models", B,
    cat="text/video/audio", note="Qwen/wan — видео и аудио",
    alt=["https://dashscope.aliyuncs.com/compatible-mode/v1/models",
         "https://dashscope-intl.aliyuncs.com/api/v1/models"])
reg("volcengine", "https://ark.cn-beijing.volces.com/api/v3/models", B,
    cat="text/video", note="Ark/Seedance — видео")
reg("openrouter", "https://openrouter.ai/api/v1/key", B, cat="router")
reg("perplexity", "https://api.perplexity.ai/models", B, cat="search/text")
reg("aimlapi", "https://api.aimlapi.com/v1/models", B, cat="router/video",
    deep={"url": "https://api.aimlapi.com/v1/chat/completions", "method": "POST", "body": {'model': 'gpt-4o-mini', 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 1}, "auth": B, "ok": (200,), "dead": (401, 403)})
reg("llmtr", "https://api.llmtr.com/v1/models", B, cat="router")
reg("nvidia", "https://integrate.api.nvidia.com/v1/models", B, cat="text",
    body_bad=r'"status"\s*:\s*401|Unauthorized|Invalid JWT',
    deep={"url": "https://integrate.api.nvidia.com/v1/chat/completions", "method": "POST", "body": {'model': 'mistralai/mistral-large-2-instruct', 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 1}, "auth": B, "ok": (200,), "dead": (401, 403)})
reg("upstage", "https://api.upstage.ai/v1/solar/models", B, cat="text")
reg("venice", "https://api.venice.ai/api/v1/models", B, cat="text/image",
    deep={"url": "https://api.venice.ai/api/v1/chat/completions", "method": "POST", "body": {'model': 'llama-3.1-8b', 'messages': [{'role': 'user', 'content': 'hi'}], 'max_tokens': 1}, "auth": B, "ok": (200,), "dead": (401, 403)})
reg("longcat", "https://api.longcat.chat/openai/v1/models", B, cat="text")
# --- видео/аудио/картинки
reg("replicate", "https://api.replicate.com/v1/account", B, cat="video/image/audio")
reg("fal", "https://api.fal.ai/v1/models", ("header", "Authorization", "Key "),
    cat="video/image/audio", note="/models публичный -> подтверждаем fal.run",
    deep={"url": "https://fal.run/fal-ai/any-llm", "method": "POST",
          "body": {"prompt": "hi", "system_prompt": "be brief"},
          "auth": ("header", "Authorization", "Key "), "ok": (200,), "dead": (401, 403)})
reg("wavespeed", "https://llm.wavespeed.ai/v1/models", B, cat="video/image/llm",
    note="LLM-эндпоинт (api.wavespeed.ai/api/v1/models -> 404)",
    credits_bad=r"Insufficient credits|balance_not_enough|balance is not enough",
    deep={"url": "https://llm.wavespeed.ai/v1/chat/completions", "method": "POST",
          "body": {"model": "aion-labs/aion-2.0", "messages": [{"role": "user", "content": "hi"}],
                   "max_tokens": 1},
          "auth": B, "ok": (200,), "dead": (401, 403)})
reg("kie", "https://api.kie.ai/api/v1/chat/credit", B, cat="video/image",
    note="ошибку прячет в теле JSON -> смотрим body",
    body_bad=r'"code"\s*:\s*(401|402|403|500)|"msg"\s*:\s*"(unauthorized|invalid)"',
    credits_bad=r'"data"\s*:\s*-\d',
    deep={"url": "https://api.kie.ai/api/v1/chat/completions", "method": "POST",
          "body": {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}],
                   "max_tokens": 1}, "auth": B, "ok": (200,), "dead": (401, 403)})
reg("apimart", "https://api.apimart.ai/v1/models", B, cat="video/image")
reg("aihubmix", "https://aihubmix.com/v1/models", B, cat="text/image/video/audio",
    note="агрегатор: /models публичен (200 на мусор) -> только deep",
    deep={"url": "https://aihubmix.com/v1/chat/completions", "method": "POST",
          "body": {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}],
                   "max_tokens": 1}, "auth": B, "ok": (200,), "dead": (401, 403)})
reg("infomaniak", "https://api.infomaniak.com/1/ai/models", B, cat="text/embed",
    body_bad=r'not_authorized|"result"\s*:\s*"error"')
reg("salad-cloud", "https://api.salad.com/api/public/v1/organizations", B, cat="infra/text",
    note="SaladCloud: бесплатные GPU-квоты, годится как дом-крон",
    body_bad=r'"status"\s*:\s*40[13]|Unauthorized')

reg("elevenlabs", "https://api.elevenlabs.io/v1/user", ("header", "xi-api-key", ""),
    cat="audio")
reg("deepgram", "https://api.deepgram.com/v1/projects", ("header", "Authorization", "Token "),
    cat="audio")
reg("assemblyai", "https://api.assemblyai.com/v2/account", ("header", "authorization", ""),
    cat="audio")
reg("minimax", "https://api.minimax.chat/v1/models", B, cat="text/video/audio",
    note="эндпоинт зависит от группы (chat vs video)",
    alt=["https://api.minimaxi.chat/v1/models",
         "https://api.minimax.chat/v1/text/chatcompletion_v2"])
reg("heygen", "https://api.heygen.com/v2/user/me", ("header", "x-api-key", ""), cat="video")
reg("luma", "https://api.lumalabs.ai/dream-machine/v1/credits", B, cat="video")
reg("runway", "https://api.dev.runwayml.com/v1/organization", B, cat="video",
    headers={"X-Runway-Version": "2024-11-06"})
# --- поиск / OSINT / агенты
reg("exa", "https://api.exa.ai/search", ("header", "x-api-key", ""), cat="search/osint",
    method="POST", body={"query": "test", "numResults": 1}, note="нейросетевой поиск")
reg("tavily", "https://api.tavily.com/search", ("json", "api_key"), cat="search/osint",
    method="POST", body={"query": "test", "max_results": 1})
reg("brave", "https://api.search.brave.com/res/v1/web/search?q=test",
    ("header", "X-Subscription-Token", ""), cat="search/osint")
reg("serper", "https://google.serper.dev/search", ("header", "X-API-KEY", ""),
    cat="search/osint", method="POST", body={"q": "test"})
reg("jina", "https://api.jina.ai/v1/models", B, cat="search/embed/rerank",
    alt=["https://api.jina.ai/v1/embeddings"],
    note="/models публичный -> подтверждаем эмбеддингом",
    deep={"url": "https://api.jina.ai/v1/embeddings", "method": "POST",
          "body": {"model": "jina-embeddings-v3", "input": ["hi"]},
          "auth": B, "ok": (200,), "dead": (401, 403)})
reg("firecrawl", "https://api.firecrawl.dev/v1/team/credit-usage", B, cat="search/osint",
    note="эндпоинт может отличаться")
reg("browserbase", "https://api.browserbase.com/v1/projects", ("header", "x-bb-api-key", ""),
    cat="agent")
reg("e2b", "https://api.e2b.dev/sandboxes", ("header", "X-API-KEY", ""), cat="agent",
    note="эндпоинт может отличаться")
reg("composio", "https://backend.composio.dev/api/v1/client/auth/client_info",
    ("header", "x-api-key", ""), cat="agent", note="эндпоинт может отличаться")
reg("langfuse", "https://cloud.langfuse.com/api/public/projects", ("basic", "pair"),
    cat="agent/observability", note="нужна пара public:secret")
reg("langsmith", "https://api.smith.langchain.com/api/v1/workspaces", ("header", "x-api-key", ""),
    cat="agent/observability", note="эндпоинт может отличаться")
reg("helicone", "https://api.helicone.ai/v1/user", B, cat="agent/observability",
    note="эндпоинт может отличаться")
# --- инфра / хранилища / прочее
reg("huggingface", "https://huggingface.co/api/whoami-v2", B, cat="text/vision/infra",
    alt=["https://huggingface.co/api/models?limit=1"])
reg("github", "https://api.github.com/user", B, cat="infra")
reg("gitlab", "https://gitlab.com/api/v4/user", ("header", "PRIVATE-TOKEN", ""), cat="infra")
reg("airtable", "https://api.airtable.com/v0/meta/whoami", B, cat="agent")
reg("notion", "https://api.notion.com/v1/users/me", B, cat="agent",
    headers={"Notion-Version": "2022-06-28"})
reg("slack", "https://slack.com/api/auth.test", B,
    body_bad=r'"ok"\s*:\s*false', cat="agent", method="POST", body={},
    deep={"url": "https://slack.com/api/auth.test", "method": "GET", "body": None, "auth": B, "ok": (200,), "dead": (401, 403)})
reg("discord", "https://discord.com/api/v10/users/@me", ("header", "Authorization", "Bot "),
    cat="agent")
reg("telegram", "https://api.telegram.org/bot{value}/getMe", ("none",), cat="agent")
reg("sendgrid", "https://api.sendgrid.com/v3/scopes", B, cat="infra")
reg("resend", "https://api.resend.com/api-keys", B, cat="infra")
reg("postmark", "https://api.postmarkapp.com/server",
    ("header", "X-Postmark-Server-Token", ""), cat="infra")
reg("supabase", "https://api.supabase.com/v1/projects", B, cat="infra")
reg("vercel", "https://api.vercel.com/v2/user", B, cat="infra")
reg("netlify", "https://api.netlify.com/api/v1/user", B, cat="infra")
reg("cloudflare", "https://api.cloudflare.com/client/v4/user/tokens/verify", B, cat="infra")
reg("digitalocean", "https://api.digitalocean.com/v2/account", B, cat="infra")
reg("stripe", "https://api.stripe.com/v1/balance", B, cat="infra")
reg("mapbox", "https://api.mapbox.com/tokens/v2", ("query", "access_token",
    "?access_token={value}"), cat="infra",
    deep={"url": "https://api.mapbox.com/geocoding/v5/mapbox.places/London.json?access_token={value}&limit=1",
          "method": "GET", "body": None, "auth": ("none",), "ok": (200,), "dead": (401, 403)})
reg("pinecone", "https://api.pinecone.io/indexes", ("header", "Api-Key", ""), cat="embed")
reg("weaviate", "https://{value}/v1/.well-known/ready", ("none",), cat="embed",
    kind="endpoint", note="нужен свой host")
# --- платформы-«дома» для копий (дают бесплатный хостинг/cron)
reg("codeberg", "https://codeberg.org/api/v1/user", ("header", "Authorization", "token "),
    cat="infra/home", note="Forgejo: даёт Actions для OSS")
reg("deno", "https://api.deno.com/v1/organizations", ("header", "Authorization", "Bearer "),
    cat="infra/home", note="Deno Deploy: 100k req/день, идеален как A2A-релей",
    alt=["https://api.deno.com/v1/projects"])
reg("netlify", "https://api.netlify.com/api/v1/accounts", B, cat="infra/home")
reg("render", "https://api.render.com/v1/owners", B, cat="infra/home")
reg("fly", "https://api.machines.dev/v1/apps", B, cat="infra/home",
    note="нужен org-slug в пути для части вызовов")
reg("koyeb", "https://app.koyeb.com/v1/apps", B, cat="infra/home")
reg("railway", "https://backboard.railway.app/graphql/v2", ("header", "Authorization", "Bearer "),
    cat="infra/home", note="GraphQL: POST {me{...}}")
reg("pythonanywhere", "https://www.pythonanywhere.com/api/v0/user/{value}/",
    ("none",), cat="infra/home", kind="endpoint", note="в URL подставляется имя пользователя")
reg("huggingface-token", "https://huggingface.co/api/whoami-v2",
    ("header", "Authorization", "Bearer "), cat="infra/home",
    note="hf_ токен: Spaces + Inference API")
reg("cloudflare-token", "https://api.cloudflare.com/client/v4/user/tokens/verify", B,
    cat="infra/home", note="CF API Token (не глобальный ключ): Workers + cron")
reg("supabase-pat", "https://api.supabase.com/v1/projects", B, cat="infra/home")
reg("vercel-token", "https://api.vercel.com/v2/user", B, cat="infra/home")
reg("gitlab-pat", "https://gitlab.com/api/v4/user", ("header", "PRIVATE-TOKEN", ""),
    cat="infra/home", note="glpat-: CI + schedules")
reg("northflank", "https://api.northflank.com/v1/projects",
    ("header", "Authorization", "APIKEY "), cat="infra/home")
reg("pipedream", "https://api.pipedream.com/v1/users/me", B, cat="infra/home")
reg("valtown", "https://api.val.town/v1/me", B, cat="infra/home", note="cron + KV в JS")
reg("neon", "https://console.neon.tech/api/v2/projects", B, cat="infra/home")
reg("appwrite", "https://cloud.appwrite.io/v1/account", ("header", "X-Appwrite-Key", ""),
    cat="infra/home")


# --- облака
reg("aws", "https://sts.amazonaws.com/", ("sigv4", "sts"), cat="text/video/embed",
    kind="pair", method="POST",
    body="Action=GetCallerIdentity&Version=2011-06-15",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    note="нужна пара access+secret (bedrock/aws)")
reg("azure", "https://management.azure.com/subscriptions?api-version=2020-01-01", B,
    cat="text/video", kind="endpoint", note="нужен свой endpoint/ресурс (Azure OpenAI)")

PRIORITY = ["deepinfra", "exa", "azure", "aws", "bedrock", "wavespeed", "kie", "apimart",
            "fal", "replicate", "dashscope", "volcengine", "elevenlabs", "deepgram",
            "assemblyai", "browserbase", "e2b", "composio", "jina", "firecrawl",
            "perplexity", "cerebras", "sambanova", "novita", "hyperbolic", "nebius",
            "siliconflow", "together", "fireworks", "groq", "mistral", "cohere", "xai"]
# deepinfra не зарегистрирован выше — добавляем (OpenAI-совместимый, есть embed+видео)
reg("deepinfra", "https://api.deepinfra.com/v1/openai/models", B, cat="text/embed/image",
    note="/models публичный -> подтверждаем чатом",
    deep={"url": "https://api.deepinfra.com/v1/openai/chat/completions", "method": "POST",
          "body": {"model": "meta-llama/Meta-Llama-3.1-8B-Instruct",
                   "messages": [{"role": "user", "content": "hi"}], "max_tokens": 1},
          "auth": B, "ok": (200,), "dead": (401, 403)})


# ---------------------------------------------------------------- авто-чекеры
def load_generated() -> int:
    """Подтянуть чекеры, сгенерированные из models.dev (autocheckers.py).

    Формат на диске: JSON с url/auth(list)/deep(list-auth). Приводим к внутреннему
    виду. Такие чекеры помечаем source=models.dev — чтобы в отчёте было видно,
    что ключ проверен по каталогу, а не вручную.
    """
    fp = ROOT / "checkers_generated.json"
    if not fp.exists():
        return 0
    try:
        gen = json.loads(fp.read_text()).get("checkers", {})
    except Exception:  # noqa: BLE001
        return 0
    n = 0
    for pid, spec in gen.items():
        if pid in CHECKS:
            continue
        deep = None
        if spec.get("deep"):
            d = spec["deep"]
            deep = {"url": d["url"], "method": d["method"], "body": d.get("body"),
                    "auth": tuple(d.get("auth") or ("header", "Authorization", "Bearer ")),
                    "ok": tuple(d.get("ok") or (200,)), "dead": tuple(d.get("dead") or (401, 403))}
        CHECKS[pid] = {"url": spec["url"],
                       "auth": tuple(spec.get("auth") or ("header", "Authorization", "Bearer ")),
                       "ok": tuple(spec.get("ok") or (200,)),
                       "cat": spec.get("cat", "text"), "note": spec.get("note", "auto"),
                       "kind": "single", "method": spec.get("method", "GET"), "body": None,
                       "headers": {}, "dead": tuple(spec.get("dead") or (401, 403)),
                       "deep": deep, "body_ok": None, "body_bad": None,
                       "credits_bad": None, "alt": [], "env": spec.get("env", []),
                       "source": "models.dev"}
        n += 1
    return n


GENERATED_LOADED = load_generated()

# ---------------------------------------------------------------- env-карта
def _apply_envmap() -> int:
    """Дополнить поле `env` из tools/envmap.py.

    У 189 из 281 сервиса поле env пустое, причём у ВСЕХ приоритетных (deepinfra, exa,
    azure, groq, cerebras, jina, firecrawl…). Из-за этого конвейер молча выбрасывал
    находки по этим именам (дорк EXA_API_KEY: 12 находок → 0 проверок).
    """
    try:
        import envmap as _E
    except Exception:  # noqa: BLE001
        try:
            import importlib.util as _u
            _fp = Path(__file__).resolve().parent / "envmap.py"
            _sp = _u.spec_from_file_location("envmap", _fp)
            _E = _u.module_from_spec(_sp)
            _sp.loader.exec_module(_E)
        except Exception:  # noqa: BLE001
            return 0
    n = 0
    for env, svc in _E.ENV2SERVICE.items():
        spec = CHECKS.get(svc)
        if not spec:
            continue
        cur = list(spec.get("env") or [])
        if env not in cur:
            cur.append(env)
            spec["env"] = cur
            n += 1
    return n


ENVMAP_ADDED = _apply_envmap()



# ---------------------------------------------------------------- авторизация
def _sigv4(access: str, secret: str, region: str = "us-east-1", service: str = "sts",
           host: str = "sts.amazonaws.com", body: str = "Action=GetCallerIdentity&Version=2011-06-15",
           method: str = "POST"):
    """Минимальная подпись AWS SigV4 — чтобы проверять bedrock/aws-пары без boto3."""
    t = datetime.now(timezone.utc)
    amzdate = t.strftime("%Y%m%dT%H%M%SZ")
    datestamp = t.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canonical_headers = (f"content-type:application/x-www-form-urlencoded\nhost:{host}\n"
                         f"x-amz-date:{amzdate}\n")
    signed = "content-type;host;x-amz-date"
    canonical = "\n".join([method, "/", "", canonical_headers, signed, payload_hash])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                     hashlib.sha256(canonical.encode()).hexdigest()])
    def _h(k, m): return hmac.new(k, m.encode(), hashlib.sha256).digest()
    key = _h(_h(_h(_h(("AWS4" + secret).encode(), datestamp), region), service), "aws4_request")
    sig = hmac.new(key, sts.encode(), hashlib.sha256).hexdigest()
    return {
        "Authorization": (f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
                          f"SignedHeaders={signed}, Signature={sig}"),
        "x-amz-date": amzdate, "Content-Type": "application/x-www-form-urlencoded",
    }


def _build(spec: dict, value: str, extra: dict | None):
    """Вернуть (url, headers, body_bytes, error)."""
    extra = extra or {}
    url = spec["url"]
    headers = {"User-Agent": UA, "Accept": "application/json", **spec["headers"]}
    auth = spec["auth"]
    body = spec["body"]
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
        headers.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        body = body.encode()
    if auth[0] == "none":
        url = url.replace("{value}", value)
    elif auth[0] == "query":
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{auth[1]}={urllib.parse.quote(value)}"
    elif auth[0] == "header":
        headers[auth[1]] = f"{auth[2]}{value}"
    elif auth[0] == "json":
        if isinstance(body, bytes):
            d = json.loads(body.decode())
        else:
            d = {}
        d[auth[1]] = value
        body = json.dumps(d).encode()
        headers.setdefault("Content-Type", "application/json")
    elif auth[0] == "basic":
        pk, sk = extra.get("public"), value
        if not pk:
            return None, None, None, "pair-required: нужен public-ключ"
        headers["Authorization"] = "Basic " + base64.b64encode(f"{pk}:{sk}".encode()).decode()
    elif auth[0] == "sigv4":
        sec = extra.get("secret")
        if not sec:
            return None, None, None, "pair-required: нужен secret"
        headers.update(_sigv4(value, sec, extra.get("region", "us-east-1")))
    return url, headers, body, None


def check_one(service: str, value: str, extra: dict | None = None, guard=None,
              timeout: float = 12.0) -> dict:
    spec = CHECKS.get(service)
    if not spec:
        return {"status": "no-checker", "http": None, "note": "нет чекера"}
    url, headers, body, err = _build(spec, value, extra)
    if err:
        return {"status": "pair-required", "http": None, "note": err, "cat": spec["cat"]}
    if spec["kind"] == "endpoint" and "{value}" in spec["url"]:
        pass
    req = urllib.request.Request(url, data=body, headers=headers, method=spec["method"])
    t0 = time.time()
    via = "direct"
    try:
        if guard is not None and spec["kind"] != "endpoint" and spec["method"] == "GET":
            st, raw, meta = guard.get(url, timeout=timeout)  # прокси-первым (только GET)
            via = meta.get("via", "direct")
            code = st
            txt = raw.decode("utf-8", "replace")
        else:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                code = r.status
                txt = r.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        code = e.code
        try:
            txt = e.read(2000).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            txt = ""
    except Exception as e:  # noqa: BLE001
        return {"status": "unknown", "http": None, "note": f"network: {type(e).__name__}",
                "cat": spec["cat"], "via": via, "sec": round(time.time() - t0, 1)}
    # 404/405 на основном эндпоинте -> пробуем альтернативные (CN/intl, иные версии API)
    if code in (404, 405) and spec.get("alt"):
        for a in spec["alt"]:
            aspec = dict(spec)
            aspec["url"] = a
            aspec["alt"] = []
            u2, h2, b2, e2 = _build(aspec, value, extra)
            if e2:
                continue
            try:
                with urllib.request.urlopen(urllib.request.Request(
                        u2, data=b2, headers=h2, method=spec["method"]), timeout=timeout) as r2:
                    code = r2.status
                    txt = r2.read(4000).decode("utf-8", "replace")
                    url = a
            except urllib.error.HTTPError as e3:
                code = e3.code
                try:
                    txt = e3.read(2000).decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    txt = ""
                url = a
            except Exception:  # noqa: BLE001
                continue
            if code in spec["ok"] or code in spec["dead"]:
                break
    status = "alive" if code in spec["ok"] else ("dead" if code in spec["dead"] else "unknown")
    if status == "alive" and spec.get("credits_bad") and re.search(spec["credits_bad"], txt or ""):
        status = "valid-no-credits"   # ключ принят, но баланс пуст
    elif status == "alive" and spec.get("body_bad") and re.search(spec["body_bad"], txt or ""):
        status = "dead"          # 200, но в теле — ошибка авторизации
    elif code == 429:
        status = "rate-limited"  # транзиентно: НЕ считаем ключ мёртвым
    if status == "alive" and spec.get("deep"):
        d = dict(spec["deep"])
        dspec = {"url": d["url"], "auth": d["auth"], "ok": d["ok"], "dead": d["dead"],
                 "cat": spec["cat"], "kind": "single", "method": d["method"],
                 "body": d.get("body"), "headers": {}, "note": "deep"}
        _u, _h, _b, _e = _build(dspec, value, extra)
        try:
            _r = urllib.request.Request(_u, data=_b, headers=_h, method=dspec["method"])
            with urllib.request.urlopen(_r, timeout=timeout) as _resp:
                _c = _resp.status
        except urllib.error.HTTPError as _e2:
            _c = _e2.code
        except Exception:  # noqa: BLE001
            _c = None
        if _c in dspec["ok"]:
            status = "alive"
        elif _c == 403 and spec.get("credits_bad"):
            status = "valid-no-credits"
        elif _c in dspec["dead"]:
            status = "dead"
        elif _c == 429:
            # сервис ответил «слишком много запросов» — мусорный ключ так не отвечает,
            # значит ключ ВАЛИДЕН, просто исчерпана минутная квота
            status = "valid-no-credits"
        else:
            status = "weak-alive"   # /models дал 200, но подтвердить не удалось
        return {"status": status, "http": code, "deep_http": _c, "cat": spec["cat"],
                "via": via, "sec": round(time.time() - t0, 1), "note": spec["note"],
                "body": (txt or "")[:200].replace("\n", " ")}
    if status == "alive" and _discriminates(service) is False:
        status = "weak-alive"   # 200, но эндпоинт публичный: валидность НЕ доказана
    return {"status": status, "http": code, "cat": spec["cat"], "via": via,
            "sec": round(time.time() - t0, 1), "note": spec["note"],
            "body": txt[:200].replace("\n", " ")}


CALIB = ROOT / "checker-calibration.json"


def calibrate(workers: int = 6, use_proxy: bool = True) -> dict:
    """Проверить, РАЗЛИЧАЕТ ли эндпоинт валидный ключ от мусора.

    200 на мусорном ключе = публичный эндпоинт (fal /v1/models, jina /v1/models) —
    такой чекер НЕ доказывает валидность. Это защита от ложных ответов.
    """
    guard = None
    if use_proxy:
        try:
            sys.path.insert(0, str(ROOT))
            import proxy_guard as pg
            guard = pg.Guard()
        except Exception:  # noqa: BLE001
            guard = None
    garbage = "__secrethunter_invalid_key__"
    res = {}

    only = os.environ.get("CALIB_ONLY")
    items = sorted(CHECKS.items())
    if only:
        want = set(only.split(","))
        items = [(k, v) for k, v in items if k in want]

    def job(item):
        svc, spec = item
        extra = {"secret": garbage, "public": garbage}
        r = check_one(svc, garbage, extra, guard, timeout=6)
        return svc, r

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for svc, r in ex.map(job, items):
            disc = r.get("http") not in CHECKS[svc]["ok"]  # 200 на мусор = публичный эндпоинт
            res[svc] = {"garbage_http": r.get("http"), "garbage_status": r["status"],
                        "discriminates": disc, "cat": CHECKS[svc]["cat"]}
            flag = "OK-различает" if disc else "!! ПУБЛИЧНЫЙ (200 на мусор)"
            print(f"  {svc:<14} {str(r.get('http')):>5} {flag}")
    CALIB.write_text(json.dumps({"generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                 "note": "discriminates=false => чекер не доказывает валидность",
                                 "checkers": res}, ensure_ascii=False, indent=1))
    pub = [k for k, v in res.items() if not v["discriminates"]]
    print(f"[calibrate] публичных (не различают): {len(pub)} -> {pub}")
    return res


def _discriminates(service: str) -> bool | None:
    if not CALIB.exists():
        return None
    c = json.loads(CALIB.read_text())["checkers"].get(service)
    return None if c is None else c["discriminates"]


def _priority_key(rec: dict) -> int:
    s = (rec.get("service") or "").lower()
    return PRIORITY.index(s) if s in PRIORITY else len(PRIORITY) + 1


def verify(limit: int = 60, services: list[str] | None = None, workers: int = 6,
           use_proxy: bool = True, only_status=("unverified", "unknown", "placeholder")):
    guard = None
    if use_proxy:
        try:
            sys.path.insert(0, str(ROOT))
            import proxy_guard as pg
            guard = pg.Guard()
            print(f"[proxy] pool={len(guard.good)} real_ip={guard.real_ip}")
        except Exception as e:  # noqa: BLE001
            print(f"[proxy] недоступен ({e}) — идём напрямую")
    recs = json.loads(KEYS.read_text())
    KEYS.with_suffix(".pre-verify.json").write_text(json.dumps(recs, ensure_ascii=False, indent=1))
    todo, seen = [], set()
    for r in sorted(recs, key=_priority_key):
        s = (r.get("service") or "").lower()
        if s not in CHECKS:
            continue
        if services and s not in services:
            continue
        if r.get("status") not in only_status and r.get("status") not in ("alive", "weak-alive"):
            continue
        v = r.get("value")
        if not v or (s, v) in seen:
            continue
        seen.add((s, v))
        todo.append(r)
        if len(todo) >= limit:
            break
    print(f"[verify] к проверке: {len(todo)} (лимит {limit}, воркеров {workers})")
    out = []

    def _job(r):
        res = check_one((r.get("service") or "").lower(), r["value"], r.get("extra"), guard)
        return r, res

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r, res in ex.map(_job, todo):
            r.update({"status": res["status"], "http": res.get("http"),
                      "checker": "checkers.py", "verified_at": time.strftime("%Y-%m-%d"),
                      "checker_note": res.get("note", ""), "via": res.get("via", "direct")})
            out.append({**{k: r.get(k) for k in ("service", "value", "repo", "file")}, **res})
            print(f"  {res['status']:>13} {str(res.get('http')):>4} {r.get('service'):<14} "
                  f"{r['value'][:26]:<26} {res.get('note','')[:34]}")
    KEYS.write_text(json.dumps(recs, ensure_ascii=False, indent=1))
    with REPORT.open("a") as f:
        for o in out:
            f.write(json.dumps(o, ensure_ascii=False) + "\n")
    with VALID.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["service", "category", "status", "value_masked", "repo", "file", "via"])
        for r in recs:
            if r.get("status") == "alive":
                v = r.get("value", "")
                w.writerow([r.get("service"), r.get("category"), "alive",
                            v[:8] + "…" + v[-4:], r.get("repo"), r.get("file"), r.get("via")])
    from collections import Counter
    c = Counter(o["status"] for o in out)
    print(f"[verify] итог: {dict(c)} | alive всего в базе: "
          f"{sum(1 for r in recs if r.get('status')=='alive')}")
    return recs


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    if cmd == "list":
        print(f"чекеров: {len(CHECKS)}")
        for s, spec in sorted(CHECKS.items()):
            print(f"  {s:<14} {spec['cat']:<22} {spec['kind']:<9} {spec['url'][:60]}")
    elif cmd == "calibrate":
        calibrate()
    elif cmd == "verify":
        lim, svcs = 60, None
        if "--limit" in sys.argv:
            lim = int(sys.argv[sys.argv.index("--limit") + 1])
        if "--services" in sys.argv:
            svcs = sys.argv[sys.argv.index("--services") + 1].split(",")
        verify(limit=lim, services=svcs)
    else:
        print(__doc__)
