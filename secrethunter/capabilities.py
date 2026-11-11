#!/usr/bin/env python3
"""capabilities.py — «разборка»: что умеет каждый API, который мы проверяем.

Источник возможностей — каталог models.dev (https://models.dev/api.json):
для каждого провайдера там перечислены модели и их модальности
(in:text, out:text, in:image, out:image, in:audio, out:audio, in:video, out:video,
in:pdf, tool_call, reasoning, attachment, open_weights).

Задача: по нашему реестру чекеров (284 сервиса) собрать матрицу
«сервис × что умеет», чтобы понимать, ЧТО даёт найденный ключ:
текст, видео, аудио, эмбеддинги, агенты (tool_call), файлы (pdf/attachment).

Запуск:
  python3 tools/capabilities.py report            # полная матрица
  python3 tools/capabilities.py report --live     # только по живым ключам
  python3 tools/capabilities.py gaps              # провайдеры models.dev без чекера
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import checkers as C  # noqa: E402

RAW = ROOT / "models_dev_raw.json"
OUT = ROOT / "capabilities-report.json"

# как называем возможности по-человечески
HUMAN = {
    "in:text": "принимает текст", "out:text": "генерирует текст",
    "in:image": "принимает картинки", "out:image": "генерирует картинки",
    "in:audio": "принимает аудио", "out:audio": "генерирует аудио/речь",
    "in:video": "принимает видео", "out:video": "генерирует видео",
    "in:pdf": "читает PDF", "tool_call": "вызывает инструменты (агент)",
    "reasoning": "умеет рассуждать", "attachment": "работает с файлами",
    "open_weights": "открытые веса", "embedding": "эмбеддинги",
}

# синонимы: как провайдер называется у нас и в models.dev
ALIAS = {
    "openai": "openai", "anthropic": "anthropic", "google": "google", "xai": "xai",
    "mistral": "mistral", "cohere": "cohere", "groq": "groq", "deepseek": "deepseek",
    "together": "togetherai", "fireworks": "fireworks-ai", "openrouter": "openrouter",
    "perplexity": "perplexity", "cerebras": "cerebras", "sambanova": "sambanova",
    "nvidia": "nvidia", "novita": "novita-ai", "deepinfra": "deepinfra",
    "hyperbolic": "hyperbolic", "lambda": "lambda", "baseten": "baseten",
    "anyscale": "anyscale", "replicate": "replicate", "fal": "fal",
    "elevenlabs": "elevenlabs", "minimax": "minimax", "zhipu": "zhipuai",
    "moonshot": "moonshotai", "dashscope": "alibaba", "aimlapi": "aimlapi",
    "aihubmix": "aihubmix", "infomaniak": "infomaniak", "venice": "venice",
    "requesty": "requesty", "llmgateway": "llmgateway", "edenai": "edenai",
    "kie": "kie", "apimart": "apimart", "wavespeed": "wavespeed",
    "ollama-cloud": "ollama-cloud", "zenmux": "zenmux", "ofox": "ofox",
}


def load() -> dict:
    if not RAW.exists():
        return {}
    return json.loads(RAW.read_text())


def caps_of(provider: dict) -> list[str]:
    out = set()
    for m in (provider.get("models") or {}).values():
        for c in (m.get("modalities") or {}).get("input", []):
            out.add("in:" + c)
        for c in (m.get("modalities") or {}).get("output", []):
            out.add("out:" + c)
        if m.get("tool_call"):
            out.add("tool_call")
        if m.get("reasoning"):
            out.add("reasoning")
        if m.get("attachment"):
            out.add("attachment")
        if m.get("open_weights"):
            out.add("open_weights")
        if m.get("modalities", {}).get("embedding") or m.get("embedding"):
            out.add("embedding")
    return sorted(out)


def report(live_only: bool = False) -> dict:
    cat = load()
    rows = []
    live = []
    if live_only:
        p = ROOT / "ALL-FOUND-KEYS.json"
        if p.exists():
            live = [r["service"] for r in json.loads(p.read_text())
                    if r.get("status") in ("alive", "valid-no-credits", "weak-alive")]
    for svc, spec in sorted(C.CHECKS.items()):
        if live_only and svc not in live:
            continue
        pid = ALIAS.get(svc, svc)
        prov = cat.get(pid) or {}
        caps = caps_of(prov)
        if not caps:
            # нет в models.dev — берём нашу собственную метку возможностей
            caps = [c for c in (spec.get("cat", "") or "").split("/") if c]
        rows.append({
            "service": svc,
            "models_dev_id": pid if prov else "",
            "in_catalog": bool(prov),
            "models": len(prov.get("models") or {}),
            "our_cat": spec.get("cat", ""),
            "caps": caps,
            "caps_human": [HUMAN.get(c, c) for c in caps],
        })
    found = [r for r in rows if r["in_catalog"]]
    summary = {
        "checkers": len(C.CHECKS),
        "in_models_dev": len(found),
        "with_video": [r["service"] for r in found if "out:video" in r["caps"]],
        "with_audio": [r["service"] for r in found if "out:audio" in r["caps"]],
        "with_image": [r["service"] for r in found if "out:image" in r["caps"]],
        "with_agents": [r["service"] for r in found if "tool_call" in r["caps"]],
        "with_reasoning": [r["service"] for r in found if "reasoning" in r["caps"]],
        "with_pdf": [r["service"] for r in found if "in:pdf" in r["caps"]],
    }
    return {"summary": summary, "rows": rows}


def gaps() -> list[str]:
    cat = load()
    known = set(ALIAS.values()) | set(C.CHECKS)
    return sorted(set(cat) - known)


def main() -> None:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "report"
    if cmd == "gaps":
        g = gaps()
        print(f"провайдеров models.dev без чекера: {len(g)}")
        for x in g:
            print(" ", x)
        return
    res = report("--live" in sys.argv)
    s = res["summary"]
    print(json.dumps(s, ensure_ascii=False, indent=1))
    OUT.write_text(json.dumps(res, ensure_ascii=False, indent=1))
    print(f"сохранено: {OUT} ({len(res['rows'])} строк)")


if __name__ == "__main__":
    main()
