from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

PROVIDERS = {
    "groq": {
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "env": "GROQ_API_KEY",
        "signup": "https://console.groq.com",
        "suggested_sleep": 25,
    },
    "gemini": {
        "url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "env": "GEMINI_API_KEY",
        "signup": "https://aistudio.google.com/apikey",
        "suggested_sleep": 6,
    },
    "openrouter": {
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "env": "OPENROUTER_API_KEY",
        "signup": "https://openrouter.ai/keys",
        "suggested_sleep": 4,
    },
}

MAX_RETRIES = 5
REQUEST_TIMEOUT = 300

USER_AGENT = "TACET/1.0 (research harness; +https://github.com/)"


class ProviderError(RuntimeError):
    pass


def split_model(spec: str) -> tuple[str, str]:
    """'groq:llama-3.3-70b' -> ('groq', 'llama-3.3-70b')."""
    if ":" not in spec:
        raise ProviderError(
            f"model {spec!r} needs a provider prefix, e.g. 'groq:{spec}'. "
            f"Known providers: {', '.join(PROVIDERS)}"
        )
    provider, model = spec.split(":", 1)
    if provider not in PROVIDERS:
        raise ProviderError(f"unknown provider {provider!r}. "
                            f"Known: {', '.join(PROVIDERS)}")
    return provider, model


def _key(provider: str) -> str:
    cfg = PROVIDERS[provider]
    key = os.environ.get(cfg["env"], "").strip()
    if not key:
        raise ProviderError(
            f"{cfg['env']} is not set. Get a free key at {cfg['signup']}, then:\n"
            f'    $env:{cfg["env"]} = "your-key-here"'
        )
    return key


def call(model_spec: str, prompt: str, *, max_tokens: int = 4096,
         temperature: float = 0.7, verbose: bool = False,
         max_retries: int = MAX_RETRIES, timeout: float = REQUEST_TIMEOUT) -> str:
    """
    Send one prompt, return the response text. Retries on rate limits and transient
    server errors with exponential backoff, honouring Retry-After when given.

    Temperature is 0.7 rather than 0, deliberately. The five seeds per condition are
    meant to sample the distribution of parsers a model produces, not to re-draw the
    same one. A greedy decode would collapse the seed dimension and leave you claiming
    a rate measured on effectively one parser per condition.
    """
    provider, model = split_model(model_spec)
    cfg = PROVIDERS[provider]

    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    headers = {
        "Authorization": f"Bearer {_key(provider)}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    if provider == "openrouter":
        
        headers["HTTP-Referer"] = "https://github.com/"
        headers["X-Title"] = "TACET"

    delay = 5.0
    last_error = ""
    for attempt in range(1, max_retries + 1):
        req = urllib.request.Request(cfg["url"], data=body, headers=headers,
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            return _extract_text(payload, model_spec)

        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            last_error = (f"HTTP {e.code}: {detail}" if e.code == 429
                          else f"HTTP {e.code}: {detail[:300]}")
            if e.code == 429 and verbose and attempt == 1:
                for hdr in ("retry-after", "x-ratelimit-limit-tokens",
                            "x-ratelimit-remaining-tokens",
                            "x-ratelimit-reset-tokens",
                            "x-ratelimit-limit-requests",
                            "x-ratelimit-remaining-requests",
                            "x-ratelimit-reset-requests"):
                    val = e.headers.get(hdr) if e.headers else None
                    if val:
                        print(f"      {hdr}: {val}")

            if e.code in (429, 500, 502, 503, 529):
                wait = delay
                retry_after = e.headers.get("Retry-After") if e.headers else None
                if retry_after:
                    try:
                        wait = min(max(wait, float(retry_after)), 120.0)
                    except ValueError:
                        pass
                if attempt == max_retries:
                    break
                if verbose:
                    print(f"      {e.code}, retry {attempt}/{max_retries} "
                          f"in {wait:.0f}s")
                time.sleep(wait)
                delay = min(delay * 2, 120)
                continue

            raise ProviderError(
                f"{model_spec} -> {last_error}\n"
                + ("  Check the key is valid and has not expired.\n"
                   if e.code in (401, 403) else "")
                + ("  Check the model ID still exists — free rosters change often.\n"
                   if e.code == 404 else "")
            )

        except (urllib.error.URLError, TimeoutError, OSError) as e:

            reason = str(getattr(e, "reason", e))
            is_timeout = isinstance(e, TimeoutError) or "timed out" in reason.lower()
            label = (f"TIMED OUT after {timeout:.0f}s — model too slow for this "
                     f"token budget" if is_timeout else f"connection failed ({reason[:60]})")
            last_error = f"{type(e).__name__}: {reason}"
            if attempt == max_retries:
                break
            if verbose:
                print(f"      {label}; retry {attempt}/{MAX_RETRIES} in {delay:.0f}s")
            time.sleep(delay)
            delay = min(delay * 2, 120)

    raise ProviderError(f"{model_spec} failed after {max_retries} attempts. "
                        f"Last error: {last_error}")


def _extract_text(payload: dict, model_spec: str) -> str:
    """
    Pull the assistant text out of an OpenAI-shaped response.

    Written defensively because reasoning models break the naive path in two ways.
    They may omit `content` entirely rather than returning null, and they spend the
    token budget on internal reasoning before emitting anything — so a small
    max_tokens yields a response that is structurally valid and completely empty.
    Both look like a broken model ID if the error message is not specific.
    """
    choices = payload.get("choices")
    if not choices:
        raise ProviderError(
            f"{model_spec}: response has no choices. Top-level keys: "
            f"{list(payload)[:8]}"
            + (f"\n  provider error: {payload['error']}" if "error" in payload else "")
        )

    choice = choices[0] if isinstance(choices, list) else choices
    message = choice.get("message") or choice.get("delta") or {}
    content = message.get("content")
    finish = choice.get("finish_reason") or choice.get("finishReason") or ""

    if isinstance(content, list):          # some providers return content blocks
        content = "".join(b.get("text", "") for b in content if isinstance(b, dict))

    usage = payload.get("usage", {})

    if content:
        if finish == "length":
            raise ProviderError(
                f"{model_spec}: response TRUNCATED at the token ceiling "
                f"({len(content):,} chars returned, finish_reason='length'). "
                f"Raise --max-tokens and retry; do not keep this output.\n"
                f"  usage: {usage}"
            )
        return content

    reasoning = message.get("reasoning") or message.get("reasoning_content")
    if finish == "length":
        raise ProviderError(
            f"{model_spec}: hit the token limit before producing any visible output. "
            f"This is normal for reasoning models — the budget went on internal "
            f"reasoning. Raise max_tokens.\n"
            f"  usage: {usage}"
        )
    if reasoning:
        raise ProviderError(
            f"{model_spec}: returned reasoning but no answer "
            f"({len(str(reasoning))} chars of reasoning). Raise max_tokens.\n"
            f"  usage: {usage}"
        )
    raise ProviderError(
        f"{model_spec}: empty content (finish_reason={finish!r}). Often a safety "
        f"refusal or a filtered response.\n"
        f"  message keys: {list(message)[:8]}  usage: {usage}"
    )



_NOT_TEXT_GEN = (
    "whisper", "tts", "transcribe", "audio", "orpheus", "lyria", "veo",
    "image", "nano-banana", "embedding", "prompt-guard", "safeguard",
    "content-safety", "robotics", "computer-use", "live", "omni", "aqa",
    "deep-research", "antigravity", "vl", "compound",
)


_GEMINI_FREE_HINTS = ("flash", "gemma")


def _is_text_gen(model_id: str) -> bool:
    low = model_id.lower()
    return not any(tok in low for tok in _NOT_TEXT_GEN)


def list_models(provider: str, free_only: bool = True) -> list[dict]:
    """
    Ask a provider what it actually serves right now.

    This exists because hardcoded model IDs rot. Rather than trusting any list —
    including the defaults shipped in run_tacet.py — query the provider and pick from
    what comes back today.
    """
    if provider not in PROVIDERS:
        raise ProviderError(f"unknown provider {provider!r}")
    url = PROVIDERS[provider]["url"].replace("/chat/completions", "/models")
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {_key(provider)}",
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise ProviderError(f"{provider} model list -> HTTP {e.code}: "
                            f"{e.read().decode('utf-8', 'replace')[:200]}")

    entries = payload.get("data", payload if isinstance(payload, list) else [])
    out = []
    for m in entries:
        if not isinstance(m, dict):
            continue
        mid = m.get("id") or m.get("name") or ""
        mid = mid.split("/")[-1] if provider == "gemini" else mid
        if not mid or not _is_text_gen(mid):
            continue
        pricing = m.get("pricing") or {}
        if provider == "groq":
            is_free, certain = True, True         
        elif provider == "gemini":
            is_free = any(h in mid.lower() for h in _GEMINI_FREE_HINTS)
            certain = False                        
        else:
            is_free = (mid.endswith(":free")
                       or (str(pricing.get("prompt", "1")) in ("0", "0.0")
                           and str(pricing.get("completion", "1")) in ("0", "0.0")))
            certain = True
        if free_only and not is_free:
            continue
        out.append({
            "id": mid,
            "context": m.get("context_length") or m.get("context_window") or "",
            "free": is_free,
            "certain": certain,
        })
    return sorted(out, key=lambda d: d["id"])


def show_models(providers: list[str] | None = None) -> None:
    """Print what each provider currently serves, ready to paste into MODELS."""
    providers = providers or list(PROVIDERS)
    for provider in providers:
        cfg = PROVIDERS[provider]
        print(f"\n{'=' * 72}\n{provider.upper()}   (key: {cfg['env']})\n{'=' * 72}")
        if not os.environ.get(cfg["env"], "").strip():
            print(f"  key not set — get one at {cfg['signup']}")
            continue
        try:
            models = list_models(provider)
        except ProviderError as e:
            print(f"  {e}")
            continue
        if not models:
            print("  no free models returned")
            continue
        for m in models:
            ctx = f"{m['context']:>9,}" if isinstance(m["context"], int) else " " * 9
            flag = "" if m.get("certain", True) else "   (verify pricing)"
            print(f"  {provider}:{m['id']:<52}{ctx}{flag}")
        print(f"\n  {len(models)} text-generation model(s) shown.")
        if provider == "gemini":
            print("  Gemini's listing carries no pricing. Flash/Flash-Lite/Gemma are")
            print("  the free tier; Pro bills. Confirm on Google's pricing page before")
            print("  you point a run at anything here.")


def check(models: list[str]) -> bool:
    """Verify every key and model ID with one tiny call each, before burning quota."""
    print("Checking provider access. One short call per model.\n")
    needed = sorted({split_model(m)[0] for m in models})
    ok = True

    for provider in needed:
        cfg = PROVIDERS[provider]
        present = bool(os.environ.get(cfg["env"], "").strip())
        print(f"  {cfg['env']:<22} {'set' if present else 'NOT SET  -> ' + cfg['signup']}")
        ok &= present
    print()

    if not ok:
        print("Set the missing keys, then run this again.")
        return False

    for spec in models:
        try:

            reply = call(spec, "Reply with the single word: ready",
                         max_tokens=512, temperature=0)
            text = reply.strip()
            if text:
                print(f"  {spec:<46} OK   {text[:30]!r}")
            else:
                ok = False
                print(f"  {spec:<46} WARN returned an empty string")
        except ProviderError as e:
            ok = False
            for i, line in enumerate(str(e).splitlines()[:3]):
                print(f"  {spec:<46} {'FAIL' if i == 0 else '    '} {line[:80]}"
                      if i == 0 else f"  {'':<46}      {line[:80]}")

    print()
    if ok:
        print("All models reachable. Safe to run `generate`.")
        for provider in needed:
            print(f"  suggested --sleep for {provider}: "
                  f"{PROVIDERS[provider]['suggested_sleep']}s")
    else:
        print("Fix the failures above before generating. A model ID that 404s has "
              "most likely been delisted — check the provider's live model list.")
    return ok