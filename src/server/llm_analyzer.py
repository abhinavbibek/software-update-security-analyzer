# src/server/llm_analyzer.py
import os
import json
import time
import logging
from datetime import datetime
import httpx
from dotenv import load_dotenv
from src.server.utils import ensure_dir
import socket
import urllib.parse

load_dotenv()
logger = logging.getLogger("llm_analyzer")

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

# Large-context endpoint (OpenAI-compatible)
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Best JSON-analysis + large-context model
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "deepseek/deepseek-chat")

MAX_RETRIES = 3


async def run_llm_analysis(v1_dir: str, v2_dir: str):
    """Read FULL baseline_inventory.json files and request file-level forensic analysis."""

    ensure_dir("reports")

    # Use baseline_inventory.json instead of deep_analysis.json
    v1_json = os.path.join(v1_dir, "baseline_inventory.json")
    v2_json = os.path.join(v2_dir, "baseline_inventory.json")

    if not os.path.exists(v1_json) or not os.path.exists(v2_json):
        raise FileNotFoundError("baseline_inventory.json missing in one or both versions.")

    with open(v1_json, "r", encoding="utf-8") as f:
        v1_data = json.load(f)

    with open(v2_json, "r", encoding="utf-8") as f:
        v2_data = json.load(f)

    combined = {
        "meta": {
            "generated": datetime.utcnow().isoformat() + "Z",
            "old_version": os.path.basename(os.path.dirname(v1_dir)),
            "new_version": os.path.basename(os.path.dirname(v2_dir)),
        },
        "old": v1_data,
        "new": v2_data,
    }

    # ------------------------------------------------------------
    # NEW: High-quality malware analyst prompt w/ file-level detail
    # ------------------------------------------------------------
    prompt = (
        "You are a senior malware reverse engineer.\n"
        "You are given TWO full JSON inventories extracted from two versions of a software product.\n"
        "Each JSON fully describes files, hashes, directories, entropy, size, metadata, imports, modules, etc.\n\n"

        "Your job is:\n"
        "1. Compare every file between the OLD and NEW versions.\n"
        "2. Identify changes in: file size, entropy, hash, path, metadata, signatures, modules, imports, behaviors.\n"
        "3. Highlight new files, removed files, and modified files.\n"
        "4. For modified files, include a per-file DIFF-STYLE explanation.\n"
        "5. Identify suspicious indicators related to malware (IOCs, persistence, privilege escalation, embedded resources).\n"
        "6. Provide a risk assessment.\n\n"

        "Return output strictly in Markdown with EXACT sections:\n\n"
        "## Modified Files (with per-file analysis)\n"
        "## New Files\n"
        "## Removed Files\n"
        "## New or Changed IOCs\n"
        "## Behavioral Changes\n"
        "## Digital Signature Changes\n"
        "## Version-wide Security Impact\n"
        "## Final Risk Assessment\n"
        "## Recommended Remediation Steps\n\n"

        "Be extremely detailed. Do not skip any file.\n"
        "Do not summarize to short text. Use bullet points and sub-sections.\n"
    )

    # Final content sent to DeepSeek
    content_text = prompt + "\n\nFULL JSON INVENTORY DATA:\n" + json.dumps(combined, indent=2)

    payload = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": "You are a malware analysis and digital forensics expert."},
            {"role": "user", "content": content_text}
        ],
        "max_tokens": 8000,
        "temperature": 0.0
    }

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }

    if not OPENROUTER_API_KEY:
        raise RuntimeError("OPENROUTER_API_KEY is missing in .env")

    # -----------------------------
    # DNS sanity check before POST
    # -----------------------------
    def _check_dns(url):
        try:
            host = urllib.parse.urlparse(url).hostname
            socket.getaddrinfo(host, 443)
            return True
        except Exception as e:
            logger.error(f"DNS resolution failed for {url}: {e}")
            return False

    if not _check_dns(OPENROUTER_URL):
        raise RuntimeError("DNS resolution failed for OpenRouter URL.")

    # -----------------------------
    # Perform request with retries
    # -----------------------------
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=180) as client:
                resp = await client.post(OPENROUTER_URL, headers=headers, json=payload)

            if resp.status_code in (200, 201):
                data = resp.json()
                md_output = None

                if "choices" in data and len(data["choices"]) > 0:
                    msg = data["choices"][0]
                    if "message" in msg and isinstance(msg["message"], dict):
                        md_output = msg["message"].get("content")
                    elif "text" in msg:
                        md_output = msg["text"]

                if not md_output:
                    md_output = json.dumps(data, indent=2)

                # Save report
                out_dir = os.path.dirname(v1_dir)
                md_path = os.path.join(out_dir, "ai_report.md")
                with open(md_path, "w", encoding="utf-8") as f:
                    f.write(md_output)

                logger.info(f"DeepSeek LLM analysis written to {md_path}")
                return {"ai_report_path": md_path, "md": md_output}

            last_err = f"{resp.status_code}: {resp.text}"
            logger.error(f"LLM API error: {last_err}")

        except Exception as e:
            last_err = e
            logger.warning(f"Attempt {attempt} failed: {e}")

        time.sleep(2 ** attempt)

    raise RuntimeError(f"LLM analysis failed after {MAX_RETRIES} retries. Last error: {last_err}")
