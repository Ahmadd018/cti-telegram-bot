#!/usr/bin/env python3
"""
CTI + AI Telegram Digest
-------------------------
Pulls:
  - High/Critical CVEs from NVD (flagging any that are in CISA's KEV list
    as actively exploited)
  - Security news from a handful of RSS feeds
  - AI/tech news from a handful of RSS feeds

...dedupes against what's already been sent, formats a digest, and pushes
it to a Telegram chat via the Bot API.

Designed to run on a schedule (see .github/workflows/digest.yml) — every
run is stateless except for state/seen_ids.json, which the workflow commits
back to the repo so duplicates aren't re-sent.
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

import feedparser
import requests

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------

# How far back to look each run. Should be a bit *longer* than your
# schedule interval so a slow run or a missed trigger doesn't lose items.
# Twice-daily digest -> 12h between runs, so we look back 18h for safety.
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "18"))

# Minimum CVSS v3 base score to include (7.0 = High threshold)
MIN_CVSS_SCORE = float(os.environ.get("MIN_CVSS_SCORE", "7.0"))

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # optional but recommended

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

SECURITY_NEWS_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "PortSwigger Research": "https://portswigger.net/research/rss",
}

# AI-dedicated feeds: everything here is included, no keyword filtering needed
AI_DEDICATED_FEEDS = {
    "OpenAI": "https://openai.com/news/rss.xml",
    "Google DeepMind": "https://deepmind.google/blog/feed/basic/",
}

# General tech feeds: only kept if they mention an AI/tech keyword below,
# since these sites cover far more than AI.
GENERAL_TECH_FEEDS = {
    "The Verge": "https://www.theverge.com/rss/index.xml",
    "Ars Technica": "https://feeds.arstechnica.com/arstechnica/index",
}
AI_KEYWORDS = [
    "openai", "anthropic", "claude", "gpt", "llm", "deepmind", "gemini",
    "chatgpt", "mistral", "meta ai", "copilot", "artificial intelligence",
    "machine learning", " ai ", "ai model", "ai chip", "nvidia",
]

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

STATE_PATH = os.path.join(os.path.dirname(__file__), "state", "seen_ids.json")
TELEGRAM_MSG_LIMIT = 3500  # stay comfortably under Telegram's 4096 char cap

HEADERS = {"User-Agent": "cti-telegram-bot/1.0 (+https://github.com/)"}

session = requests.Session()
session.headers.update(HEADERS)


# ----------------------------------------------------------------------
# State (dedup) handling
# ----------------------------------------------------------------------

def load_seen():
    if not os.path.exists(STATE_PATH):
        return set()
    with open(STATE_PATH, "r", encoding="utf-8") as f:
        try:
            return set(json.load(f))
        except json.JSONDecodeError:
            return set()


def save_seen(seen_ids):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    # Keep the state file from growing forever — retain the most recent 5000 ids
    trimmed = list(seen_ids)[-5000:]
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(trimmed, f)


# ----------------------------------------------------------------------
# CVE / KEV fetching
# ----------------------------------------------------------------------

def fetch_kev_ids():
    """Return the set of CVE IDs in CISA's Known Exploited Vulnerabilities catalog."""
    try:
        resp = session.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return {v["cveID"] for v in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"[warn] Could not fetch CISA KEV list: {e}", file=sys.stderr)
        return set()


def fetch_recent_cves(hours, min_score, kev_ids):
    """Fetch CVEs published in the last `hours`, keep only ones scoring >= min_score."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
    }
    req_headers = {}
    if NVD_API_KEY:
        req_headers["apiKey"] = NVD_API_KEY

    try:
        resp = session.get(NVD_API_URL, params=params, headers=req_headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[warn] Could not fetch NVD CVEs: {e}", file=sys.stderr)
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        # Prefer CVSS v3.1, fall back to v3.0
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                score = metrics[key][0]["cvssData"]["baseScore"]
                break

        is_kev = cve_id in kev_ids

        if score is None:
            continue
        if score < min_score and not is_kev:
            continue

        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        results.append({
            "id": cve_id,
            "score": score,
            "kev": is_kev,
            "desc": desc.strip(),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    # Show KEV / highest severity first
    results.sort(key=lambda r: (not r["kev"], -r["score"]))
    return results


# ----------------------------------------------------------------------
# RSS fetching
# ----------------------------------------------------------------------

def fetch_rss(feed_url, hours):
    """Return entries from a feed published within the last `hours`."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    entries = []
    try:
        parsed = feedparser.parse(feed_url)
        for entry in parsed.entries:
            published = entry.get("published_parsed") or entry.get("updated_parsed")
            if published:
                pub_dt = datetime(*published[:6], tzinfo=timezone.utc)
                if pub_dt < cutoff:
                    continue
            entries.append({
                "title": entry.get("title", "").strip(),
                "link": entry.get("link", ""),
                "id": entry.get("id", entry.get("link", entry.get("title", ""))),
            })
    except Exception as e:
        print(f"[warn] Could not fetch RSS {feed_url}: {e}", file=sys.stderr)
    return entries


def matches_ai_keywords(title):
    t = f" {title.lower()} "
    return any(kw in t for kw in AI_KEYWORDS)


# ----------------------------------------------------------------------
# Formatting + Telegram delivery
# ----------------------------------------------------------------------

def escape_md(text):
    """Escape text for Telegram MarkdownV2."""
    escape_chars = r"_*[]()~`>#+-=|{}.!"
    return re.sub(f"([{re.escape(escape_chars)}])", r"\\\1", text)


def build_sections(new_cves, new_security, new_ai):
    sections = []

    if new_cves:
        lines = ["🚨 *High/Critical CVEs*"]
        for c in new_cves:
            tag = "🔥 EXPLOITED" if c["kev"] else f"CVSS {c['score']}"
            title = escape_md(c["desc"][:180])
            lines.append(f"• *{escape_md(c['id'])}* \\({escape_md(tag)}\\)\n  {title}\n  {c['url']}")
        sections.append("\n\n".join(lines))

    if new_security:
        lines = ["📰 *Security News*"]
        for s in new_security:
            lines.append(f"• [{escape_md(s['title'])}]({s['link']})  \\-  _{escape_md(s['source'])}_")
        sections.append("\n".join(lines))

    if new_ai:
        lines = ["🤖 *AI & Tech*"]
        for a in new_ai:
            lines.append(f"• [{escape_md(a['title'])}]({a['link']})  \\-  _{escape_md(a['source'])}_")
        sections.append("\n".join(lines))

    return sections


def chunk_message(text, limit=TELEGRAM_MSG_LIMIT):
    """Split on section boundaries so we never cut mid-entry."""
    chunks = []
    current = ""
    for block in text.split("\n\n"):
        candidate = f"{current}\n\n{block}" if current else block
        if len(candidate) > limit and current:
            chunks.append(current)
            current = block
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


def send_telegram(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[error] TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set", file=sys.stderr)
        sys.exit(1)

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    for chunk in chunk_message(text):
        resp = session.post(url, data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": chunk,
            "parse_mode": "MarkdownV2",
            "disable_web_page_preview": True,
        }, timeout=30)
        if resp.status_code != 200:
            print(f"[error] Telegram send failed: {resp.status_code} {resp.text}", file=sys.stderr)
        time.sleep(1)  # be gentle with Telegram's rate limits


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    seen = load_seen()
    new_seen = set(seen)

    print("Fetching CISA KEV list...")
    kev_ids = fetch_kev_ids()

    print("Fetching recent High/Critical CVEs from NVD...")
    all_cves = fetch_recent_cves(LOOKBACK_HOURS, MIN_CVSS_SCORE, kev_ids)
    new_cves = [c for c in all_cves if c["id"] not in seen]
    for c in new_cves:
        new_seen.add(c["id"])

    print("Fetching security news feeds...")
    new_security = []
    for source, url in SECURITY_NEWS_FEEDS.items():
        for entry in fetch_rss(url, LOOKBACK_HOURS):
            if entry["id"] in seen:
                continue
            new_seen.add(entry["id"])
            new_security.append({**entry, "source": source})

    print("Fetching AI/tech feeds...")
    new_ai = []
    for source, url in AI_DEDICATED_FEEDS.items():
        for entry in fetch_rss(url, LOOKBACK_HOURS):
            if entry["id"] in seen:
                continue
            new_seen.add(entry["id"])
            new_ai.append({**entry, "source": source})

    for source, url in GENERAL_TECH_FEEDS.items():
        for entry in fetch_rss(url, LOOKBACK_HOURS):
            if entry["id"] in seen:
                continue
            if not matches_ai_keywords(entry["title"]):
                continue
            new_seen.add(entry["id"])
            new_ai.append({**entry, "source": source})

    if not new_cves and not new_security and not new_ai:
        print("Nothing new since last run. Skipping Telegram send.")
        save_seen(new_seen)
        return

    sections = build_sections(new_cves, new_security, new_ai)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = f"🛰 *CTI Digest* \\- {escape_md(now_str)}"
    full_message = header + "\n\n" + "\n\n".join(sections)

    print(f"Sending digest: {len(new_cves)} CVEs, {len(new_security)} security items, {len(new_ai)} AI items.")
    send_telegram(full_message)

    save_seen(new_seen)
    print("Done.")


if __name__ == "__main__":
    main()
