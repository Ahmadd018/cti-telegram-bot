#!/usr/bin/env python3
"""
CTI + AI Telegram Digest
-------------------------
Pulls:
  - High/Critical CVEs from NVD (flagging any that are in CISA's KEV list
    as actively exploited)
  - Security news from a handful of RSS feeds
  - AI/tech news from a handful of RSS feeds

Groups items by source into collapsible ("expandable") Telegram quote
blocks, so a source with many items (e.g. 18 PortSwigger posts in one
run) doesn't flood the chat — you see one line per source with a count
and timestamp, and tap to expand the ones you actually want to read.

Dedupes against what's already been sent, and pushes the result to a
Telegram chat via the Bot API using HTML formatting.

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
LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "72"))

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
    "The Record": "https://therecord.media/feed/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "The Verge (Security)": "https://www.theverge.com/rss/cyber-security/index.xml",
}

# AI-dedicated feeds: official lab announcements + a dedicated AI-only news section
AI_FEEDS = {
    "OpenAI": "https://openai.com/news/rss.xml",
    "Google DeepMind": "https://deepmind.google/blog/feed/basic/",
    "The Verge (AI)": "https://www.theverge.com/rss/ai-artificial-intelligence/index.xml",
}

# General tech feeds: the Tech section specifically, NOT the firehose —
# the firehose also includes entertainment/gaming/deals coverage which isn't
# useful here.
TECH_FEEDS = {
    "The Verge (Tech)": "https://www.theverge.com/rss/tech/index.xml",
    "Ars Technica": "https://feeds.arstechnica.com/arstechnica/index",
}

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

STATE_PATH = os.path.join(os.path.dirname(__file__), "state", "seen_ids.json")
STATE_RETENTION_DAYS = int(os.environ.get("STATE_RETENTION_DAYS", "30"))

# Groups (per source) with this many items or fewer are shown inline,
# directly visible. Bigger groups get collapsed into a tap-to-expand block.
INLINE_THRESHOLD = 3

MAX_BLOCK_CHARS = 3400    # cap for a single collapsible block's HTML
CHUNK_LIMIT = 3800        # cap per Telegram message (hard limit is 4096)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; CTI-Digest-Bot/1.0; +https://github.com/)",
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
}

session = requests.Session()
session.headers.update(HEADERS)


# ----------------------------------------------------------------------
# State (dedup) handling
# ----------------------------------------------------------------------

def load_seen():
    """Returns {item_id: iso_timestamp_last_seen}. Transparently migrates the
    old flat-list format from earlier versions of this script."""
    if not os.path.exists(STATE_PATH):
        return {}
    with open(STATE_PATH, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return {}

    if isinstance(data, list):
        now = datetime.now(timezone.utc).isoformat()
        return {item_id: now for item_id in data}

    return data


def save_seen(seen_map):
    """Prune anything older than STATE_RETENTION_DAYS, then write to disk."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=STATE_RETENTION_DAYS)
    pruned = {}
    for item_id, ts in seen_map.items():
        try:
            seen_at = datetime.fromisoformat(ts)
        except (ValueError, TypeError):
            continue
        if seen_at >= cutoff:
            pruned[item_id] = ts

    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(pruned, f, indent=2, sort_keys=True)


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

    results.sort(key=lambda r: (not r["kev"], -r["score"]))
    return results


# ----------------------------------------------------------------------
# RSS fetching
# ----------------------------------------------------------------------

def fetch_rss(feed_url, hours, source_name="feed"):
    """Return entries from a feed published within the last `hours`."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    entries = []
    try:
        resp = session.get(feed_url, timeout=20)
        resp.raise_for_status()
        parsed = feedparser.parse(resp.content)
    except Exception as e:
        print(f"[warn] Could not fetch {source_name} ({feed_url}): {e}", file=sys.stderr)
        return entries

    if parsed.bozo and not parsed.entries:
        print(f"[warn] {source_name}: feed did not parse cleanly ({parsed.bozo_exception})", file=sys.stderr)

    # Diagnostic: how old is the newest entry in this feed, regardless of
    # whether it passes our lookback filter? If this is way older than
    # expected for an active outlet, the feed itself is stale (CDN caching,
    # etc.) rather than our filtering being wrong.
    all_dates = []
    for e in parsed.entries:
        p = e.get("published_parsed") or e.get("updated_parsed")
        if p:
            all_dates.append(datetime(*p[:6], tzinfo=timezone.utc))
    if all_dates:
        newest = max(all_dates)
        age_h = (datetime.now(timezone.utc) - newest).total_seconds() / 3600
        print(f"[info] {source_name}: newest entry in feed is {age_h:.1f}h old ({newest.isoformat()})")
    else:
        print(f"[info] {source_name}: no dated entries found in feed at all")

    used_full_content = 0
    for entry in parsed.entries:
        published = entry.get("published_parsed") or entry.get("updated_parsed")
        if published:
            pub_dt = datetime(*published[:6], tzinfo=timezone.utc)
            if pub_dt < cutoff:
                continue

        content_field = entry.get("content")
        if content_field and content_field[0].get("value"):
            body = content_field[0]["value"]
            used_full_content += 1
        else:
            body = entry.get("summary", entry.get("description", ""))

        entries.append({
            "title": entry.get("title", "").strip(),
            "link": entry.get("link", ""),
            "id": entry.get("id", entry.get("link", entry.get("title", ""))),
            "summary": smart_truncate(strip_html(body), 380),
        })

    print(f"[info] {source_name}: {len(entries)} item(s) in the last {hours}h "
          f"(feed had {len(parsed.entries)} total, {used_full_content} used full content)")
    return entries


# ----------------------------------------------------------------------
# Text processing: HTML stripping, boilerplate cleanup, extractive summary
# ----------------------------------------------------------------------

def strip_html(text):
    """Turn an RSS summary's HTML into plain, readable text."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)          # drop tags
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&#39;|&rsquo;", "'", text)
    text = re.sub(r"&quot;", '"', text)
    text = re.sub(r"\s+", " ", text).strip()

    text = re.sub(r"\s*The post .+? appeared first on .+?\.?\s*$", "", text)
    text = re.sub(r"\s*Continue reading.*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*Read (the full story|more)\.?\s*$", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*\[…\]\s*$", "", text)
    text = re.sub(r"\s*\.\.\.\s*$", "", text)

    _starters = ("The|A|An|In|On|At|While|After|Before|With|As|When|Once|"
                 "Following|According|Despite|However|Meanwhile|It|This|"
                 "That|These|Those|If|Since|Because|For|Amid|Given|New|"
                 "Now|Here|There")
    text = re.sub(
        rf"^[^.!?|]{{0,120}}\|?\s*(?:Image|Photo(?:graph)?)\s*:?\s*(?:by\s+)?(?:[A-Z][\w&.'-]*\s*){{1,5}}?(?=(?:{_starters})\b)",
        "", text,
    )
    text = re.sub(
        rf"\|?\s*(?:Image|Photo(?:graph)?)\s*:?\s*(?:by\s+)?(?:[A-Z][\w&.'-]*\s*){{1,5}}?(?=(?:{_starters})\b)",
        "", text,
    )
    text = re.sub(r"\s+", " ", text).strip()
    return text


BORING_PHRASES = [
    "here's what you need to know", "in this article", "in this post",
    "sign up", "subscribe", "follow us", "read more", "click here",
    "as always,", "for more information", "this article originally",
    "share this", "related:", "update:", "editor's note",
]


def _sentence_score(sentence):
    s_lower = sentence.lower()
    if any(phrase in s_lower for phrase in BORING_PHRASES):
        return -1000
    if len(sentence) < 25:
        return -1000

    score = 0.0
    score += len(re.findall(r"\d", sentence)) * 1.5
    score += len(re.findall(r"\b[A-Z][a-zA-Z]{2,}\b", sentence)) * 1.0
    score += sentence.count("%") * 2
    score += sentence.count("$") * 2
    ideal = 160
    score -= abs(len(sentence) - ideal) / 120.0
    return score


def extract_summary(text, limit=380, max_sentences=3):
    """Pick the most information-dense sentences (not just the first ones),
    so the summary actually says what happened instead of leading with fluff."""
    if not text:
        return ""
    sentences = re.split(r"(?<=[.!?])\s+", text)
    sentences = [s.strip() for s in sentences if s.strip()]
    if not sentences:
        return ""

    scored = [(i, s, _sentence_score(s)) for i, s in enumerate(sentences)]
    viable = [t for t in scored if t[2] > -1000]
    if not viable:
        viable = scored

    min_score = 1.0
    qualifying = [t for t in viable if t[2] >= min_score]
    if qualifying:
        top = sorted(qualifying, key=lambda t: t[2], reverse=True)[:max_sentences]
    else:
        top = [max(viable, key=lambda t: t[2])]

    top_in_order = [s for i, s, sc in sorted(top, key=lambda t: t[0])]
    result = " ".join(top_in_order)
    return smart_truncate(result, limit)


def smart_truncate(text, limit):
    """Truncate to `limit` chars, preferring to end on a sentence, else a word, plus an ellipsis."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    sentence_end = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    if sentence_end > limit * 0.4:
        return cut[:sentence_end + 1]
    word_end = cut.rfind(" ")
    if word_end > 0:
        cut = cut[:word_end]
    return cut.rstrip(".,;: ") + "…"


# ----------------------------------------------------------------------
# HTML escaping + Telegram message building
# ----------------------------------------------------------------------

def escape_html(text):
    """Escape text for Telegram's HTML parse mode (visible text)."""
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))


def escape_html_attr(text):
    """Escape a URL for use inside an href="..." attribute."""
    return (text.replace("&", "&amp;")
                .replace('"', "&quot;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))


def format_cve_item(c):
    tag = "🔥 EXPLOITED" if c["kev"] else f"CVSS {c['score']}"
    desc = escape_html(smart_truncate(c["desc"], 400))
    return (f"• <b>{escape_html(c['id'])}</b> ({escape_html(tag)})\n"
            f"{desc}\n"
            f'<a href="{escape_html_attr(c["url"])}">NVD advisory</a>')


def format_news_item(it):
    title = escape_html(it["title"])
    lines = [f"• <b>{title}</b>"]
    if it.get("summary"):
        lines.append(escape_html(it["summary"]))
    lines.append(f'<a href="{escape_html_attr(it["link"])}">Read more</a>')
    return "\n".join(lines)


def group_by_source(items):
    """Groups items by source, preserving first-seen order."""
    groups = {}
    for it in items:
        groups.setdefault(it["source"], []).append(it)
    return groups


def build_group_block(emoji, group_name, items, item_formatter, timestamp_str):
    """One block for a single source/category: always-visible header with a
    count + timestamp, and either the items inline (small groups) or tucked
    into a tap-to-expand quote (larger groups) so they don't flood the chat."""
    count = len(items)
    header = f"{emoji} <b>{escape_html(group_name)}</b> — {count} new — {escape_html(timestamp_str)}"

    formatted_items = [item_formatter(it) for it in items]

    if count <= INLINE_THRESHOLD:
        return header + "\n\n" + "\n\n".join(formatted_items)

    included = []
    omitted = 0
    running_len = len(header) + len("<blockquote expandable></blockquote>") + 40
    hit_limit = False
    for text in formatted_items:
        if hit_limit:
            omitted += 1
            continue
        addition = len(text) + 2
        if included and running_len + addition > MAX_BLOCK_CHARS:
            hit_limit = True
            omitted += 1
            continue
        included.append(text)
        running_len += addition

    body_inner = "\n\n".join(included)
    if omitted:
        body_inner += f"\n\n… and {omitted} more not shown this run"
    return header + "\n" + f"<blockquote expandable>{body_inner}</blockquote>"


def build_blocks(new_cves, new_security, new_ai, new_tech, timestamp_str):
    blocks = []

    if new_cves:
        blocks.append(build_group_block("🚨", "High/Critical CVEs", new_cves, format_cve_item, timestamp_str))

    for source, items in group_by_source(new_security).items():
        blocks.append(build_group_block("📰", source, items, format_news_item, timestamp_str))

    for source, items in group_by_source(new_ai).items():
        blocks.append(build_group_block("🤖", source, items, format_news_item, timestamp_str))

    for source, items in group_by_source(new_tech).items():
        blocks.append(build_group_block("💻", source, items, format_news_item, timestamp_str))

    return blocks


def chunk_blocks(blocks, limit=CHUNK_LIMIT):
    """Pack blocks into messages, never splitting a single block across two
    messages (that would break an open <blockquote> tag)."""
    chunks = []
    current = []
    current_len = 0
    for b in blocks:
        addition = len(b) + 2
        if current and current_len + addition > limit:
            chunks.append("\n\n".join(current))
            current = [b]
            current_len = len(b)
        else:
            current.append(b)
            current_len += addition
    if current:
        chunks.append("\n\n".join(current))
    return chunks


def send_telegram_chunks(chunks):
    """Returns True only if every chunk was accepted by Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[error] TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set", file=sys.stderr)
        sys.exit(1)

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    all_ok = True
    for chunk in chunks:
        resp = session.post(url, data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": chunk,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }, timeout=30)
        if resp.status_code != 200:
            print(f"[error] Telegram send failed: {resp.status_code} {resp.text}", file=sys.stderr)
            all_ok = False
        time.sleep(1)
    return all_ok


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    seen = load_seen()
    new_seen = dict(seen)
    now_iso = datetime.now(timezone.utc).isoformat()

    print(f"Loaded state: {len(seen)} previously-seen item(s) "
          f"(retention: {STATE_RETENTION_DAYS} days).")

    print("Fetching CISA KEV list...")
    kev_ids = fetch_kev_ids()

    print("Fetching recent High/Critical CVEs from NVD...")
    all_cves = fetch_recent_cves(LOOKBACK_HOURS, MIN_CVSS_SCORE, kev_ids)
    new_cves = [c for c in all_cves if c["id"] not in seen]
    for c in new_cves:
        new_seen[c["id"]] = now_iso

    print("Fetching security news feeds...")
    new_security = []
    for source, url in SECURITY_NEWS_FEEDS.items():
        for entry in fetch_rss(url, LOOKBACK_HOURS, source):
            if entry["id"] in seen:
                continue
            new_seen[entry["id"]] = now_iso
            new_security.append({**entry, "source": source})

    print("Fetching AI feeds...")
    new_ai = []
    for source, url in AI_FEEDS.items():
        for entry in fetch_rss(url, LOOKBACK_HOURS, source):
            if entry["id"] in seen:
                continue
            new_seen[entry["id"]] = now_iso
            new_ai.append({**entry, "source": source})

    print("Fetching general tech feeds...")
    new_tech = []
    for source, url in TECH_FEEDS.items():
        for entry in fetch_rss(url, LOOKBACK_HOURS, source):
            if entry["id"] in seen:
                continue
            new_seen[entry["id"]] = now_iso
            new_tech.append({**entry, "source": source})

    if not new_cves and not new_security and not new_ai and not new_tech:
        print("Nothing new since last run. Skipping Telegram send.")
        save_seen(new_seen)
        return

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    blocks = build_blocks(new_cves, new_security, new_ai, new_tech, now_str)
    top_header = f"🛰 <b>CTI Digest</b> — {escape_html(now_str)}"
    chunks = chunk_blocks([top_header] + blocks)

    print(f"Sending digest: {len(new_cves)} CVEs, {len(new_security)} security items, "
          f"{len(new_ai)} AI items, {len(new_tech)} tech items, across {len(chunks)} message(s).")
    delivered = send_telegram_chunks(chunks)

    if delivered:
        save_seen(new_seen)
        print("Done.")
    else:
        print("[warn] Send failed — NOT marking these items as seen, so they'll retry next run.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()