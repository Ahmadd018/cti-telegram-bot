# CTI + AI Telegram Digest

Twice-daily Telegram digest of:
- High/Critical CVEs (CVSS ≥ 7.0), with anything on CISA's Known Exploited
  Vulnerabilities (KEV) list flagged as 🔥 EXPLOITED
- Security news (The Hacker News, BleepingComputer, Krebs on Security,
  Dark Reading, PortSwigger Research)
- AI/tech news (OpenAI, Google DeepMind, plus AI-relevant items from The
  Verge and Ars Technica)

Runs entirely on GitHub Actions — no server to manage.

## 1. Create your Telegram bot

1. Open Telegram, search for **@BotFather**, and start a chat.
2. Send `/newbot` and follow the prompts (pick a name and a username
   ending in `bot`).
3. BotFather will reply with a token that looks like
   `123456789:AAExampleTokenAbCdEfGhIjKlMnOpQrStUvW`. Save it — this is
   your `TELEGRAM_BOT_TOKEN`.
4. Send any message (e.g. "hi") to your new bot so it has a chat to
   reply into.
5. Get your chat ID by visiting this URL in a browser (replace
   `<TOKEN>` with your bot's token):
   `https://api.telegram.org/bot<TOKEN>/getUpdates`
   Look for `"chat":{"id":123456789, ...}` in the response — that
   number is your `TELEGRAM_CHAT_ID`.
   (If it's empty, make sure you sent the bot a message first, then
   refresh.)

## 2. (Optional but recommended) Get a free NVD API key

Without a key, NVD limits you to ~5 requests per 30 seconds, which is
fine for this script (it only makes one request per run) — so this step
is optional. If you want a bit more headroom, request a free key here:
https://nvd.nist.gov/developers/request-an-api-key

## 3. Create a GitHub repo and push this code

```bash
cd cti-telegram-bot
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/<your-username>/cti-telegram-bot.git
git push -u origin main
```

## 4. Add your secrets

In your new GitHub repo: **Settings → Secrets and variables → Actions →
New repository secret**. Add:

| Name                  | Value                                  |
|------------------------|-----------------------------------------|
| `TELEGRAM_BOT_TOKEN`   | the token from BotFather                |
| `TELEGRAM_CHAT_ID`     | your chat ID from step 1.5              |
| `NVD_API_KEY`          | (optional) your NVD API key             |

## 5. Test it

Go to the **Actions** tab in your repo → **CTI Digest** workflow → **Run
workflow** (this uses the `workflow_dispatch` trigger). Check your
Telegram chat for the digest. If nothing arrives, check the workflow's
logs for errors (most common issue: a typo'd secret).

Once that works, it'll run automatically at 05:00 and 17:00 UTC every
day — no further action needed.

## Tuning

All of this lives in `fetch_and_send.py` — feel free to edit and push
changes:

- **Schedule**: edit the two `cron` lines in
  `.github/workflows/digest.yml`. Cron times are always UTC.
- **CVE severity threshold**: change `MIN_CVSS_SCORE` (default `7.0`).
- **Lookback window**: change `LOOKBACK_HOURS` (default `18`, i.e. a bit
  more than the 12h gap between runs, so a slow or missed run doesn't
  drop anything — duplicates are filtered out by the state file anyway).
- **Sources**: add/remove entries in `SECURITY_NEWS_FEEDS`,
  `AI_DEDICATED_FEEDS`, or `GENERAL_TECH_FEEDS` at the top of
  `fetch_and_send.py`.
- **Dedup state**: stored in `state/seen_ids.json`, committed back to the
  repo by the workflow after each run. Delete its contents (back to `[]`)
  if you ever want to reset and get a fresh full digest.

## Notes for a pentester's use case

- KEV-flagged CVEs are sorted to the top and shown regardless of score,
  since active exploitation is a stronger signal than CVSS alone.
- If you want *only* KEV (i.e. even lower volume than High/Critical),
  set `MIN_CVSS_SCORE` to something above 10 (e.g. `11`) — no CVE will
  qualify on score alone, so only KEV-flagged CVEs will appear.
- Exploit-DB / PoC-availability tracking isn't included yet but could be
  added as another source if you want it — shout if that'd be useful.
