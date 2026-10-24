# JobShield

Verify a job offer before you pay. Paste a WhatsApp, Telegram, email or LinkedIn message and get a
0 to 100 risk score, the exact flagged phrases, the reasons, and what to do next.

No model training. Explainable weighted rules plus a scam database and an optional live domain age check.

## Run

    pip install -r requirements.txt
    streamlit run app.py          # web app
    python evaluate.py            # accuracy on labelled samples

Works fully offline. Turn on "Live domain age check" in the sidebar only when internet is available.

## Files

| File | Purpose |
|---|---|
| engine.py | Rules, weights, scoring, highlighting |
| checks.py | SQLite scam database, WHOIS domain age, domain helpers |
| samples.py | 20 labelled messages (10 scam, 10 genuine) |
| evaluate.py | Confusion matrix, accuracy, precision, recall |
| app.py | Streamlit UI |

## How the score works

Each red flag adds points. Good signs (real interview process, official careers page, no-fee statement,
official recruiter email) subtract up to 25. Critical flags (asking for money, OTP or card details, a
match in the scam database) force the score to at least 70 and good signs are ignored.

| Score | Verdict |
|---|---|
| 60 to 100 | Likely scam |
| 30 to 59 | Suspicious, verify first |
| 0 to 29 | Looks safe |

| Flag | Points |
|---|---|
| Matches reported scam database | 60 (critical) |
| Asks for fee, deposit, kit purchase | 40 (critical) |
| Asks for OTP, PIN, card details | 40 (critical) |
| Brand impersonation (e.g. "Amazon" via Telegram) | 25 |
| Unrealistic earnings | 25 |
| Domain younger than 90 days (live) | 25 |
| Asks for Aadhaar, PAN, bank details | 20 |
| Email domain differs from company website | 20 |
| Free email, WhatsApp or Telegram only, task job, no interview promise | 10 to 15 each |
| Suspicious link, easy money bait, urgency, guarantee, no verifiable company | 5 to 12 each |

## AI web verification (optional, OpenRouter)

`ai.py` searches the web (DuckDuckGo, free, no key), then sends the message and the search results to a free
OpenRouter model. The model checks the company, its official site, whether the recruiter email, links and phone
match it, and whether this exact contact is reported as a scam. The page shows the sources used. Final score is the
average of the rule score and the AI score, with floors for critical flags. With no key, no internet, or no search
results, the rule score stands and the app says so.

Optional: tick "Use OpenRouter paid web search" in the sidebar. It uses OpenRouter's own search tool and costs credits.
If credits are missing it falls back to the free path automatically.

Key: create one at openrouter.ai/keys. Local: paste it in the sidebar or set `OPENROUTER_API_KEY`.
Streamlit Cloud: App settings, Secrets, add `OPENROUTER_API_KEY = "your-key"`. Never upload the key to GitHub.
Free models pick themselves from OpenRouter's live list. Free models have per-minute and daily request limits.
Domain age uses RDAP over HTTPS first, so it works on networks that block WHOIS.

## Limits (say this to the judges before they ask)

- It is a risk estimate, not proof. A polished scam with no money ask and a believable company can score low.
- Real fees exist for some exams (for example government or entrance exams), so the tool says Suspicious and asks the user to verify on the official site.
- The sample accuracy is measured on messages written for the demo. Replace them with real messages and re-run `evaluate.py`.
- The scam database ships with 6 synthetic demo entries. Real entries come from the "Report" button.
- Rules cover English and Hinglish. Devanagari Hindi is not covered yet.

## Next steps (for the pitch)

1. Hindi (Devanagari) patterns.
2. Browser extension and WhatsApp bot front end.
3. Shared community scam database, sync with cybercrime.gov.in reports.
4. Optional LLM layer to explain the verdict in the user's language.
