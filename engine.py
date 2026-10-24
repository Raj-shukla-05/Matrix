"""JobShield rule engine: weighted, explainable job-scam scoring. No model training needed."""
import re
from dataclasses import dataclass, field

import checks

FREE_MAIL = {
    "gmail.com", "yahoo.com", "yahoo.in", "yahoo.co.in", "outlook.com", "hotmail.com",
    "rediffmail.com", "live.com", "ymail.com", "proton.me", "protonmail.com", "aol.com",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "t.co", "is.gd", "goo.gl", "shorturl.at", "ow.ly"}
MESSENGER_HOSTS = {"t.me", "wa.me", "telegram.me", "chat.whatsapp.com"}
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "work", "online", "site", "icu", "club", "buzz", "shop",
    "vip", "life", "rest", "fun", "monster", "cfd", "sbs", "cyou",
}
TRUSTED_SUFFIXES = (".gov.in", ".nic.in", ".edu.in", ".ac.in", ".gov", ".edu")

# brand -> (regex for mentions, official domains)
BRANDS = {
    "Amazon": (r"\bamazon\b", ["amazon.com", "amazon.in", "amazon.jobs", "aboutamazon.com"]),
    "Google": (r"\bgoogle\b", ["google.com", "withgoogle.com"]),
    "Microsoft": (r"\bmicrosoft\b", ["microsoft.com"]),
    "TCS": (r"\btcs\b|tata consultancy", ["tcs.com"]),
    "Infosys": (r"\binfosys\b", ["infosys.com"]),
    "Wipro": (r"\bwipro\b", ["wipro.com"]),
    "HCLTech": (r"\bhcl(?:tech)?\b", ["hcltech.com", "hcl.com"]),
    "Accenture": (r"\baccenture\b", ["accenture.com"]),
    "Cognizant": (r"\bcognizant\b", ["cognizant.com"]),
    "Capgemini": (r"\bcapgemini\b", ["capgemini.com"]),
    "Flipkart": (r"\bflipkart\b", ["flipkart.com"]),
    "Deloitte": (r"\bdeloitte\b", ["deloitte.com"]),
    "IBM": (r"\bibm\b", ["ibm.com"]),
    "Tech Mahindra": (r"tech\s*mahindra", ["techmahindra.com"]),
    "Reliance": (r"\breliance\b", ["ril.com", "jio.com"]),
    "Paytm": (r"\bpaytm\b", ["paytm.com"]),
    "Zomato": (r"\bzomato\b", ["zomato.com"]),
    "Swiggy": (r"\bswiggy\b", ["swiggy.com", "swiggy.in"]),
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,})")
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"')]+"
    r"|\b(?:[a-z0-9\-]+\.)+(?:com|in|org|net|io|co|gov|edu|me|ly|xyz|top|online|site|click|work|icu|club|buzz|shop|vip)\b(?:/[^\s<>\"')]*)?",
    re.I,
)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}(?!\d)")
COMPANY_RE = re.compile(
    r"\b[A-Z][\w&.\-]*(?:\s+[A-Z][\w&.\-]*){0,3}\s+"
    r"(?:Pvt\.?\s*Ltd\.?|Private\s+Limited|Limited|Ltd\.?|LLP|Inc\.?|Technologies|Technology|Solutions|"
    r"Systems|Infotech|Labs|Analytics|Services|Consulting|Softwares?)\b"
)

# ---------------------------------------------------------------- pattern rules
_FEE_WORDS = (
    r"registration|training|security|joining|kit|laptop|refundable|processing|verification|application|"
    r"admin|administrative|onboarding|id[\s\-]?card|uniform|software|course|certification|agent|visa|"
    r"courier|medical|stamp|document|documentation|file|form|access|activation|membership|login|code|"
    r"consultancy|commission"
)
FEE = re.compile(
    rf"(?:{_FEE_WORDS})\s+(?:fees?|charges?|deposit|amount|cost|money|payment)"
    r"|(?:small|nominal|minimal|one[\s\-]time|token)\s+(?:fees?|charges?|amount|payment)"
    r"|(?:need\s+to|have\s+to|must|should|please|kindly|will\s+have\s+to|has\s+to)\s+"
    r"(?:(?:pay|deposit)\s+(?:rs\.?|₹|inr)?\s*\d[\d,]{2,}|(?:transfer|send|sending|transferring)\s+(?:rs\.?|₹|inr)\s*[\d,]+)"
    r"|(?:deposit|transfer)\s+(?:rs\.?|₹|inr)\s*[\d,]+"
    r"|(?:^|[.!:\n])\s*pay\s+(?:rs\.?|₹|inr)\s*[\d,]+"
    r"|(?:buy|purchase)\s+(?:the\s+)?(?:company\s+)?(?:laptop|kit|software|id\s*card|uniform|sim|device|material)"
    r"|(?:fees?|paisa|paise|amount|rupay[ae])\s+(?:jama|bhej\w*|dena|lagana)"
    r"|(?:processing|registration|verification|training|joining|security|visa)\s+(?:rs\.?|₹|inr)\s*\d[\d,]*"
    r"|(?:rs\.?|₹|inr)\s*[\d,]+\s*(?:/-)?\s*advance"
    r"|security\s+money|refundable\s+deposit|(?:upfront|advance)\s+(?:fee|payment|amount)"
    r"|(?:rs\.?|₹|inr)\s*[\d,]+\s*(?:/-)?\s*(?:as|for|towards)\s+(?:registration|training|security|joining|kit|deposit|processing|verification)",
    re.I | re.M,
)
OTP = re.compile(
    r"(?:share|send|give|tell|provide|forward|enter)\s+(?:us\s+)?(?:the\s+|your\s+)?"
    r"(?:otp|cvv|upi\s*pin|atm\s*pin|password|card\s+number|card\s+details)",
    re.I,
)
DOCS = re.compile(
    r"(?:send|share|submit|provide|upload|give)\s+(?:us\s+)?(?:your\s+)?(?:scanned\s+)?(?:copy\s+of\s+)?"
    r"(?:aadhaar|aadhar|adhar|pan(?:\s*card)?|bank\s+(?:account|details|passbook)|account\s+number|passbook|selfie)"
    r"|(?:and|&)\s+(?:your\s+)?bank\s+account\s+(?:number|details)"
    r"|(?:aadhaar|aadhar)\s+(?:card\s+)?(?:is\s+)?(?:required|needed|mandatory)",
    re.I,
)
URGENCY = re.compile(
    r"join\s+(?:today|now|immediately)|limited\s+(?:seats?|vacanc(?:y|ies)|slots?|positions?)"
    r"|hurry|apply\s+(?:now|immediately|today)|last\s+date\s+(?:is\s+)?(?:today|tomorrow)"
    r"|only\s+\d+\s+(?:seats?|slots?|vacanc\w+)|offer\s+(?:expires|valid)|jaldi|turant|seat\s+limited"
    r"|urgent(?:ly)?\s+(?:hiring|required|requirement|vacancy)",
    re.I,
)
NO_INTERVIEW = re.compile(
    r"no\s+(?:interview|exam|test|experience(?:\s+(?:needed|required|necessary))?|qualification|skills?)(?:\s+required)?"
    r"|without\s+(?:interview|experience|exam)|bina\s+interview"
    r"|direct\s+(?:joining|selection)|(?:instant|immediate|turant|seedha)\s+(?:joining|selection|offer)",
    re.I,
)
TASK_JOB = re.compile(
    r"(?:like|subscribe|follow)\s+(?:youtube|instagram|videos?|channels?|pages?|reels?)"
    r"|rate\s+products?|task[\s\-]based|complete\s+(?:simple\s+)?tasks?|simple\s+tasks?"
    r"|review\s+(?:products?|hotels?|writing)|google\s+maps\s+rating|liking\s+videos?"
    r"|per\s+task|withdraw\s+(?:daily|anytime|instantly)",
    re.I,
)
WFH_BAIT = re.compile(
    r"ghar\s+baithe|sitting\s+at\s+home|earn\s+(?:money\s+)?from\s+home"
    r"|(?:typing|data\s+entry|form\s+filling|copy[\s\-]?paste)\s+(?:job|work)"
    r"|just\s+\d+\s+hours?\s+(?:daily|a\s+day|per\s+day)|(?:paise|paisa|money)\s+kamao"
    r"|easy\s+money|passive\s+income|double\s+your",
    re.I,
)
GUARANTEE = re.compile(
    r"100\s*%\s*(?:guarantee\w*|genuine|placement|selection|job|payment)"
    r"|guaranteed\s+(?:job|income|payment|salary|placement|selection)",
    re.I,
)
MESSENGER = re.compile(r"whats\s?app|telegram|\bt\.me/|\bwa\.me/|signal\s+(?:me|group)", re.I)

NEGATOR = re.compile(r"\b(?:no|never|not|without|zero|don'?t|doesn'?t)\b[^.,;!?]*$", re.I)

# (id, title, points, hard, regex, check_negation, why)
PATTERN_RULES = [
    ("FEE", "Asks you to pay money", 40, True, FEE, True,
     "Genuine employers never charge candidates. Registration, training, kit or deposit fees are the number one job scam signal."),
    ("OTP", "Asks for OTP, PIN or card details", 40, True, OTP, False,
     "No recruiter needs your OTP, PIN or card details. Sharing them gives access to your bank account."),
    ("DOCS", "Asks for Aadhaar, PAN or bank details", 20, False, DOCS, False,
     "Identity and bank details are collected by scammers for fraud. Real employers ask for them only after a verified offer."),
    ("URGENCY", "Creates false urgency", 10, False, URGENCY, False,
     "Pressure to act today stops you from checking. Scammers rely on it."),
    ("NO_INTERVIEW", "Promises selection without interview or experience", 15, False, NO_INTERVIEW, False,
     "Real hiring has an interview or test. Direct joining offers are bait."),
    ("TASK_JOB", "Task job (like, rate, subscribe)", 15, False, TASK_JOB, False,
     "Like, rate and subscribe jobs are a known fraud pattern that starts with small payouts and ends with a deposit demand."),
    ("WFH_BAIT", "Easy money from home bait", 12, False, WFH_BAIT, False,
     "Typing, data entry and sitting-at-home offers with high pay are a typical bait."),
    ("GUARANTEE", "Guaranteed job or income", 10, False, GUARANTEE, False,
     "No employer can guarantee a job or income."),
    ("MESSENGER", "Recruiter contact only on WhatsApp or Telegram", 15, False, MESSENGER, False,
     "Official recruiters use company email and a verifiable process, not only a chat app."),
]

EARN_PREFIX = r"(?:salary|income|package|earn(?:ing)?s?|pay)\s*(?:of|is|upto|up\s*to|:|-)?\s*(?:up\s*to\s+|upto\s+)?"
CUR = r"(?:₹|rs\.?|inr|rupees)\s*"
NUM = r"(\d{1,3}(?:,\d{2,3})+|\d+(?:\.\d+)?)"
EARN_RE = re.compile(
    rf"(?:{CUR}|{EARN_PREFIX}(?:{CUR})?){NUM}\s*(k|lakhs?|lacs?)?\s*(?:/-)?\s*(?:/|per|a|each|every|ek)?\s*"
    r"(day|daily|din|week|weekly|month|monthly|mahina)?",
    re.I,
)
ENTRY_LEVEL = re.compile(
    r"fresher|no\s+experience|without\s+experience|12th|10th|part[\s\-]?time|work\s+from\s+home|typing|"
    r"data\s+entry|students?|housewives|from\s+home|at\s+home",
    re.I,
)

POSITIVES = [
    ("P_PROCESS", "Mentions a real selection process (interview, assessment)", 8,
     re.compile(r"interview|assessment|aptitude|technical\s+round|hr\s+round|shortlisted|selection\s+process|written\s+test", re.I)),
    ("P_OFFICIAL", "Points to an official website, careers page or portal", 8,
     re.compile(r"official\s+(?:website|site|portal|careers)|careers?\s+page|careers?\.[a-z0-9\-]+\.[a-z]+|"
                r"linkedin\.com/jobs|\.gov\.in|naukri\.com|indeed\.com|\bcareers?@|/careers", re.I)),
    ("P_NOFEE", "States that no fee is charged or warns about fake offers", 8,
     re.compile(r"(?:never|not|n't)\s+(?:ask|charge|collect|take|demand)\w*[^.]{0,30}?(?:money|fees?|payment)"
                r"|no\s+fees?\b[^.]{0,20}(?:charged|taken|collected|required|at\s+any\s+stage)"
                r"|beware\s+of\s+(?:fake|fraud)", re.I)),
    ("P_ANNUAL", "Quotes salary in LPA or CTC (formal offer style)", 6,
     re.compile(r"\b\d+(?:\.\d+)?\s*(?:lpa|lakhs?\s+per\s+annum)|\bctc\b", re.I)),
]
POSITIVE_CAP = 25


@dataclass
class Flag:
    id: str
    title: str
    points: int
    why: str
    evidence: list = field(default_factory=list)
    spans: list = field(default_factory=list)
    hard: bool = False


def _domain_of(url):
    u = re.sub(r"^https?://", "", url.strip(), flags=re.I)
    u = re.sub(r"^www\.", "", u, flags=re.I)
    return re.split(r"[/?#:]", u)[0].lower().strip(".,;")


def _is_official(domain, official_list):
    return any(domain == d or domain.endswith("." + d) for d in official_list)


def extract_entities(text):
    emails = [(m.group(0), m.group(1).lower(), m.span()) for m in EMAIL_RE.finditer(text)]
    masked = EMAIL_RE.sub(lambda m: " " * len(m.group(0)), text)
    urls = []
    for m in URL_RE.finditer(masked):
        raw = m.group(0).rstrip(".,;)")
        urls.append((raw, _domain_of(raw), m.span()))
    phones = [(m.group(0), re.sub(r"\D", "", m.group(0))[-10:], m.span()) for m in PHONE_RE.finditer(text)]
    return emails, urls, phones


def _parse_earnings(text):
    """Yield (monthly_equivalent, period, span, snippet) for amounts that state a pay period."""
    out = []
    for m in EARN_RE.finditer(text):
        period = (m.group(3) or "").lower()
        if not period:
            continue
        amount = float(m.group(1).replace(",", ""))
        suffix = (m.group(2) or "").lower()
        if suffix == "k":
            amount *= 1_000
        elif suffix.startswith("lakh") or suffix.startswith("lac"):
            amount *= 100_000
        if period in ("day", "daily", "din"):
            monthly = amount * 26
        elif period in ("week", "weekly"):
            monthly = amount * 4
        else:
            monthly = amount
        out.append((monthly, period, m.span(), m.group(0).strip()))
    return out


def analyze(text, company_site="", live=False, db_path=None):
    text = text or ""
    flags = []
    emails, urls, phones = extract_entities(text)
    email_domains = sorted({d for _, d, _ in emails})
    url_domains = sorted({d for _, d, _ in urls})
    site_domain = _domain_of(company_site) if company_site.strip() else ""

    def add(flag):
        flags.append(flag)

    # 1. pattern rules
    for rid, title, pts, hard, rx, check_neg, why in PATTERN_RULES:
        spans, ev = [], []
        for m in rx.finditer(text):
            if check_neg and NEGATOR.search(text[max(0, m.start() - 25):m.start()]):
                continue
            spans.append(m.span())
            ev.append(m.group(0).strip())
        if spans:
            add(Flag(rid, title, pts, why, ev, spans, hard))

    # 1b. government exams can charge an official fee. If the message points to a .gov.in style site,
    # a fee mention is downgraded from a critical flag to a warning.
    if any(d.endswith(TRUSTED_SUFFIXES) for d in url_domains + email_domains):
        for i, f in enumerate(flags):
            if f.id == "FEE":
                flags[i] = Flag("FEE_GOVT", "Mentions an application fee (government exams can have official fees)", 10,
                                "Pay only on the official .gov.in portal, never to a person, UPI ID or agent.",
                                f.evidence, f.spans)

    # 2. free mail used for recruiter contact
    free = [(raw, d, sp) for raw, d, sp in emails if d in FREE_MAIL]
    if free:
        add(Flag("FREE_MAIL", "Recruiter uses a free email (Gmail, Yahoo, etc.)", 15,
                 "Companies hire from their own domain. A free mail address means anyone can claim to be HR.",
                 [raw for raw, _, _ in free], [sp for _, _, sp in free]))

    # 3. brand impersonation
    brand_hit = None
    official_domains_for_text = []
    for name, (rx, domains) in BRANDS.items():
        m = re.search(rx, text, re.I)
        if m:
            brand_hit = (name, m.span())
            official_domains_for_text.extend(domains)
            bad_mail = [raw for raw, d, _ in emails if not _is_official(d, domains)]
            uses_messenger = bool(MESSENGER.search(text))
            if bad_mail or uses_messenger:
                ev = [name] + bad_mail
                add(Flag("BRAND", f"Uses the name of {name} but contact is not official", 25,
                         f"{name} recruits only through its own domain and portal. A different email or a chat app is impersonation.",
                         ev, [m.span()]))
            break

    # 4. links
    link_ev, link_sp, link_why = [], [], []
    for raw, d, sp in urls:
        tld = d.rsplit(".", 1)[-1]
        if d in SHORTENERS:
            link_ev.append(raw); link_sp.append(sp); link_why.append("shortened link hides the real site")
        elif d in MESSENGER_HOSTS:
            continue
        elif tld in SUSPICIOUS_TLDS and not d.endswith(TRUSTED_SUFFIXES):
            link_ev.append(raw); link_sp.append(sp); link_why.append(f".{tld} sites are cheap and common in scams")
    if link_ev:
        add(Flag("LINK", "Suspicious link", 12,
                 "Link problems: " + "; ".join(sorted(set(link_why))) + ".", link_ev, link_sp))

    # 5. unrealistic earnings
    earn_ev, earn_sp = [], []
    entry = bool(ENTRY_LEVEL.search(text))
    for monthly, period, sp, snip in _parse_earnings(text):
        daily_style = period in ("day", "daily", "din", "week", "weekly")
        if (daily_style and monthly >= 52_000) or (not daily_style and monthly >= 80_000 and entry):
            earn_ev.append(snip); earn_sp.append(sp)
    if earn_ev:
        add(Flag("EARNINGS", "Unrealistic earnings for the role", 25,
                 "Very high pay for easy or entry level work is not how real salaries work.", earn_ev, earn_sp))

    # 6. no verifiable organisation
    org_present = bool(COMPANY_RE.search(text)) or bool(brand_hit) or any(
        d.endswith(TRUSTED_SUFFIXES) for d in url_domains + email_domains)
    if not org_present:
        for _, d, _ in urls:
            tld = d.rsplit(".", 1)[-1]
            if d not in SHORTENERS and d not in MESSENGER_HOSTS and tld not in SUSPICIOUS_TLDS:
                org_present = True
        for _, d, _ in emails:
            if d not in FREE_MAIL:
                org_present = True
    if text.strip() and not org_present:
        add(Flag("NO_ORG", "No verifiable company name, website or official email", 10,
                 "You cannot check who is hiring. Always ask for the company name, website and registered address."))

    # 7. shouting
    letters = [c for c in text if c.isalpha()]
    if len(letters) > 40:
        caps = sum(c.isupper() for c in letters) / len(letters)
    else:
        caps = 0
    if caps > 0.35 or text.count("!") >= 3:
        add(Flag("SHOUTING", "Shouting style (many capitals or exclamation marks)", 5,
                 "Mass-forwarded scam messages are written to grab attention, not to inform."))

    # 8. company website vs email domain
    positives_extra = []
    if site_domain:
        for raw, d, sp in emails:
            if d in FREE_MAIL:
                continue
            if not checks.same_site(d, site_domain):
                add(Flag("MISMATCH", "Email domain does not match the company website", 20,
                         f"Email is from {d} but the company website is {site_domain}.", [raw], [sp]))
            else:
                positives_extra.append(("P_MATCH", "Recruiter email matches the company website", 10))

    # 9. brand email genuinely official
    if brand_hit:
        for name, (rx, domains) in BRANDS.items():
            if name == brand_hit[0] and any(_is_official(d, domains) for d in email_domains):
                positives_extra.append(("P_BRANDMAIL", f"Recruiter email is on {name}'s official domain", 10))

    # 10. known scam database
    db_hits = (
        [("email", v, n) for v, n in checks.lookup("email", [r for r, _, _ in emails], db_path)]
        + [("domain", v, n) for v, n in checks.lookup("domain", url_domains + email_domains, db_path)]
        + [("phone", v, n) for v, n in checks.lookup("phone", [p for _, p, _ in phones], db_path)]
    )
    if db_hits:
        add(Flag("KNOWN_SCAM", "Matches a reported scam in the JobShield database", 60,
                 "; ".join(f"{k} {v} ({n})" for k, v, n in db_hits), [v for _, v, _ in db_hits], [], hard=True))

    # 11. live domain age (needs internet)
    live_notes = []
    if live:
        to_check = []
        for d in email_domains + url_domains:
            if d in FREE_MAIL or d in SHORTENERS or d in MESSENGER_HOSTS or d in to_check:
                continue
            if _is_official(d, official_domains_for_text) or d.endswith(TRUSTED_SUFFIXES):
                continue
            to_check.append(d)
        for d in to_check[:3]:
            age = checks.domain_age_days(checks.registrable(d))
            if age is None:
                live_notes.append(f"{d}: age lookup unavailable (offline or hidden by registrar)")
            elif age < 90:
                add(Flag("NEW_DOMAIN", f"Domain {d} is only {age} days old", 25,
                         "Scam sites are usually registered days or weeks before the campaign.", [d], []))
                live_notes.append(f"{d}: {age} days old")
            elif age < 365:
                add(Flag("YOUNG_DOMAIN", f"Domain {d} is less than a year old", 10,
                         "A young domain for an established employer is a warning sign.", [d], []))
                live_notes.append(f"{d}: {age} days old")
            else:
                live_notes.append(f"{d}: {age // 365} year(s) old")

    # ---- positives and score
    hard = any(f.hard for f in flags)
    positives = []
    for pid, title, pts, rx in POSITIVES:
        m = rx.search(text)
        if m:
            positives.append({"id": pid, "title": title, "points": pts, "evidence": m.group(0).strip()})
    for pid, title, pts in positives_extra:
        if not any(p["id"] == pid for p in positives):
            positives.append({"id": pid, "title": title, "points": pts, "evidence": ""})

    raw = sum(f.points for f in flags)
    credit = 0 if hard else min(sum(p["points"] for p in positives), POSITIVE_CAP)
    score = max(0, min(100, raw - credit))
    if hard:
        score = max(score, 70)

    if score >= 60:
        verdict = "SCAM"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    flags.sort(key=lambda f: -f.points)
    cm = COMPANY_RE.search(text)
    company = brand_hit[0] if brand_hit else (cm.group(0).strip() if cm else "")
    return {
        "company": company,
        "score": score,
        "rule_score": score,
        "verdict": verdict,
        "flags": flags,
        "positives": positives,
        "positive_credit": credit,
        "hard": hard,
        "emails": [r for r, _, _ in emails],
        "urls": [r for r, _, _ in urls],
        "phones": [p for _, p, _ in phones],
        "live_notes": live_notes,
        "advice": advice_for(verdict),
        "text": text,
    }


def verdict_for(score):
    return "SCAM" if score >= 60 else "SUSPICIOUS" if score >= 30 else "SAFE"


def advice_for(verdict):
    if verdict == "SCAM":
        return [
            "Do not pay any money and do not share OTP, Aadhaar, PAN or bank details.",
            "Do not click the links in the message.",
            "Report it at cybercrime.gov.in or call the national cyber crime helpline 1930.",
            "Block and report the number on WhatsApp or Telegram.",
            "Warn your friends and classmates so nobody else pays.",
        ]
    if verdict == "SUSPICIOUS":
        return [
            "Do not pay anything. A real job never asks for money.",
            "Check the company on its official website and careers page. Type the address yourself, do not use the link in the message.",
            "Ask for the company registration (CIN) and verify it on mca.gov.in.",
            "Ask for a video interview and a written offer from an official company email.",
            "If anything still feels wrong, report at cybercrime.gov.in or call 1930.",
        ]
    return [
        "No major red flags found. This is an estimate, not a guarantee.",
        "Still confirm the recruiter on the company's official careers page.",
        "Never pay for a job, even if the offer looks genuine later.",
    ]


def highlight_html(result):
    """HTML of the message with every flagged phrase highlighted."""
    import html
    text = result["text"]
    spans = sorted(sp for f in result["flags"] for sp in f.spans)
    merged = []
    for s, e in spans:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out, pos = [], 0
    for s, e in merged:
        out.append(html.escape(text[pos:s]))
        out.append(f"<mark style='background:#FEE2E2;color:#991B1B;border-bottom:2px solid #DC2626;padding:1px 5px;border-radius:4px;font-weight:600;display:inline-block;margin:1px 0'>{html.escape(text[s:e])}</mark>")
        pos = e
    out.append(html.escape(text[pos:]))
    return "<div style='line-height:1.85;white-space:pre-wrap;font-family:inherit;font-size:14.5px;color:#1E293B'>" + "".join(out) + "</div>"

