"""JobShield UI - AI & Rule-Based Recruitment Fraud Forensics System.
Run: streamlit run app.py
"""
import os
import streamlit as st

import ai
import checks
import engine
import ocr
from samples import SAMPLES

# Page configuration
st.set_page_config(
    page_title="JobShield — Recruitment Fraud Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Clean & Human-Designed Light Theme CSS
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    html, body, [class*="css"], .stMarkdown, .stText, p, span, div {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    /* Clean Light Background */
    .stApp {
        background-color: #F8FAFC;
        color: #0F172A;
    }

    /* Clean Top Header Card */
    .hero-container {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 12px;
        padding: 24px 28px;
        margin-bottom: 22px;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.03);
    }

    .hero-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #ECFDF5;
        border: 1px solid #A7F3D0;
        color: #065F46;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.3px;
        margin-bottom: 12px;
    }

    .pulse-dot {
        width: 8px;
        height: 8px;
        background-color: #10B981;
        border-radius: 50%;
    }

    .hero-title {
        font-size: 28px;
        font-weight: 800;
        color: #0F172A;
        margin: 0 0 6px 0;
        letter-spacing: -0.5px;
    }

    .hero-sub {
        color: #475569;
        font-size: 14.5px;
        line-height: 1.5;
        margin: 0;
        max-width: 820px;
    }

    /* Threat Verdict Cards (Light Theme) */
    .verdict-box {
        border-radius: 12px;
        padding: 24px 20px;
        text-align: center;
        margin-bottom: 18px;
        border: 1px solid transparent;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05);
    }

    .verdict-scam {
        background: #FEF2F2;
        border-color: #FECACA;
    }

    .verdict-suspicious {
        background: #FFFBEB;
        border-color: #FDE68A;
    }

    .verdict-safe {
        background: #F0FDF4;
        border-color: #BBF7D0;
    }

    .score-label-scam { color: #991B1B; }
    .score-label-suspicious { color: #92400E; }
    .score-label-safe { color: #166534; }

    .score-label {
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        margin-bottom: 4px;
    }

    .score-number {
        font-size: 54px;
        font-weight: 800;
        line-height: 1;
        letter-spacing: -1.5px;
        margin: 6px 0;
    }

    .verdict-badge {
        display: inline-block;
        font-size: 14px;
        font-weight: 700;
        padding: 5px 14px;
        border-radius: 9999px;
        color: #FFFFFF;
        margin-top: 6px;
    }

    .badge-scam { background: #DC2626; }
    .badge-suspicious { background: #D97706; }
    .badge-safe { background: #16A34A; }

    /* Clean Document Inspection Window */
    .doc-container {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 10px;
        overflow: hidden;
        margin-top: 10px;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.04);
    }

    .doc-header {
        background: #F8FAFC;
        padding: 8px 14px;
        display: flex;
        align-items: center;
        gap: 6px;
        border-bottom: 1px solid #E2E8F0;
    }

    .doc-dot {
        width: 10px;
        height: 10px;
        border-radius: 50%;
    }
    .doc-red { background: #EF4444; }
    .doc-yellow { background: #F59E0B; }
    .doc-green { background: #10B981; }

    .doc-title {
        color: #64748B;
        font-size: 12px;
        font-weight: 600;
        margin-left: 8px;
        letter-spacing: 0.3px;
    }

    .doc-body {
        padding: 16px 18px;
        color: #1E293B;
        line-height: 1.85;
        font-size: 14.5px;
    }

    /* Red Flag Threat Cards */
    .flag-card {
        background: #FFF5F5;
        border: 1px solid #FED7D7;
        border-left: 4px solid #DC2626;
        border-radius: 8px;
        padding: 12px 14px;
        margin-bottom: 10px;
    }

    .flag-card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 4px;
    }

    .flag-card-title {
        font-weight: 700;
        font-size: 14px;
        color: #991B1B;
    }

    .flag-card-pts {
        background: #FEE2E2;
        color: #991B1B;
        font-weight: 700;
        font-size: 12px;
        padding: 2px 8px;
        border-radius: 6px;
    }

    .flag-card-why {
        color: #475569;
        font-size: 13.5px;
        margin: 4px 0 0 0;
        line-height: 1.45;
    }

    .flag-evidence-chip {
        display: inline-block;
        background: #FFFFFF;
        border: 1px solid #FCA5A5;
        color: #B91C1C;
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px;
        padding: 2px 7px;
        border-radius: 4px;
        margin-top: 6px;
        margin-right: 6px;
    }

    /* Trust / Good Signs */
    .trust-card {
        background: #F0FDF4;
        border: 1px solid #DCFCE7;
        border-left: 4px solid #16A34A;
        border-radius: 8px;
        padding: 10px 14px;
        margin-bottom: 8px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .trust-title {
        color: #166534;
        font-size: 13.5px;
        font-weight: 600;
    }

    .trust-pts {
        background: #DCFCE7;
        color: #15803D;
        font-size: 12px;
        font-weight: 700;
        padding: 2px 8px;
        border-radius: 6px;
    }

    /* Entity Pill Box */
    .entity-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: #FFFFFF;
        border: 1px solid #CBD5E1;
        border-radius: 6px;
        padding: 4px 10px;
        font-size: 13px;
        color: #1E293B;
        margin-right: 6px;
        margin-bottom: 6px;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Helpline Card in Sidebar */
    .helpline-card {
        background: #FEF2F2;
        border: 1px solid #FECACA;
        border-radius: 10px;
        padding: 14px;
        margin-top: 14px;
    }

    /* Clean Button Styling */
    .stButton>button {
        border-radius: 8px;
        font-weight: 600;
        font-size: 13.5px;
        letter-spacing: 0.2px;
        transition: all 0.15s ease;
    }

    /* Metric cards styling */
    div[data-testid="stMetric"] {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 10px 12px;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.03);
    }

    div[data-testid="stMetricLabel"] {
        font-size: 11.5px !important;
        font-weight: 700 !important;
        color: #64748B !important;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    div[data-testid="stMetricValue"] {
        font-size: 19px !important;
        font-weight: 800 !important;
        color: #0F172A !important;
    }

    /* Tabs styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 6px;
        background: #F1F5F9;
        padding: 4px;
        border-radius: 8px;
        border: 1px solid #E2E8F0;
    }

    .stTabs [data-baseweb="tab"] {
        border-radius: 6px;
        font-weight: 600;
        color: #64748B;
        padding: 7px 16px;
        font-size: 13.5px;
    }

    .stTabs [aria-selected="true"] {
        background: #0F172A !important;
        color: #FFFFFF !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Benchmark Sample Titles
sample_titles = ["-- Custom (Paste your own message) --"] + [s["title"] for s in SAMPLES]

# App State Management
if "input_message_text" not in st.session_state:
    st.session_state["input_message_text"] = ""
if "input_company_site" not in st.session_state:
    st.session_state["input_company_site"] = ""
if "selected_sample_title" not in st.session_state:
    st.session_state["selected_sample_title"] = sample_titles[0]
if "res" not in st.session_state:
    st.session_state["res"] = None
if "reported" not in st.session_state:
    st.session_state["reported"] = False
if "last_uploaded_name" not in st.session_state:
    st.session_state["last_uploaded_name"] = None

def set_sample_content(title):
    st.session_state["selected_sample_title"] = title
    st.session_state["last_uploaded_name"] = None
    matched = next((s for s in SAMPLES if s["title"] == title), None)
    if matched:
        st.session_state["input_message_text"] = matched["text"]
        st.session_state["input_company_site"] = ""
    else:
        st.session_state["input_message_text"] = ""
        st.session_state["input_company_site"] = ""
    st.session_state["res"] = None
    st.session_state["reported"] = False

def on_dropdown_change():
    chosen = st.session_state.get("sample_dropdown_key", sample_titles[0])
    set_sample_content(chosen)

# Sidebar Configuration
with st.sidebar:
    st.markdown(
        """
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:14px;">
            <div style="font-size:24px;">🛡️</div>
            <div>
                <div style="font-weight:800; font-size:17px; color:#0F172A;">JobShield</div>
                <div style="font-size:12px; color:#64748B;">Recruitment Fraud Verification</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("### Settings")
    default_key = os.environ.get("GEMINI_API_KEY", "") or os.environ.get("OPENROUTER_API_KEY", "")
    try:
        default_key = default_key or st.secrets.get("GEMINI_API_KEY", "") or st.secrets.get("OPENROUTER_API_KEY", "")
    except Exception:
        pass

    api_key = st.text_input(
        "Enter your API Key",
        value=default_key,
        type="password",
        help="Google Gemini API Key (starts with AIza...) or OpenRouter Key (starts with sk-or...).",
    )
    clean_k = api_key.strip().strip("'\"")
    if clean_k:
        if clean_k.startswith("AIza"):
            st.caption("🟢 Using **Google Gemini API** (`gemini-2.0-flash`)")
        elif clean_k.startswith("sk-or"):
            st.caption("🔵 Using **OpenRouter API**")
        else:
            st.caption("🟢 Using **Google Gemini API**")

    use_ai = st.toggle(
        "AI Web Verification",
        value=bool(default_key),
        help="Searches DuckDuckGo for the company & fraud warnings, then an LLM verifies the evidence.",
    )

    live = st.toggle(
        "Live Domain Age Check",
        value=True,
        help="Queries RDAP/WHOIS. Freshly registered domains (<90 days) are high-risk indicators.",
    )

    with st.expander("Advanced Model Tuning"):
        model = st.text_input(
            "Custom Model (Optional)",
            value="",
            placeholder="e.g. meta-llama/llama-3.3-70b-instruct:free",
            help="Leave blank to automatically auto-select the best available free model.",
        )
        native = st.checkbox(
            "Use OpenRouter Paid Web Search",
            value=False,
            help="Uses OpenRouter's integrated search plugin (consumes credits). Falls back to free DDG if empty.",
        )

    scam_count = checks.count()
    st.markdown(
        f"""
        <div style="background:#FFFFFF; border:1px solid #E2E8F0; border-radius:8px; padding:12px; margin-top:14px; box-shadow:0 1px 2px rgba(0,0,0,0.03);">
            <div style="font-size:11px; text-transform:uppercase; color:#64748B; font-weight:700;">Community Database</div>
            <div style="font-size:20px; font-weight:800; color:#0F172A; margin:2px 0;">{scam_count} <span style="font-size:13px; font-weight:500; color:#64748B;">Known Threats</span></div>
            <div style="font-size:12px; color:#64748B;">Flagged emails, phone numbers & sites</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("🔍 Search & Verify Community Database", expanded=False):
        db_query = st.text_input(
            "Search phone, email, or domain:",
            placeholder="e.g. 9876543210 or quick-earn-jobs.xyz",
            key="db_search_input"
        )
        if db_query.strip():
            results = checks.search_database(db_query.strip())
            if results:
                st.error(f"🚨 Found {len(results)} threat match(es) in database!")
                for kind, val, note, added in results:
                    st.markdown(
                        f"""
                        <div style="background:#FEF2F2; border:1px solid #FECACA; border-radius:6px; padding:6px 10px; margin-bottom:6px; font-size:12px;">
                            <strong>{kind.upper()}:</strong> <code>{val}</code><br>
                            <span style="color:#991B1B;">Reason:</span> {note}<br>
                            <span style="color:#64748B; font-size:10.5px;">Reported: {added or 'Recently'}</span>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
            else:
                st.success(f"✓ No reports found for '{db_query.strip()}'. Not currently flagged.")

        st.markdown("<div style='height:4px;'></div>", unsafe_allow_html=True)
        if st.checkbox("View All Flagged Threats", value=False, key="show_threat_table"):
            all_reports = checks.get_all_reports(limit=30)
            if all_reports:
                st.markdown(
                    "<div style='font-size:11px; font-weight:700; color:#475569; margin-bottom:4px;'>RECENT COMMUNITY THREATS:</div>",
                    unsafe_allow_html=True
                )
                for kind, val, note, added in all_reports:
                    st.markdown(
                        f"""
                        <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:6px; padding:5px 8px; margin-bottom:5px; font-size:11.5px;">
                            <span style="background:#F1F5F9; padding:1px 4px; border-radius:3px; font-weight:600; font-size:10px;">{kind.upper()}</span>
                            <code>{val}</code><br>
                            <span style="color:#475569; font-size:11px;">{note}</span>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
            else:
                st.caption("Database is currently empty.")

        st.markdown("<hr style='margin:10px 0; border:0; border-top:1px solid #E2E8F0;'>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:11.5px; font-weight:700; color:#0F172A;'>Report a Fraud Contact:</div>", unsafe_allow_html=True)
        rep_col1, rep_col2 = st.columns([1, 2])
        with rep_col1:
            rep_kind = st.selectbox("Type", ["phone", "email", "domain"], key="rep_kind_select")
        with rep_col2:
            rep_val = st.text_input("Contact / URL", placeholder="Value...", key="rep_val_input")
        rep_note = st.text_input("Details / Description", placeholder="e.g. asked 1500 registration fee", key="rep_note_input")
        if st.button("Submit Threat to Database", use_container_width=True, key="btn_direct_submit"):
            if rep_val.strip():
                added = checks.add_report(rep_kind, rep_val.strip(), rep_note.strip() or "Community verified threat")
                if added:
                    st.success(f"✓ Added {rep_val.strip()} to community database!")
                    st.rerun()
                else:
                    st.error("Invalid input.")
            else:
                st.warning("Please enter a phone number, email, or domain.")

    st.markdown(
        """
        <div class="helpline-card">
            <div style="display:flex; align-items:center; gap:6px; margin-bottom:4px;">
                <span style="font-size:16px;">🚨</span>
                <span style="font-weight:700; color:#991B1B; font-size:12px; text-transform:uppercase; letter-spacing:0.5px;">National Cyber Helpline</span>
            </div>
            <div style="font-size:12.5px; color:#475569; line-height:1.4;">
                Targeted or lost money? Call immediately:
            </div>
            <div style="font-size:22px; font-weight:800; color:#DC2626; margin:4px 0;">📞 1930</div>
            <div style="font-size:12px; color:#64748B;">
                Lodge complaint: <a href="https://cybercrime.gov.in" target="_blank" style="color:#DC2626; text-decoration:underline; font-weight:600;">cybercrime.gov.in</a>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div style="margin-top:20px; font-size:11px; color:#94A3B8; text-align:center;">
            JobShield • Explainable Rule Forensics<br>
            Protecting job seekers from employment fraud.
        </div>
        """,
        unsafe_allow_html=True,
    )

# Top Hero Banner
st.markdown(
    """
    <div class="hero-container">
        <div class="hero-badge">
            <div class="pulse-dot"></div>
            <span>Verification System Active</span>
        </div>
        <h1 class="hero-title">Job & Internship Offer Verifier</h1>
        <p class="hero-sub">
            Paste suspicious WhatsApp messages, Telegram chats, recruiter emails, or offer letters to check for advance-fee fraud, fake domains, and known recruitment scams before paying any money.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Quick Load Sample Bar
st.markdown("<div style='font-size:12.5px; font-weight:700; color:#475569; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px;'>Try a quick sample:</div>", unsafe_allow_html=True)
q1, q2, q3, q4, q5 = st.columns([1, 1, 1, 1, 1])

with q1:
    if st.button("🚨 Fake Infosys (Fee)", use_container_width=True):
        set_sample_content("Fake Infosys offer letter")
        st.rerun()
with q2:
    if st.button("🚨 Telegram Task Fraud", use_container_width=True):
        set_sample_content("YouTube like task group")
        st.rerun()
with q3:
    if st.button("🚨 Laptop Kit Scam", use_container_width=True):
        set_sample_content("Soft scam: laptop kit purchase")
        st.rerun()
with q4:
    if st.button("🛡️ Infosys Official", use_container_width=True):
        set_sample_content("Infosys campus hiring mail")
        st.rerun()
with q5:
    if st.button("🛡️ Wipro Elite Drive", use_container_width=True):
        set_sample_content("Wipro hiring notification")
        st.rerun()

# Main Input & Score Layout
col_input, col_score = st.columns([3, 2])

with col_input:
    st.markdown("<div style='font-weight:700; font-size:15px; margin-bottom:6px; color:#0F172A;'>Offer Text & Details</div>", unsafe_allow_html=True)

    curr_selected = st.session_state.get("selected_sample_title", sample_titles[0])
    sel_idx = sample_titles.index(curr_selected) if curr_selected in sample_titles else 0

    st.selectbox(
        "Choose a sample message (20 benchmark test cases):",
        sample_titles,
        index=sel_idx,
        key="sample_dropdown_key",
        on_change=on_dropdown_change,
        help="Select a realistic job offer sample to see how the engine and AI evaluate it.",
    )

    st.markdown(
        """
        <div style="display: flex; align-items: center; text-align: center; margin: 12px 0 10px 0;">
            <div style="flex-grow: 1; border-bottom: 1px solid #CBD5E1;"></div>
            <span style="padding: 0 14px; color: #475569; font-weight: 700; font-size: 12px; letter-spacing: 1px;">— OR —</span>
            <div style="flex-grow: 1; border-bottom: 1px solid #CBD5E1;"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("📷 / 📄 Upload an Image or PDF (Offer Letter / Screenshot)", expanded=False):
        uploaded_doc = st.file_uploader(
            "Upload an offer letter screenshot or document:",
            type=["png", "jpg", "jpeg", "webp", "pdf"],
            key="offer_doc_uploader",
            help="Extracts text directly from PDF documents or scans using OCR, then fills the text area.",
        )
        if uploaded_doc is not None:
            if st.session_state.get("last_uploaded_name") != uploaded_doc.name:
                with st.spinner("Extracting text from offer document..."):
                    extracted_text, ocr_err = ocr.extract_text(uploaded_doc, api_key=api_key)
                    if extracted_text:
                        st.session_state["input_message_text"] = extracted_text
                        st.session_state["last_uploaded_name"] = uploaded_doc.name
                        st.session_state["selected_sample_title"] = sample_titles[0]
                        st.success(f"✓ Extracted text from {uploaded_doc.name} successfully!")
                        st.rerun()
                    else:
                        st.error(f"Text Extraction Notice: {ocr_err}")
            else:
                st.caption(f"✓ Active document: `{uploaded_doc.name}`")
                if uploaded_doc.type.startswith("image"):
                    st.image(uploaded_doc, caption=uploaded_doc.name, use_container_width=True)

    msg_text = st.text_area(
        "Job message, offer letter, recruiter chat or email text:",
        height=180,
        placeholder="Paste the WhatsApp text, Telegram message, recruiter email body, or job description here...",
        key="input_message_text",
    )

    c_sub1, c_sub2 = st.columns([2, 1])
    with c_sub1:
        comp_site = st.text_input(
            "Company Official Website (Optional)",
            placeholder="e.g. infosys.com or amazon.jobs",
            help="Providing the real company website allows the engine to flag mismatched recruiter email domains.",
            key="input_company_site",
        )
    with c_sub2:
        st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
        btn_clear = st.button("Clear Input", use_container_width=True)
        if btn_clear:
            set_sample_content(sample_titles[0])
            st.session_state["last_uploaded_name"] = None
            st.rerun()

    analyze_clicked = st.button("Check This Offer", type="primary", use_container_width=True)

# Analysis Execution
if analyze_clicked:
    if not msg_text.strip():
        st.warning("Please paste a job offer message or choose a sample to inspect.")
    else:
        with st.spinner("Analyzing message patterns and domains..."):
            res_new = engine.analyze(msg_text, company_site=comp_site.strip(), live=live)

        if use_ai:
            if not api_key.strip():
                res_new["ai"] = {"ok": False, "error": "OpenRouter API Key not set in sidebar"}
            else:
                with st.spinner("Searching the web and asking the AI (15-30s)..."):
                    ai_audit = ai.verify(
                        msg_text,
                        res_new["emails"],
                        res_new["urls"],
                        res_new["phones"],
                        [f.id for f in res_new["flags"]],
                        comp_site.strip(),
                        api_key,
                        company=res_new.get("company", ""),
                        model=model.strip(),
                        native_search=native,
                    )
                res_new = ai.combine(res_new, ai_audit)

        st.session_state["res"] = res_new
        st.session_state["reported"] = False

res = st.session_state.get("res")

# Right Column: Risk Verdict Card
with col_score:
    st.markdown("<div style='font-weight:700; font-size:15px; margin-bottom:6px; color:#0F172A;'>Risk Assessment</div>", unsafe_allow_html=True)

    if res:
        v = res["verdict"]
        score = res["score"]

        # Color & label mappings
        if v == "SCAM":
            card_class = "verdict-scam"
            lbl_class = "score-label-scam"
            badge_class = "badge-scam"
            status_text = "LIKELY SCAM"
            sub_label = "Do not pay any money or share sensitive documents"
        elif v == "SUSPICIOUS":
            card_class = "verdict-suspicious"
            lbl_class = "score-label-suspicious"
            badge_class = "badge-suspicious"
            status_text = "SUSPICIOUS"
            sub_label = "Proceed with caution • Confirm on official careers page"
        else:
            card_class = "verdict-safe"
            lbl_class = "score-label-safe"
            badge_class = "badge-safe"
            status_text = "LOOKS SAFE"
            sub_label = "No major red flags or fee demands detected"

        st.markdown(
            f"""
            <div class="verdict-box {card_class}">
                <div class="score-label {lbl_class}">RISK SCORE</div>
                <div class="score-number {lbl_class}">{score}<span style="font-size:22px; font-weight:500; opacity:0.8;">/100</span></div>
                <div class="verdict-badge {badge_class}">{status_text}</div>
                <div style="font-size:12.5px; margin-top:8px; color:#475569;">{sub_label}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.progress(score / 100)

        # Score breakdown cards
        b1, b2, b3 = st.columns(3)
        b1.metric("Rule Score", f"{res.get('rule_score', res.get('score', 0))}")
        ai_meta = res.get("ai")
        if ai_meta and ai_meta.get("ok") and ai_meta.get("grounded"):
            b2.metric("AI Score", f"{ai_meta['risk_score']}")
        else:
            b2.metric("AI Check", "Offline")
        b3.metric("Good Signs", f"-{res.get('positive_credit', 0)}")

        if res.get("hard"):
            st.markdown(
                """
                <div style="background:#FEF2F2; border:1px solid #FECACA; border-radius:6px; padding:10px 12px; margin-top:10px; font-size:13px; color:#991B1B;">
                    <strong>Critical Red Flag:</strong> Demands upfront money, banking OTP, or matches the reported scam database. Score is locked to at least 70/100.
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            """
            <div style="background:#FFFFFF; border:1px dashed #CBD5E1; border-radius:12px; padding:45px 20px; text-align:center;">
                <div style="font-size:38px; margin-bottom:8px;">🛡️</div>
                <div style="font-size:16px; font-weight:700; color:#0F172A;">No Offer Checked Yet</div>
                <div style="font-size:13px; color:#64748B; margin-top:4px; line-height:1.5;">
                    Select a sample above or paste an offer message to see the risk score, flagged phrases, and next steps.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# Detailed Multi-Tab Breakdown
if res:
    st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
    t1, t2, t3 = st.tabs([
        "Threat Breakdown & Flagged Text",
        "Entity & AI Web Verification",
        "Recommended Next Steps",
    ])

    with t1:
        st.markdown("### Highlighted Message Text")
        st.markdown(
            """
            <div class="doc-container">
                <div class="doc-header">
                    <div class="doc-dot doc-red"></div>
                    <div class="doc-dot doc-yellow"></div>
                    <div class="doc-dot doc-green"></div>
                    <span class="doc-title">FLAGGED PHRASES HIGHLIGHTED</span>
                </div>
                <div class="doc-body">
            """,
            unsafe_allow_html=True,
        )

        if res["flags"]:
            st.markdown(engine.highlight_html(res), unsafe_allow_html=True)
        else:
            st.markdown(f"<div style='white-space:pre-wrap; color:#1E293B;'>{res['text']}</div>", unsafe_allow_html=True)

        st.markdown("</div></div>", unsafe_allow_html=True)

        st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)
        col_flags, col_good = st.columns([3, 2])

        with col_flags:
            st.markdown(f"#### Red Flags Found ({len(res['flags'])})")
            if not res["flags"]:
                st.markdown(
                    """
                    <div style="background:#F0FDF4; border:1px solid #BBF7D0; border-radius:8px; padding:12px; color:#166534; font-size:13.5px;">
                        ✓ No red flags found in this message.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                for f in res["flags"]:
                    evidence_html = "".join([f"<span class='flag-evidence-chip'>{ev}</span>" for ev in dict.fromkeys(f.evidence)])
                    st.markdown(
                        f"""
                        <div class="flag-card">
                            <div class="flag-card-header">
                                <span class="flag-card-title">{f.title}</span>
                                <span class="flag-card-pts">+{f.points} PTS</span>
                            </div>
                            <div class="flag-card-why">{f.why}</div>
                            <div style="margin-top:4px;">{evidence_html}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

        with col_good:
            st.markdown(f"#### Good Signs ({len(res['positives'])})")
            if not res["positives"]:
                st.markdown(
                    """
                    <div style="color:#64748B; font-size:13px; padding:10px; background:#F1F5F9; border-radius:6px;">
                        No explicit good signs found (such as an official careers link, multi-stage assessment, or formal no-fee disclaimer).
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            else:
                for p in res["positives"]:
                    st.markdown(
                        f"""
                        <div class="trust-card">
                            <span class="trust-title">✓ {p['title']}</span>
                            <span class="trust-pts">-{p['points']} PTS</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                if res["hard"]:
                    st.caption("Not counted: a critical red flag overrides good signs.")
                else:
                    st.caption(f"Total credit applied: -{res['positive_credit']} pts (capped at {engine.POSITIVE_CAP}).")

    with t2:
        st.markdown("### Extracted Contact Details")

        e1, e2 = st.columns(2)
        with e1:
            st.markdown("#### Recruiter Emails")
            if res["emails"]:
                for e in res["emails"]:
                    domain = e.split("@")[-1].lower() if "@" in e else ""
                    is_free = domain in engine.FREE_MAIL
                    tag = "Free Webmail" if is_free else "Corporate Domain"
                    st.markdown(
                        f"""
                        <div class="entity-pill">
                            <span>📧 {e}</span>
                            <span style="font-size:11px; background:#F1F5F9; border:1px solid #E2E8F0; padding:1px 5px; border-radius:4px; color:#475569;">{tag}</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown("<span style='color:#64748B; font-size:13px;'>No email addresses found.</span>", unsafe_allow_html=True)

            st.markdown("#### Phone Numbers & WhatsApp")
            if res["phones"]:
                for p in res["phones"]:
                    st.markdown(f"<div class='entity-pill'><span>📞 +91 {p[-10:]}</span></div>", unsafe_allow_html=True)
            else:
                st.markdown("<span style='color:#64748B; font-size:13px;'>No phone numbers found.</span>", unsafe_allow_html=True)

        with e2:
            st.markdown("#### Links & Domains")
            if res["urls"]:
                for u in res["urls"]:
                    d = engine._domain_of(u)
                    is_short = d in engine.SHORTENERS
                    is_msg = d in engine.MESSENGER_HOSTS
                    tag = "Shortener" if is_short else ("Messaging" if is_msg else "Link")
                    st.markdown(
                        f"""
                        <div class="entity-pill">
                            <span>{u[:45]}{'...' if len(u)>45 else ''}</span>
                            <span style="font-size:11px; background:#F1F5F9; border:1px solid #E2E8F0; padding:1px 5px; border-radius:4px; color:#475569;">{tag}</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown("<span style='color:#64748B; font-size:13px;'>No links found.</span>", unsafe_allow_html=True)

            st.markdown("#### Live Domain Age Checks")
            if res["live_notes"]:
                for n in res["live_notes"]:
                    st.markdown(
                        f"""
                        <div style="background:#F8FAFC; border:1px solid #E2E8F0; border-radius:6px; padding:6px 12px; margin-bottom:6px; font-size:13px; color:#334155;">
                            🌐 {n}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown("<span style='color:#64748B; font-size:13px;'>No domain age alerts.</span>", unsafe_allow_html=True)

        st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
        st.markdown("### AI Web Verification")
        ai_res = res.get("ai")
        if not ai_res:
            st.info("AI Web Verification is off. Enable it in the sidebar with a free OpenRouter key to check company domains against live search.")
        elif not ai_res.get("ok"):
            st.warning(f"AI Verification Error: {ai_res.get('error')}. Showing rule-based score only.")
        else:
            if not ai_res.get("grounded"):
                st.warning("Insufficient web evidence was found; AI results are advisory and not included in the score.")

            st.markdown(
                f"""
                <div style="background:#FFFFFF; border:1px solid #E2E8F0; border-radius:8px; padding:16px; margin-bottom:14px; box-shadow:0 1px 2px rgba(0,0,0,0.03);">
                    <div style="font-size:12px; font-weight:700; color:#475569; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">
                        AI Summary ({ai_res.get('model', 'Free Model')})
                    </div>
                    <div style="font-size:14.5px; color:#1E293B; line-height:1.55;">
                        {ai_res['summary']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # 3 Verification Metrics
            m1, m2, m3 = st.columns(3)
            m1.metric("Company Exists?", ai_res["company_exists"].upper())
            m2.metric("Contacts Match Records?", ai_res["contacts_match_company"].upper())
            m3.metric("Named in Scam Reports?", ai_res["reported_as_scam"].upper())

            if ai_res.get("official_site"):
                st.markdown(f"**Official Corporate Website:** `{ai_res['official_site']}`")

            st.markdown("#### Structured Findings:")
            for f in ai_res["findings"]:
                st.markdown(
                    f"""
                    <div style="background:#FFFFFF; border:1px solid #E2E8F0; border-radius:6px; padding:9px 12px; margin-bottom:6px;">
                        <span style="font-weight:700; color:#0F172A;">{f['check']}</span>: <span style="color:#334155;">{f['result']}</span>
                        <div style="font-size:12.5px; color:#64748B; margin-top:3px; font-style:italic;">Evidence: {f['evidence']}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            if ai_res.get("sources"):
                st.markdown("#### Web Sources Used:")
                for s in ai_res["sources"][:6]:
                    st.markdown(f"- [{s['title']}]({s['url']})")

    with t3:
        st.markdown("### What To Do Next")

        col_act1, col_act2 = st.columns([3, 2])

        with col_act1:
            st.markdown("#### Recommended Actions:")
            for idx, a in enumerate(res["advice"], 1):
                st.markdown(
                    f"""
                    <div style="background:#FFFFFF; border:1px solid #E2E8F0; border-radius:8px; padding:12px 14px; margin-bottom:8px; display:flex; align-items:center; gap:12px; box-shadow:0 1px 2px rgba(0,0,0,0.02);">
                        <div style="background:#0F172A; color:#FFFFFF; width:24px; height:24px; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:12px; flex-shrink:0;">
                            {idx}
                        </div>
                        <div style="color:#1E293B; font-size:13.5px; line-height:1.4;">
                            {a}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        with col_act2:
            st.markdown("#### Report This Offer")
            st.markdown(
                """
                Help protect other candidates. Submitting this offer adds the detected email, phone number, and domain to the local JobShield database.
                """
            )

            if res["verdict"] != "SAFE":
                is_reported = st.session_state.get("reported", False)
                if st.button("Report to Database", type="secondary", disabled=is_reported, use_container_width=True):
                    for e in res["emails"]:
                        checks.add_report("email", e, "User verified threat submission")
                    for u in res["urls"]:
                        d = engine._domain_of(u)
                        if d not in engine.SHORTENERS and d not in engine.MESSENGER_HOSTS:
                            checks.add_report("domain", d, "User verified threat submission")
                    for p in res["phones"]:
                        checks.add_report("phone", p, "User verified threat submission")
                    st.session_state["reported"] = True
                    st.success("Saved to database. Future checks for these contacts will be warned.")
                    st.rerun()
                if is_reported:
                    st.info("Already submitted to the database.")
            else:
                st.info("Only suspicious or scam offers can be submitted to the database.")

            st.markdown(
                """
                <div style="background:#FEF2F2; border:1px solid #FECACA; border-radius:8px; padding:12px; margin-top:14px;">
                    <div style="font-weight:700; font-size:13px; color:#991B1B; margin-bottom:3px;">Cybercrime Helpline:</div>
                    <div style="font-size:12.5px; color:#475569; line-height:1.5;">
                        • Call <strong>1930</strong> (Toll-free fraud hotline)<br>
                        • File official complaint at <strong>cybercrime.gov.in</strong><br>
                        • If money was debited, contact your bank immediately to freeze the transaction.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
