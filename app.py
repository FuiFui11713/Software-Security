"""
OverflowGuard — Streamlit UI
Ata Beyazıt
"""
from __future__ import annotations

import streamlit as st
from analyzer import analyze, Finding
from report import generate_html

# ── page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="OverflowGuard",
    page_icon="🔍",
    layout="wide",
)

# ── palette ──────────────────────────────────────────────────────────────────
RISK_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#d4ac0d",
    "LOW":      "#27ae60",
}
RISK_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

# ── helpers ───────────────────────────────────────────────────────────────────
def _badge(risk: str) -> str:
    color = RISK_COLOR.get(risk, "#333")
    emoji = RISK_EMOJI.get(risk, "⚪")
    return (
        f'<span style="background:{color};color:#fff;padding:3px 10px;'
        f'border-radius:12px;font-size:0.82em;font-weight:bold">'
        f'{emoji} {risk}</span>'
    )

def _severity_order(f: Finding) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.risk, 9)

# ── sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/security-checked.png", width=72)
    st.title("OverflowGuard")
    st.caption("Static Integer Overflow Analyzer")
    st.divider()
    st.markdown("""
**What we detect**
- `INT_MAX + 1` boundary violations
- `malloc(n * sizeof(...))` allocation overflows
- Unchecked multiplication `a * b`
- Risky addition `a + b`
- Underflow-prone subtraction `a - b`

**Severity levels**
🔴 CRITICAL · 🟠 HIGH · 🟡 MEDIUM · 🟢 LOW
""")
    st.divider()
    st.caption("CWE-190 · Integer Overflow or Wraparound")

# ── main area ─────────────────────────────────────────────────────────────────
st.title("🔍 OverflowGuard")
st.subheader("Integer Overflow Vulnerability Detection Tool")
st.markdown("Upload a **C source file** to detect potential integer overflow vulnerabilities.")

uploaded = st.file_uploader(
    "Choose a .c file",
    type=["c", "h"],
    help="Supported: .c and .h files",
)

if uploaded is None:
    st.info("Upload a C file above to start analysis.")
    st.stop()

source = uploaded.read().decode("utf-8", errors="replace")
filename = uploaded.name

col_l, col_r = st.columns([3, 2])

with col_l:
    with st.expander("📄 Source Preview", expanded=True):
        st.code(source, language="c", line_numbers=True)

with col_r:
    st.markdown(f"**File:** `{filename}`")
    st.markdown(f"**Lines:** {len(source.splitlines())}")
    analyze_btn = st.button("🔎 Analyze", type="primary", use_container_width=True)

# ── analysis ──────────────────────────────────────────────────────────────────
if "findings" not in st.session_state:
    st.session_state.findings = None
    st.session_state.analyzed_file = None

if analyze_btn:
    with st.spinner("Analyzing…"):
        findings = sorted(analyze(source), key=_severity_order)
    st.session_state.findings = findings
    st.session_state.analyzed_file = filename

findings: list[Finding] | None = st.session_state.findings

if findings is None:
    st.stop()

st.divider()

# ── summary metrics ───────────────────────────────────────────────────────────
total = len(findings)
counts = {r: sum(1 for f in findings if f.risk == r)
          for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}

m0, m1, m2, m3, m4 = st.columns(5)
m0.metric("Total Findings", total)
m1.metric("🔴 Critical", counts["CRITICAL"])
m2.metric("🟠 High",     counts["HIGH"])
m3.metric("🟡 Medium",   counts["MEDIUM"])
m4.metric("🟢 Low",      counts["LOW"])

if total == 0:
    st.success("✅ No integer overflow vulnerabilities detected.")
    st.stop()

# ── findings table ────────────────────────────────────────────────────────────
st.markdown("### Findings")

header = (
    "<table style='width:100%;border-collapse:collapse'>"
    "<thead><tr style='background:#1a1a2e;color:#fff'>"
    "<th style='padding:10px 12px;text-align:center'>Line</th>"
    "<th style='padding:10px 12px'>Code</th>"
    "<th style='padding:10px 12px;text-align:center'>Severity</th>"
    "<th style='padding:10px 12px'>Reason</th>"
    "<th style='padding:10px 12px'>Suggested Fix</th>"
    "</tr></thead><tbody>"
)

rows = ""
ROW_BG = {
    "CRITICAL": "#fde8e8",
    "HIGH":     "#fef3e2",
    "MEDIUM":   "#fefce8",
    "LOW":      "#eafaf1",
}
for f in findings:
    bg = ROW_BG.get(f.risk, "#fff")
    rows += (
        f"<tr style='background:{bg};border-bottom:1px solid #ddd'>"
        f"<td style='text-align:center;font-weight:bold;padding:9px 12px'>{f.line_number}</td>"
        f"<td style='padding:9px 12px'><code style='font-size:.88em'>{f.line_content[:80]}</code></td>"
        f"<td style='text-align:center;padding:9px 12px'>{_badge(f.risk)}</td>"
        f"<td style='padding:9px 12px;font-size:.9em'>{f.reason}</td>"
        f"<td style='padding:9px 12px;font-size:.85em;font-family:monospace'>{f.suggestion}</td>"
        "</tr>"
    )

st.html(header + rows + "</tbody></table>")

# ── detail expanders ──────────────────────────────────────────────────────────
st.markdown("### Details")
for f in findings:
    label = f"{RISK_EMOJI.get(f.risk,'⚪')} Line {f.line_number} — {f.risk}"
    with st.expander(label):
        st.markdown(f"**Code:** `{f.line_content}`")
        st.markdown(f"**Reason:** {f.reason}")
        st.code(f.suggestion, language="c")

# ── download HTML report ──────────────────────────────────────────────────────
st.divider()
html_report = generate_html(filename, source, findings)

st.download_button(
    label="⬇️ Download HTML Report",
    data=html_report,
    file_name=f"overflowguard_{filename}.html",
    mime="text/html",
    type="primary",
    use_container_width=True,
)
