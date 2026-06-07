"""
OverflowGuard — Streamlit UI
Ata Beyazıt
"""
from __future__ import annotations

import streamlit as st
from analyzer import analyze, Finding
from history_store import delete_history_entry, entry_summary, entry_to_findings, load_history, record_analysis
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


def _history_cell(text: str, selected: bool, *, bold: bool = False, align: str = "left") -> str:
    bg = "#dbeafe" if selected else "#f8fafc"
    border = "2px solid #2563eb" if selected else "1px solid #cbd5e1"
    weight = "700" if bold else "400"
    text_color = "#0f172a"
    return (
        f"<div style='background:{bg};border:{border};border-radius:10px;"
        f"padding:10px 12px;font-weight:{weight};text-align:{align};"
        f"box-shadow:{'0 0 0 2px rgba(37,99,235,.12)' if selected else 'none'};"
        f"color:{text_color};line-height:1.25'>"
        f"{text}</div>"
    )


def _scroll_to_results() -> None:
    st.components.v1.html(
        """
        <script>
        setTimeout(() => {
          const target = window.parent.document.getElementById('results-anchor');
          if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
          }
        }, 150);
        </script>
        """,
        height=0,
    )


def _render_analysis_view(filename: str, source: str, findings: list[Finding]) -> None:
    st.markdown('<div id="results-anchor"></div>', unsafe_allow_html=True)
    st.divider()

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
    else:
        st.markdown("### Findings")

        header = (
            "<table style='width:100%;border-collapse:collapse'>"
            "<thead><tr style='background:#1a1a2e;color:#fff'>"
            "<th style='padding:10px 12px;text-align:center'>Line</th>"
            "<th style='padding:10px 12px'>Function</th>"
            "<th style='padding:10px 12px'>Expression</th>"
            "<th style='padding:10px 12px'>Code</th>"
            "<th style='padding:10px 12px;text-align:center'>Severity</th>"
            "<th style='padding:10px 12px;text-align:center'>Risk Type</th>"
            "<th style='padding:10px 12px;text-align:center'>Certainty</th>"
            "<th style='padding:10px 12px;text-align:center'>Confidence</th>"
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
                f"<td style='text-align:center;font-weight:bold;padding:9px 12px;color:#1f2937'>{f.line_number}</td>"
                f"<td style='padding:9px 12px;color:#1f2937;font-weight:600'>{f.function_name}</td>"
                f"<td style='padding:9px 12px;color:#1f2937'><code style='font-size:.88em;color:#1f2937;background:rgba(255,255,255,.35);padding:2px 6px;border-radius:4px'>{f.expression[:80]}</code></td>"
                f"<td style='padding:9px 12px;color:#1f2937'><code style='font-size:.88em;color:#1f2937;background:rgba(255,255,255,.35);padding:2px 6px;border-radius:4px'>{f.line_content[:80]}</code></td>"
                f"<td style='text-align:center;padding:9px 12px'>{_badge(f.risk)}</td>"
                f"<td style='text-align:center;padding:9px 12px;font-weight:600;color:#1f2937'>{f.risk_type}</td>"
                f"<td style='text-align:center;padding:9px 12px;font-weight:600;color:#1f2937'>{f.certainty_type}</td>"
                f"<td style='text-align:center;padding:9px 12px;font-weight:bold;color:#1f2937'>{f.confidence}</td>"
                f"<td style='padding:9px 12px;font-size:.9em;color:#1f2937'>{f.reason}</td>"
                f"<td style='padding:9px 12px;font-size:.85em;font-family:monospace;color:#1f2937'>{f.suggestion}</td>"
                "</tr>"
            )

        st.html(header + rows + "</tbody></table>")

        st.markdown("### Details")
        for f in findings:
            label = f"{RISK_EMOJI.get(f.risk,'⚪')} Line {f.line_number} — {f.risk}"
            with st.expander(label):
                st.markdown(f"**Code:** `{f.line_content}`")
                st.markdown(f"**Reason:** {f.reason}")
                st.code(f.suggestion, language="c")

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


def _render_history_detail_panel(entry: dict[str, object]) -> None:
    filename = str(entry.get("filename", "unknown.c"))
    source = str(entry.get("source", ""))
    findings = entry_to_findings(entry)
    counts = {r: sum(1 for f in findings if f.risk == r) for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    created_at = str(entry.get("created_at", "")).replace("T", " ")[:19] or "-"

    st.markdown("### Kayıt Detayı")
    st.markdown(f"**Dosya:** `{filename}`")
    st.caption(f"{created_at} · {int(entry.get('total_findings', len(findings)))} findings")

    c1, c2 = st.columns(2)
    c1.metric("Critical", counts["CRITICAL"])
    c2.metric("High", counts["HIGH"])
    c3, c4 = st.columns(2)
    c3.metric("Medium", counts["MEDIUM"])
    c4.metric("Low", counts["LOW"])

    st.divider()

    with st.expander("📄 Source Preview", expanded=False):
        st.code(source, language="c", line_numbers=True)

    if findings:
        st.markdown("##### Findings")
        for f in findings:
            label = f"{RISK_EMOJI.get(f.risk,'⚪')} Line {f.line_number} — {f.risk}"
            with st.expander(label):
                st.markdown(f"**Function:** `{f.function_name}`")
                st.markdown(f"**Expression:** `{f.expression}`")
                st.markdown(f"**Code:** `{f.line_content}`")
                st.markdown(f"**Risk Type:** `{f.risk_type}`")
                st.markdown(f"**Certainty:** `{f.certainty_type}`")
                st.markdown(f"**Confidence:** `{f.confidence}`")
                st.markdown(f"**Reason:** {f.reason}")
                st.code(f.suggestion, language="c")
    else:
        st.info("Bu kayıtta finding yok.")

    st.divider()
    html_report = generate_html(filename, source, findings)
    st.download_button(
        label="⬇️ Download HTML Report",
        data=html_report,
        file_name=f"overflowguard_{filename}.html",
        mime="text/html",
        type="primary",
        use_container_width=True,
        key=f"download_{entry.get('id', '')}",
    )

    if st.button("🗑️ Kaydı Sil", type="secondary", use_container_width=True, key=f"delete_{entry.get('id', '')}"):
        deleted = delete_history_entry(str(entry.get("id", "")))
        if deleted:
            st.session_state.pop("selected_history_id", None)
            st.session_state.history_view = "history_table"
            st.rerun()
        else:
            st.error("Kayıt silinemedi.")

# ── sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/security-checked.png", width=72)
    st.title("OverflowGuard")
    st.caption("Static Integer Overflow Analyzer")
    st.divider()
    st.markdown(
        """
        <div style="
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f8fafc;
            padding: 14px 16px;
            border-radius: 14px;
            border: 1px solid #334155;
            margin-bottom: 10px;
            box-shadow: 0 8px 24px rgba(15, 23, 42, 0.18);
        ">
            <div style="font-size: 0.78rem; letter-spacing: 0.14em; text-transform: uppercase; color: #93c5fd; font-weight: 700;">
                Menu
            </div>
            <div style="font-size: 1.35rem; font-weight: 800; margin-top: 4px;">
                Analysis View
            </div>
            <div style="font-size: 0.88rem; color: #cbd5e1; margin-top: 4px;">
                Switch between live analysis and past reviews.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    menu = st.radio(
        "",
        ["Yeni Analiz", "Daha Önce İncelenenler"],
        label_visibility="collapsed",
        captions=["Upload and scan a C file", "Browse saved analyses"],
    )
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

if "findings" not in st.session_state:
    st.session_state.findings = None
    st.session_state.analyzed_file = None
    st.session_state.analyzed_source = None

if menu == "Yeni Analiz":
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

    if analyze_btn:
        with st.spinner("Analyzing…"):
            findings = sorted(analyze(source), key=_severity_order)
        st.session_state.findings = findings
        st.session_state.analyzed_file = filename
        st.session_state.analyzed_source = source
        record_analysis(filename, source, findings)
        st.session_state.scroll_to_results = True

    findings = st.session_state.findings
    analyzed_file = st.session_state.analyzed_file
    analyzed_source = st.session_state.analyzed_source

    if findings is None or analyzed_file is None or analyzed_source is None:
        st.stop()

    _render_analysis_view(analyzed_file, analyzed_source, findings)

    if st.session_state.get("scroll_to_results"):
        _scroll_to_results()
        st.session_state.scroll_to_results = False

else:
    history = load_history()
    st.markdown("Previously analyzed files are stored here so you can review them later.")

    if not history:
        st.info("Henüz kaydedilmiş analiz yok.")
        st.stop()

    filter_text = st.text_input(
        "Dosya adına göre filtrele",
        value="",
        placeholder="Örn: risky_add.c",
    ).strip().lower()

    if filter_text:
        filtered_history = [entry for entry in history if filter_text in str(entry.get("filename", "")).lower()]
    else:
        filtered_history = history

    if not filtered_history:
        st.warning("Filtreye uyan kayıt bulunamadı.")
        st.stop()

    if "history_view" not in st.session_state:
        st.session_state.history_view = "history_table"

    if "selected_history_id" not in st.session_state:
        st.session_state.selected_history_id = str(filtered_history[0].get("id", ""))

    selected_history_id = st.session_state.get("selected_history_id")
    selected_entry = None
    if selected_history_id:
        for entry in filtered_history:
            if str(entry.get("id", "")) == str(selected_history_id):
                selected_entry = entry
                break

    if selected_entry is None:
        selected_entry = filtered_history[0]
        st.session_state.selected_history_id = str(selected_entry.get("id", ""))

    if st.session_state.history_view == "history_detail":
        st.markdown("### Kayıt Detayı")
        top_left, top_right = st.columns([1, 5])
        with top_left:
            if st.button("← Tabloya Dön", use_container_width=True):
                st.session_state.history_view = "history_table"
                st.rerun()
        with top_right:
            st.caption("Detay ekranı ayrı görünüm olarak açılır. Tabloya dönmek için geri butonunu kullan.")

        _render_history_detail_panel(selected_entry)
    else:
        st.markdown("#### Kayıt Tablosu")
        st.caption("Satırda özet bilgiler görürsün. Detay butonu ayrı detay ekranını açar.")

        table_header = st.columns([2.7, 1.3, 0.8, 0.7, 0.7, 0.7, 0.7, 0.9])
        header_labels = ["Dosya", "Tarih", "Toplam", "C", "H", "M", "L", "Aksiyon"]
        for col, label in zip(table_header, header_labels):
            col.markdown(
                f"<div style='background:#0f172a;color:#f8fafc;padding:10px 12px;"
                f"border-radius:10px;font-weight:700;border:1px solid #1e293b'>{label}</div>",
                unsafe_allow_html=True,
            )

        for idx, entry in enumerate(filtered_history):
            findings = entry_to_findings(entry)
            counts = {r: sum(1 for f in findings if f.risk == r) for r in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
            created_at = str(entry.get("created_at", "")).replace("T", " ")[:19]
            entry_id = str(entry.get("id", ""))
            selected = str(st.session_state.get("selected_history_id", "")) == entry_id
            row = st.columns([2.7, 1.3, 0.8, 0.7, 0.7, 0.7, 0.7, 0.9])
            shade = "#eff6ff" if selected else ("#f8fafc" if idx % 2 == 0 else "#eef2f7")
            row[0].markdown(
                _history_cell(
                    f"<div><strong>{entry_summary(entry).split(' · ')[0]}</strong></div>"
                    f"<div style='font-size:.8em;color:#475569;margin-top:4px'>ID: {entry_id[:8]} · {counts['CRITICAL']} critical · {counts['HIGH']} high</div>",
                    selected,
                ).replace("background:#f8fafc", f"background:{shade}"),
                unsafe_allow_html=True,
            )
            row[1].markdown(_history_cell(created_at or "-", selected, align="center").replace("background:#f8fafc", f"background:{shade}"), unsafe_allow_html=True)
            row[2].markdown(_history_cell(str(int(entry.get("total_findings", len(findings)))), selected, bold=True, align="center").replace("background:#f8fafc", f"background:{shade}"), unsafe_allow_html=True)
            row[3].markdown(_history_cell(str(counts["CRITICAL"]), selected, bold=True, align="center").replace("background:#f8fafc", f"background:{shade}"), unsafe_allow_html=True)
            row[4].markdown(_history_cell(str(counts["HIGH"]), selected, bold=True, align="center").replace("background:#f8fafc", f"background:{shade}"), unsafe_allow_html=True)
            row[5].markdown(_history_cell(str(counts["MEDIUM"]), selected, bold=True, align="center").replace("background:#f8fafc", f"background:{shade}"), unsafe_allow_html=True)
            row[6].markdown(_history_cell(str(counts["LOW"]), selected, bold=True, align="center").replace("background:#f8fafc", f"background:{shade}"), unsafe_allow_html=True)
            button_label = "Seçili" if selected else "Detay"
            if row[7].button(button_label, key=f"detail_{entry_id}", use_container_width=True, type="primary" if selected else "secondary"):
                st.session_state.selected_history_id = entry_id
                st.session_state.history_view = "history_detail"
                st.rerun()
