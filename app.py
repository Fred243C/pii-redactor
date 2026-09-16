from __future__ import annotations

import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

import detector
import redactor
from detector import ENTITY_TYPES, LoadError, expand_entity_selection

# --------------------------------------------------------------------------
# Page setup and palette
# --------------------------------------------------------------------------
st.set_page_config(page_title="PII Redaction Tool", page_icon="🔒", layout="wide")

NAVY = "#2F4A63"
BG = "#FAFBFC"
PANEL = "#F4F6F8"
GREEN = "#DCEBD5"
GREEN_EDGE = "#6E8C60"
RED = "#8C2F2F"
AMBER_BG = "#FBF0D9"
AMBER_EDGE = "#C9AC7C"
ERROR_BG = "#F7DDDD"
ERROR_EDGE = "#C58C8C"
GREY_EDGE = "#8A94A6"
SCORE_LOW = "#B07A1E"
SCORE_HIGH = "#3A6B2E"

st.markdown(f"""
<style>
  .stApp {{ background: {BG}; }}
  .block-container {{ padding-top: 3.4rem; max-width: 1280px; }}

  .titlebar {{
      background: {NAVY}; color: #fff; padding: 0.7rem 1.1rem;
      font-size: 1.05rem; font-weight: 700; letter-spacing: 0.01em;
      border-radius: 4px 4px 0 0; margin-bottom: 1.1rem;
  }}
  .ctrlname {{
      font-size: 0.78rem; color: #5A6472; margin: 0 0 0.25rem 0;
      font-family: ui-monospace, Consolas, monospace;
  }}
  .dropzone {{
      border: 1.5px dashed {GREY_EDGE}; background: {PANEL};
      border-radius: 4px; padding: 1.55rem 1rem; text-align: center;
      color: #5A6472; font-size: 0.9rem; line-height: 1.5;
  }}
  .statusbar {{
      background: {PANEL}; border: 1px solid {GREY_EDGE}; border-radius: 4px;
      padding: 0.85rem 1rem; font-size: 0.9rem; color: #333;
  }}
  .warnbar {{
      background: {AMBER_BG}; border: 1px solid {AMBER_EDGE}; border-radius: 4px;
      padding: 0.8rem 1rem; font-size: 0.88rem; color: #4A3B1E;
  }}
  .errbar {{
      background: {ERROR_BG}; border: 1px solid {ERROR_EDGE}; border-radius: 4px;
      padding: 0.8rem 1rem; font-size: 0.88rem; color: #5A2020;
  }}

  /* Streamlit exposes a .st-key-<key> class on each widget container, so the
     wireframe colours are applied to the exact controls by name. */
  .st-key-btnScan button {{
      background: {NAVY} !important; border: 1px solid {NAVY} !important;
      color: #fff !important;
  }}
  .st-key-btnScan button:hover:enabled {{
      background: #24394E !important; border-color: #24394E !important;
  }}
  /* the destructive action, deliberately a different colour to everything else */
  .st-key-btnApplyRedaction button {{
      background: {RED} !important; border: 1px solid {RED} !important;
      color: #fff !important;
  }}
  .st-key-btnApplyRedaction button:hover:enabled {{
      background: #741F1F !important; border-color: #741F1F !important;
  }}
  .st-key-btnConfirm button {{
      background: {GREEN} !important; border: 1px solid {GREEN_EDGE} !important;
      color: #21331A !important;
  }}
  .st-key-btnClearQueue button, .st-key-btnSelectAll button,
  .st-key-btnDeselectAll button, .st-key-btnCancel button {{
      background: {PANEL}; border: 1px solid {GREY_EDGE}; color: #333;
  }}
  section[data-testid="stFileUploaderDropzone"] {{
      background: {GREEN}; border: 1.5px solid {GREEN_EDGE};
  }}
  [data-testid="stDataFrame"] thead th {{ background: #E8EEF7 !important; }}
  footer, #MainMenu {{ visibility: hidden; }}
</style>
""", unsafe_allow_html=True)

WORKDIR = Path(tempfile.gettempdir()) / "pii_redaction_tool"
INPUT_DIR = WORKDIR / "input"
OUTPUT_DIR = WORKDIR / "output"
LOG_PATH = WORKDIR / "audit_log.csv"

# --------------------------------------------------------------------------
# Session state
# --------------------------------------------------------------------------
defaults = {
    "screen": 1,
    "queue": [],            # list of dicts: path, name, pages, status
    "detections": {},       # file name -> list[Detection]
    "table": None,          # pandas DataFrame backing tblDetections
    "status": "No files selected yet.",
    "errors": [],
    "confirming": False,
    "summary": None,
}
for key, value in defaults.items():
    st.session_state.setdefault(key, value)


def titlebar(text: str) -> None:
    st.markdown(f'<div class="titlebar">{text}</div>', unsafe_allow_html=True)


def label(name: str) -> None:
    st.markdown(f'<p class="ctrlname">{name}</p>', unsafe_allow_html=True)


# ==========================================================================
# SCREEN 1 — Select Documents
# ==========================================================================
def screen_one() -> None:
    titlebar("PII Redaction Tool &nbsp;—&nbsp; Screen 1: Select Documents")

    left, right = st.columns([1, 1], gap="medium")

    with left:
        label("btnSelectFiles")
        uploaded = st.file_uploader(
            "Browse for documents…",
            type=["pdf", "docx", "eml", "msg"],
            accept_multiple_files=True,
            label_visibility="collapsed",
            key="btnSelectFiles",
        )
    with right:
        label("lblDropZone")
        st.markdown(
            '<div class="dropzone">Drag and drop files onto the box on the left.'
            '<br>Accepted formats: .pdf, .docx, .eml, .msg</div>',
            unsafe_allow_html=True,
        )

    # UC-1: validate format, read page count, add to the queue
    if uploaded:
        INPUT_DIR.mkdir(parents=True, exist_ok=True)
        known = {item["name"] for item in st.session_state.queue}
        errors = []
        for file in uploaded:
            if file.name in known:
                continue
            path = INPUT_DIR / file.name
            path.write_bytes(file.getbuffer())
            if path.suffix.lower() not in detector.SUPPORTED:
                errors.append(f"{file.name}: format not supported.")
                continue
            try:
                pages = detector.page_count(path)
                unit = "message" if path.suffix.lower() in (".eml", ".msg") else "pages"
                st.session_state.queue.append({
                    "path": str(path), "name": file.name,
                    "pages": f"{pages} {unit}" if pages else "—",
                    "status": "Ready" if pages else "Unavailable",
                })
            except LoadError as exc:
                errors.append(f"{file.name}: {exc}")
                st.session_state.queue.append({
                    "path": str(path), "name": file.name,
                    "pages": "—", "status": "Unavailable",
                })
        st.session_state.errors = errors

    st.write("")
    queue_col, entity_col = st.columns([1.8, 1], gap="medium")

    with queue_col:
        label("lstFileQueue")
        if st.session_state.queue:
            st.dataframe(
                pd.DataFrame([
                    {"File": q["name"], "Size": q["pages"], "Status": q["status"]}
                    for q in st.session_state.queue
                ]),
                hide_index=True, use_container_width=True, height=180,
            )
        else:
            st.markdown(
                '<div class="dropzone" style="text-align:left;">'
                'No files in the queue. Select documents above to begin.</div>',
                unsafe_allow_html=True,
            )

    with entity_col:
        label("chkEntityTypes")
        selected = []
        for code, text in ENTITY_TYPES:
            if st.checkbox(text, value=True, key=f"chk_{code}"):
                selected.append(code)

    st.write("")
    slider_col, azure_col = st.columns([1.8, 1], gap="medium")
    with slider_col:
        label("sldConfidence &nbsp;(minimum confidence score)")
        threshold = st.slider(
            "Minimum confidence", 0.0, 1.0, 0.65, 0.01,
            label_visibility="collapsed", key="sldConfidence",
        )
        if threshold < 0.5:
            st.markdown(
                '<div class="warnbar">A threshold below 0.50 will produce more false '
                'positives and more manual review.</div>',
                unsafe_allow_html=True,
            )
    with azure_col:
        label("chkAzurePass")
        use_azure = st.checkbox(
            "Send text to Azure AI Language", value=False, key="chkAzurePass",
        )
        if use_azure:
            st.markdown(
                '<div class="warnbar">Document text will leave this machine. '
                'Only enable this where a DPIA covers it.</div>',
                unsafe_allow_html=True,
            )

    st.write("")
    scan_col, clear_col, _ = st.columns([1, 1, 2.2], gap="small")
    ready = [q for q in st.session_state.queue if q["status"] == "Ready"]
    with scan_col:
        scan = st.button(
            "Scan for PII", type="primary", use_container_width=True,
            disabled=not (ready and selected), key="btnScan",
        )
    with clear_col:
        if st.button("Clear", type="secondary", use_container_width=True,
                     key="btnClearQueue"):
            st.session_state.queue = []
            st.session_state.errors = []
            st.session_state.status = "Queue cleared."
            st.rerun()

    if not selected:
        st.markdown(
            '<div class="errbar">Select at least one type of personal information '
            'before scanning.</div>', unsafe_allow_html=True,
        )

    for message in st.session_state.errors:
        st.markdown(f'<div class="errbar">{message}</div>', unsafe_allow_html=True)

    st.write("")
    count = len(ready)
    st.session_state.status = (
        f"{count} file{'s' if count != 1 else ''} ready. "
        "No documents have been changed yet."
        if count else "No files ready. Select documents to begin."
    )
    st.markdown(
        f'<div class="statusbar"><b>lblStatus:</b> &nbsp;{st.session_state.status}</div>',
        unsafe_allow_html=True,
    )
    st.caption(detector.nlp_status())

    if scan:
        run_scan(ready, selected, threshold, use_azure)


# --------------------------------------------------------------------------
# UC-3: Scan Document for PII
# --------------------------------------------------------------------------
def run_scan(ready, selected, threshold, use_azure) -> None:
    codes = expand_entity_selection(selected)
    rows, store, problems = [], {}, []
    progress = st.progress(0.0, text="Scanning…")

    for index, item in enumerate(ready, start=1):
        path = Path(item["path"])
        progress.progress(index / len(ready), text=f"Scanning {item['name']}…")
        try:
            text, spans = detector.load(path)
        except LoadError as exc:
            problems.append(f"{item['name']}: {exc}")
            continue

        if not text.strip():
            problems.append(
                f"{item['name']}: no text layer found. This looks like a scan, "
                "so it needs OCR and has not been processed."
            )
            continue

        found = detector.detect(text, spans, codes, threshold, use_azure)
        store[item["name"]] = found
        for d in found:
            rows.append({
                "Redact": d.accepted,
                "File": item["name"],
                "Type": d.entity_type,
                "Text found": d.text,
                "Page": d.page,
                "Score": round(d.score, 2),
                "Source": d.source,
                "Check": "Low score" if d.score < 0.70 else "",
            })

    progress.empty()
    st.session_state.detections = store
    st.session_state.errors = problems
    st.session_state.table = pd.DataFrame(rows)

    if not rows:
        st.session_state.status = (
            "The scan found nothing. Check these documents manually before release."
        )
        st.rerun()

    st.session_state.screen = 2
    st.rerun()


# ==========================================================================
# SCREEN 2 — Review Detections
# ==========================================================================
def screen_two() -> None:
    table: pd.DataFrame = st.session_state.table
    files = table["File"].nunique()
    heading = (
        f"{table.iloc[0]['File']}" if files == 1 else f"{files} documents"
    )
    titlebar("PII Redaction Tool &nbsp;—&nbsp; Screen 2: Review Detections")

    st.markdown(
        f'<p class="ctrlname">tblDetections &nbsp;—&nbsp; {heading} &nbsp;'
        f'({len(table)} items found)</p>', unsafe_allow_html=True,
    )

    edited = st.data_editor(
        table,
        hide_index=True,
        use_container_width=True,
        height=430,
        key="tblDetections",
        column_config={
            "Redact": st.column_config.CheckboxColumn("Redact", width="small"),
            "File": st.column_config.TextColumn("File", disabled=True),
            "Type": st.column_config.TextColumn("Type", width="small", disabled=True),
            "Text found": st.column_config.TextColumn("Text found", disabled=True),
            "Page": st.column_config.NumberColumn("Page", width="small", disabled=True),
            "Score": st.column_config.NumberColumn(
                "Score", width="small", format="%.2f", disabled=True),
            "Source": st.column_config.TextColumn("Source", width="small", disabled=True),
            "Check": st.column_config.TextColumn("Check", width="small", disabled=True),
        },
    )
    st.session_state.table = edited

    ticked = int(edited["Redact"].sum())
    st.caption(
        f"{ticked} of {len(edited)} items ticked for redaction. "
        "Items scored below 0.70 are flagged in the Check column."
    )

    for message in st.session_state.errors:
        st.markdown(f'<div class="errbar">{message}</div>', unsafe_allow_html=True)

    st.write("")
    all_col, none_col, apply_col = st.columns([1, 1, 2.4], gap="small")
    with all_col:
        if st.button("Select all", type="secondary", use_container_width=True,
                     key="btnSelectAll"):
            st.session_state.table["Redact"] = True
            st.rerun()
    with none_col:
        if st.button("Deselect all", type="secondary", use_container_width=True,
                     key="btnDeselectAll"):
            st.session_state.table["Redact"] = False
            st.rerun()
    with apply_col:
        if st.button("Apply redaction to a copy", use_container_width=True,
                     disabled=ticked == 0, key="btnApplyRedaction"):
            st.session_state.confirming = True

    st.write("")
    st.markdown(
        '<div class="warnbar"><b>lblWarning:</b> &nbsp;Redaction is permanent in the '
        'output file. The original file is not changed.</div>',
        unsafe_allow_html=True,
    )

    if st.session_state.confirming:
        confirm_dialog(edited, ticked)

    st.write("")
    if st.button("← Back to file selection", type="secondary"):
        st.session_state.screen = 1
        st.session_state.confirming = False
        st.rerun()


# --------------------------------------------------------------------------
# UC-5: Apply Redaction
# --------------------------------------------------------------------------
def confirm_dialog(edited: pd.DataFrame, ticked: int) -> None:
    st.write("")
    with st.container(border=True):
        st.markdown(f"**Apply {ticked} redactions?**")
        st.write(
            "A redacted copy is written to the output folder. The text is removed "
            "from the copy and cannot be recovered from it. Your original files are "
            "not touched."
        )
        yes_col, no_col, _ = st.columns([1, 1, 3])
        with yes_col:
            confirmed = st.button("Confirm", use_container_width=True, key="btnConfirm")
        with no_col:
            if st.button("Cancel", type="secondary", use_container_width=True,
                         key="btnCancel"):
                st.session_state.confirming = False
                st.rerun()

    if confirmed:
        apply_redactions(edited)


def apply_redactions(edited: pd.DataFrame) -> None:
    outputs, failures = [], []

    for name, group in edited.groupby("File"):
        found = st.session_state.detections.get(name, [])
        keep = set(zip(group.loc[group["Redact"], "Type"],
                       group.loc[group["Redact"], "Text found"]))
        accepted = [d for d in found if (d.entity_type, d.text) in keep]
        for d in found:
            d.accepted = (d.entity_type, d.text) in keep

        source = Path(next(q["path"] for q in st.session_state.queue
                           if q["name"] == name))
        try:
            target = redactor.redact(source, OUTPUT_DIR, accepted)
            pages = len({d.page for d in found}) or 1
            redactor.write_audit(LOG_PATH, source, target, pages, found)
            outputs.append((name, target, len(accepted)))
        except Exception as exc:                       # fail closed, keep going
            failures.append(f"{name}: {exc}")
            redactor.write_audit(LOG_PATH, source, None, 0, [])

    st.session_state.summary = {"outputs": outputs, "failures": failures}
    st.session_state.confirming = False
    st.session_state.screen = 3
    st.rerun()


# ==========================================================================
# SCREEN 3 — Summary and audit log (UC-5 step 8, UC-6)
# ==========================================================================
def screen_three() -> None:
    titlebar("PII Redaction Tool &nbsp;—&nbsp; Job Complete")
    summary = st.session_state.summary or {"outputs": [], "failures": []}

    for name, target, count in summary["outputs"]:
        st.markdown(
            f'<div class="statusbar"><b>{name}</b> — {count} redactions applied. '
            f'Written to <code>{target}</code></div>', unsafe_allow_html=True,
        )
        with open(target, "rb") as handle:
            st.download_button(
                f"Download {target.name}", handle.read(), file_name=target.name,
                key=f"dl_{target.name}",
            )
        st.write("")

    for message in summary["failures"]:
        st.markdown(
            f'<div class="errbar">{message} — no output file was written.</div>',
            unsafe_allow_html=True,
        )

    st.markdown('<p class="ctrlname">btnViewLog</p>', unsafe_allow_html=True)
    if LOG_PATH.exists():
        log = pd.read_csv(LOG_PATH)
        st.dataframe(log.tail(200), hide_index=True, use_container_width=True, height=280)
        st.download_button("Export audit log (CSV)", LOG_PATH.read_bytes(),
                           file_name="audit_log.csv")
        st.caption(
            "The log records the type and location of every redaction. It never "
            "records the redacted value."
        )
    else:
        st.info("No audit entries yet.")

    st.write("")
    if st.button("Start a new job", type="primary"):
        for key in ("queue", "detections", "table", "errors", "summary"):
            st.session_state[key] = defaults[key]
        st.session_state.screen = 1
        st.rerun()


# ==========================================================================
SCREENS = {1: screen_one, 2: screen_two, 3: screen_three}
SCREENS[st.session_state.screen]()
