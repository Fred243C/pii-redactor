"""
detector.py
-----------
Document loading and PII detection.

Loaders map to the DocumentLoader family in the class diagram. Detection uses
Presidio and spaCy when they are installed, and falls back to the pattern
recognisers on their own when they are not, so the interface can be run and
demonstrated before the NLP model is set up.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from recognisers import Detection, merge, run_pattern_recognisers

# --------------------------------------------------------------------------
# Optional dependencies. The tool degrades rather than crashes.
# --------------------------------------------------------------------------
try:
    import fitz  # PyMuPDF
    HAVE_PDF = True
except ImportError:
    HAVE_PDF = False

try:
    import docx  # python-docx
    HAVE_DOCX = True
except ImportError:
    HAVE_DOCX = False

try:
    from presidio_analyzer import AnalyzerEngine
    HAVE_PRESIDIO = True
except ImportError:
    HAVE_PRESIDIO = False


SUPPORTED = {".pdf", ".docx", ".eml", ".msg"}

# Entity types offered in chkEntityTypes, in the order they appear on screen.
ENTITY_TYPES = [
    ("PERSON",  "Person name"),
    ("ADDRESS", "Address / Eircode"),
    ("EMAIL",   "Email address"),
    ("PHONE",   "Phone number"),
    ("PPSN",    "PPS number"),
    ("DOB",     "Date of birth"),
    ("IBAN",    "IBAN"),
]

# "Address / Eircode" is one tick box on screen but two entity codes underneath.
_UI_TO_CODES = {"ADDRESS": ["ADDRESS", "EIRCODE"]}


def expand_entity_selection(selected: list[str]) -> list[str]:
    codes: list[str] = []
    for s in selected:
        codes.extend(_UI_TO_CODES.get(s, [s]))
    return codes


# --------------------------------------------------------------------------
# Loaders
# --------------------------------------------------------------------------
class LoadError(Exception):
    """Raised when a file cannot be read. Caught so a batch can continue."""


def _load_pdf(path: Path) -> tuple[str, list[tuple[int, int, int]]]:
    if not HAVE_PDF:
        raise LoadError("PyMuPDF is not installed, so PDF files cannot be read.")
    parts, spans, offset = [], [], 0
    with fitz.open(path) as doc:
        for number, page in enumerate(doc, start=1):
            page_text = page.get_text()
            parts.append(page_text)
            spans.append((number, offset, offset + len(page_text)))
            offset += len(page_text)
    return "".join(parts), spans


def _load_docx(path: Path) -> tuple[str, list[tuple[int, int, int]]]:
    if not HAVE_DOCX:
        raise LoadError("python-docx is not installed, so Word files cannot be read.")
    document = docx.Document(str(path))
    blocks = [p.text for p in document.paragraphs]
    for table in document.tables:
        for row in table.rows:
            blocks.extend(cell.text for cell in row.cells)
    text = "\n".join(blocks)
    return text, [(1, 0, len(text))]


def _load_email(path: Path) -> tuple[str, list[tuple[int, int, int]]]:
    if path.suffix.lower() == ".msg":
        try:
            import extract_msg
        except ImportError:
            raise LoadError("extract-msg is not installed, so .msg files cannot be read.")
        message = extract_msg.Message(str(path))
        text = "\n".join(filter(None, [
            f"From: {message.sender}", f"To: {message.to}",
            f"Subject: {message.subject}", "", message.body or "",
        ]))
    else:
        import email
        import email.policy
        message = email.message_from_bytes(path.read_bytes(), policy=email.policy.default)
        body = message.get_body(preferencelist=("plain", "html"))
        text = "\n".join(filter(None, [
            f"From: {message.get('From', '')}", f"To: {message.get('To', '')}",
            f"Subject: {message.get('Subject', '')}", "",
            body.get_content() if body else "",
        ]))
    return text, [(1, 0, len(text))]


def load(path: Path) -> tuple[str, list[tuple[int, int, int]]]:
    """Return the extracted text and a list of (page_number, start, end) spans."""
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return _load_pdf(path)
    if suffix == ".docx":
        return _load_docx(path)
    if suffix in (".eml", ".msg"):
        return _load_email(path)
    raise LoadError(f"{suffix} is not a supported format.")


def page_count(path: Path) -> int:
    try:
        text, spans = load(path)
        return len(spans)
    except LoadError:
        return 0


def page_for_offset(spans: list[tuple[int, int, int]], offset: int) -> int:
    for number, start, end in spans:
        if start <= offset < end:
            return number
    return spans[-1][0] if spans else 1


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------
_analyzer = None


def _get_analyzer():
    global _analyzer
    if _analyzer is None and HAVE_PRESIDIO:
        _analyzer = AnalyzerEngine()
    return _analyzer


# Used only when Presidio is unavailable. This is deliberately narrow: it only
# fires on a title or a salutation, because matching any two capitalised words
# in a row flags half the document. Scored low so it never auto-ticks.
_NAME_PART = r"(?:O['’]|Mc|Mac)?[A-Z][a-z]{1,20}"
_TITLE = r"(?:Mr|Mrs|Ms|Miss|Dr|Prof|Cllr)"
_NAME_FALLBACK = re.compile(
    rf"\b{_TITLE}\.?\s+{_NAME_PART}(?:\s+{_NAME_PART}){{0,3}}"
    rf"|(?<=Dear\s){_NAME_PART}(?:\s+{_NAME_PART}){{0,3}}"
    rf"|(?<=sincerely,\s){_NAME_PART}(?:\s+{_NAME_PART}){{0,3}}"
)
_ADDRESS_FALLBACK = re.compile(
    r"\b\d{1,4}[A-Za-z]?\s+[A-Z][A-Za-z'’\-]+(?:\s+[A-Z][A-Za-z'’\-]+){0,3}\s+"
    r"(Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Park|Close|Court|Crescent|"
    r"Terrace|Grove|Green|Place|Square|Way|Heights|View|Rise)\b"
)


def detect(text: str,
           spans: list[tuple[int, int, int]],
           entity_codes: list[str],
           threshold: float,
           use_azure: bool = False) -> list[Detection]:
    """
    Run detection over the extracted text and return the findings above the
    threshold. Pattern recognisers always run. The NLP pass runs if Presidio
    is available, otherwise a low confidence fallback is used and flagged.
    """
    results = run_pattern_recognisers(text, entity_codes)

    wants_person = "PERSON" in entity_codes
    wants_address = "ADDRESS" in entity_codes

    analyzer = _get_analyzer()
    if analyzer is not None and (wants_person or wants_address):
        wanted = [c for c in ("PERSON", "LOCATION") if
                  (c == "PERSON" and wants_person) or (c == "LOCATION" and wants_address)]
        nlp_hits = [
            Detection(
                entity_type="ADDRESS" if r.entity_type == "LOCATION" else r.entity_type,
                text=text[r.start:r.end],
                start=r.start, end=r.end,
                score=round(r.score, 2),
                source="Presidio",
            )
            for r in analyzer.analyze(text=text, entities=wanted, language="en")
        ]
        results = merge(results, nlp_hits)
    else:
        fallback: list[Detection] = []
        if wants_person:
            fallback += [
                Detection("PERSON", m.group(0), m.start(), m.end(), 0.50, source="Fallback")
                for m in _NAME_FALLBACK.finditer(text)
            ]
        if wants_address:
            fallback += [
                Detection("ADDRESS", m.group(0), m.start(), m.end(), 0.55, source="Fallback")
                for m in _ADDRESS_FALLBACK.finditer(text)
            ]
        results = merge(results, fallback)

    if use_azure:
        # Placeholder for the optional second pass (FR-6). Wire the Azure AI
        # Language client in here and merge its results the same way.
        pass

    for d in results:
        d.page = page_for_offset(spans, d.start)
        d.accepted = d.score >= threshold

    return [d for d in results
            if d.score >= threshold * 0.6 and d.entity_type in entity_codes]


def nlp_status() -> str:
    """One line describing which detection engine is actually running."""
    if HAVE_PRESIDIO:
        return "Presidio and spaCy are loaded. Name and address detection is active."
    return ("Presidio is not installed, so name and address detection is running on a "
            "basic pattern fallback with low confidence scores. "
            "Run: pip install presidio-analyzer && python -m spacy download en_core_web_lg")
