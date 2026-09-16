
from __future__ import annotations
 
import csv
import datetime as dt
import getpass
import re
from pathlib import Path
 
from detector import HAVE_DOCX, HAVE_PDF, sha256
from recognisers import Detection
 
PLACEHOLDER = "[REDACTED]"
 
# How a redaction looks in the output file.
#   "bar"  - solid black block, the traditional look of a redacted document
#   "text" - the words [REDACTED]
# This is cosmetic only. In both styles the underlying text is deleted, not
# covered: see the note in _redact_pdf below.
REDACTION_STYLE = "bar"
 
_BLOCK = "\u2588"      # FULL BLOCK, the character that draws a solid bar
 
 
def _replacement(value: str) -> str:
    """The text that takes the place of a redacted value in a Word file."""
    if REDACTION_STYLE != "bar":
        return PLACEHOLDER
    # One block per character keeps the bar roughly the width of what it
    # replaced, so the layout of the page does not shift.
    return _BLOCK * max(len(value), 3)
 
 
class RedactionError(Exception):
    pass
 
 
def _output_path(source: Path, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{source.stem}_REDACTED{source.suffix}"
    if target.exists():
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        target = output_dir / f"{source.stem}_REDACTED_{stamp}{source.suffix}"
    return target
 
 
def _redact_pdf(source: Path, target: Path, accepted: list[Detection]) -> None:
    if not HAVE_PDF:
        raise RedactionError("PyMuPDF is not installed, so PDF files cannot be redacted.")
    import fitz
 
    wanted = {d.text for d in accepted if d.text.strip()}
    doc = fitz.open(source)
    try:
        for page in doc:
            for value in wanted:
                for rect in page.search_for(value):
                    if REDACTION_STYLE == "bar":
                        # fill paints the box; passing no text leaves it solid.
                        page.add_redact_annot(rect, fill=(0, 0, 0))
                    else:
                        page.add_redact_annot(rect, text=PLACEHOLDER,
                                              fontsize=8, fill=(1, 1, 1))
            # apply_redactions is what actually deletes the text object. The
            # black box on its own is only paint: drawing a rectangle with
            # draw_rect and skipping this call leaves the text underneath,
            # selectable and copyable. That is the mistake behind several
            # published redaction failures.
            page.apply_redactions()
        doc.save(target, garbage=4, deflate=True)
    finally:
        doc.close()
 
 
def _redact_docx(source: Path, target: Path, accepted: list[Detection]) -> None:
    if not HAVE_DOCX:
        raise RedactionError("python-docx is not installed, so Word files cannot be redacted.")
    import docx
 
    wanted = sorted({d.text for d in accepted if d.text.strip()}, key=len, reverse=True)
    document = docx.Document(str(source))
 
    def scrub(paragraph):
        for run in paragraph.runs:
            for value in wanted:
                if value in run.text:
                    run.text = run.text.replace(value, _replacement(value))
 
    for paragraph in document.paragraphs:
        scrub(paragraph)
    for table in document.tables:
        for row in table.rows:
            for cell in row.cells:
                for paragraph in cell.paragraphs:
                    scrub(paragraph)
    document.save(target)
 
 
def _redact_email(source: Path, target: Path, accepted: list[Detection]) -> None:
    wanted = sorted({d.text for d in accepted if d.text.strip()}, key=len, reverse=True)
    raw = source.read_text(errors="replace")
    for value in wanted:
        # Email is plain text, where a bar of blocks reads poorly and can break
        # header parsing, so the word form is always used here.
        raw = raw.replace(value, PLACEHOLDER)
    target.write_text(raw)
 
 
def redact(source: Path, output_dir: Path, accepted: list[Detection]) -> Path:
    """Write a redacted copy and return its path. Deletes the copy on failure."""
    target = _output_path(source, output_dir)
    suffix = source.suffix.lower()
    try:
        if suffix == ".pdf":
            _redact_pdf(source, target, accepted)
        elif suffix == ".docx":
            _redact_docx(source, target, accepted)
        elif suffix in (".eml", ".msg"):
            _redact_email(source, target, accepted)
        else:
            raise RedactionError(f"{suffix} cannot be redacted.")
    except Exception:
        if target.exists():
            target.unlink()      # fail closed
        raise
    return target
 
 
# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------
# The log records the type and location of each redaction and never the value.
# If it stored the values it would become an unredacted copy of everything the
# organisation has ever released, which is the problem the tool exists to fix.
AUDIT_COLUMNS = [
    "timestamp", "user", "file_name", "file_format",
    "source_sha256", "output_sha256", "page_count",
    "entity_type", "page_number", "start_offset", "end_offset",
    "confidence", "source_engine", "action_taken",
]
 
 
def write_audit(log_path: Path,
                source: Path,
                output: Path | None,
                page_total: int,
                detections: list[Detection]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    new_file = not log_path.exists()
    stamp = dt.datetime.now().isoformat(timespec="seconds")
    user = getpass.getuser()
    src_hash = sha256(source)
    out_hash = sha256(output) if output and output.exists() else ""
 
    with open(log_path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        if new_file:
            writer.writerow(AUDIT_COLUMNS)
        if not detections:
            writer.writerow([stamp, user, source.name, source.suffix.lstrip("."),
                             src_hash, out_hash, page_total,
                             "", "", "", "", "", "", "no_detections"])
        for d in detections:
            writer.writerow([
                stamp, user, source.name, source.suffix.lstrip("."),
                src_hash, out_hash, page_total,
                d.entity_type, d.page, d.start, d.end,
                f"{d.score:.2f}", d.source,
                "redacted" if d.accepted else "rejected",
            ])
 