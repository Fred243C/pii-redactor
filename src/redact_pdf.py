# src/redact_pdf.py
try:
    import pymupdf                 # PyMuPDF 1.24.3 and later
except ImportError:
    import fitz as pymupdf         # older releases expose it as fitz
from .detector import PIIDetector, _merge_spans
 
 
def _rects_for(page, snippet):
    """Locate a snippet on the page, tolerating line wraps.
 
    search_for() matches a literal string, so a name split across two lines
    returns nothing. Falling back to word-by-word search costs a little
    precision and buys back the recall. Returning an empty list means the
    caller must flag the page, never pass it through silently.
    """
    snippet = snippet.strip()
    if not snippet:
        return []
    rects = page.search_for(snippet)
    if rects:
        return rects
    rects = page.search_for(" ".join(snippet.split()))
    if rects:
        return rects
    for word in snippet.split():
        if len(word) >= 3:
            rects.extend(page.search_for(word))
    return rects
 
 
def redact_pdf(in_path: str, out_path: str, det: PIIDetector):
    doc = pymupdf.open(in_path)
    all_findings, unresolved = [], 0
    for page_num, page in enumerate(doc, start=1):
        text = page.get_text()
        if not text.strip():
            print(f"  WARNING page {page_num}: no text layer (scanned image?). "
                  f"Nothing can be redacted. Flag for manual review.")
            continue
        findings = det.analyze(text)
        for span in _merge_spans(findings):
            rects = _rects_for(page, text[span["start"]:span["end"]])
            if not rects:
                unresolved += 1
                print(f"  WARNING page {page_num}: detected "
                      f"{'+'.join(span['types'])} but could not locate it on "
                      f"the page. NOT REDACTED - manual review required.")
                continue
            for rect in rects:
                page.add_redact_annot(rect, fill=(0, 0, 0))
        page.apply_redactions()
        all_findings.extend((f, f"page {page_num}") for f in findings)
    doc.save(out_path, garbage=3, deflate=True)
    doc.close()
    if unresolved:
        print(f"  {unresolved} detection(s) could not be placed on the page.")
    return all_findings
