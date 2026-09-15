# src/redact_email.py
from email import policy
from email.parser import BytesParser
from pathlib import Path
from .detector import PIIDetector, redact_text
 
HEADERS = ("From", "To", "Cc", "Bcc", "Subject", "Reply-To")
 
 
def _redact_blocks(blocks, det):
    """blocks: list of (label, text). Returns (rendered_text, findings)."""
    out, all_findings = [], []
    for label, text in blocks:
        findings = det.analyze(text)
        out.append(redact_text(text, findings))
        all_findings.extend((f, label) for f in findings)
    return "\n\n".join(out), all_findings
 
 
def redact_eml(in_path: str, out_path: str, det: PIIDetector):
    with open(in_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    body_part = msg.get_body(preferencelist=("plain",))
    body = body_part.get_content() if body_part else ""
    header_text = "\n".join(f"{h}: {msg[h]}" for h in HEADERS if msg[h])
    text, findings = _redact_blocks(
        [("headers", header_text), ("body", body)], det)
    Path(out_path).write_text(text, encoding="utf-8")
    return findings
 
 
def redact_msg(in_path: str, out_path: str, det: PIIDetector):
    """Outlook .msg. Optional - only wire this up if Day 1 finishes early."""
    import extract_msg
    m = extract_msg.Message(in_path)
    header_text = "\n".join([
        f"From: {m.sender or ''}", f"To: {m.to or ''}",
        f"Cc: {m.cc or ''}", f"Subject: {m.subject or ''}"])
    text, findings = _redact_blocks(
        [("headers", header_text), ("body", m.body or "")], det)
    Path(out_path).write_text(text, encoding="utf-8")
    return findings
