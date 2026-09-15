# src/cli.py
import argparse
from pathlib import Path
from .detector import PIIDetector
from .redact_docx import redact_docx
from .redact_email import redact_eml, redact_msg
from .redact_pdf import redact_pdf
from .audit import write_audit
 
# suffix -> (handler, output suffix). The redacted email is a plain-text
# transcript, not a sendable message, so it is written as .txt.
HANDLERS = {
    ".docx": (redact_docx, ".docx"),
    ".pdf":  (redact_pdf,  ".pdf"),
    ".eml":  (redact_eml,  ".txt"),
    ".msg":  (redact_msg,  ".txt"),
}
 
 
def process(path: Path, out_dir: Path, det: PIIDetector):
    entry = HANDLERS.get(path.suffix.lower())
    if entry is None:
        print(f"SKIP {path.name}: unsupported format")
        return
    handler, out_suffix = entry
    out_file = out_dir / (path.stem + "_redacted" + out_suffix)
    try:
        findings = handler(str(path), str(out_file), det)
    except Exception as exc:                     # one bad file must not stop the batch
        print(f"FAIL {path.name}: {type(exc).__name__}: {exc}")
        return
    audit = write_audit(findings, str(path), str(out_dir))
    print(f"OK   {path.name}: {len(findings)} redactions -> "
          f"{out_file.name}, audit: {Path(audit).name}")
 
 
def main():
    ap = argparse.ArgumentParser(
        description="Redact PII from PDF, Word and email documents.")
    ap.add_argument("--input", required=True, help="file or folder to process")
    ap.add_argument("--output", default="out", help="output folder")
    ap.add_argument("--config", default="entities.yaml")
    args = ap.parse_args()
 
    det = PIIDetector(args.config)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = Path(args.input)
    files = sorted(target.glob("*")) if target.is_dir() else [target]
    for f in files:
        if f.is_file():
            process(f, out_dir, det)
 
 
if __name__ == "__main__":
    main()
