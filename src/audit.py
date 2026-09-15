# src/audit.py
import json
from datetime import datetime, timezone
from pathlib import Path
 
 
def write_audit(findings, source_file: str, out_dir: str) -> str:
    src = Path(source_file)
    records = [
        {"entity_type": f.entity_type,
         "location": location,
         "start": f.start,
         "end": f.end,
         "confidence": round(f.score, 2)}
        for f, location in findings
    ]
    audit = {
        "source_file": src.name,
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "total_redactions": len(records),
        "redactions": records,
    }
    # include the source extension: sample1.docx and sample1.pdf must not
    # write to the same audit file and silently overwrite each other
    out = Path(out_dir) / f"{src.stem}_{src.suffix.lstrip('.')}_audit.json"
    out.write_text(json.dumps(audit, indent=2), encoding="utf-8")
    return str(out)

