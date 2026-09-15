# eval_metrics.py  (project root)
"""Precision and recall per entity type, measured on the plain-text samples.
 
Ground truth lives in tests/truth.json. Add one entry per .txt sample; the
evaluation runs the detector directly rather than reading the audit logs,
so the audit stays free of PII values.
"""
import json
from collections import defaultdict
from pathlib import Path
from src.detector import PIIDetector
 
truth = json.loads(Path("tests/truth.json").read_text(encoding="utf-8"))
det = PIIDetector()
tp, fp, fn = defaultdict(int), defaultdict(int), defaultdict(int)
 
 
def same(a, b):
    """Loose match: a detected span counts if it overlaps the truth string."""
    return a[0] == b[0] and (a[1] in b[1] or b[1] in a[1])
 
 
for name, items in truth.items():
    text = (Path("sample_docs") / name).read_text(encoding="utf-8")
    found = [(f.entity_type, text[f.start:f.end].strip())
             for f in det.analyze(text)]
    expected = [(i["type"], i["text"]) for i in items]
    for e in expected:
        (tp if any(same(e, g) for g in found) else fn)[e[0]] += 1
    for g in found:
        if not any(same(e, g) for e in expected):
            fp[g[0]] += 1
 
print(f"{'ENTITY':<18}{'TP':>4}{'FP':>4}{'FN':>4}{'PRECISION':>11}{'RECALL':>9}")
for t in sorted(set(tp) | set(fp) | set(fn)):
    prec = tp[t] / (tp[t] + fp[t]) if tp[t] + fp[t] else 0.0
    rec = tp[t] / (tp[t] + fn[t]) if tp[t] + fn[t] else 0.0
    print(f"{t:<18}{tp[t]:>4}{fp[t]:>4}{fn[t]:>4}{prec:>11.2f}{rec:>9.2f}")
