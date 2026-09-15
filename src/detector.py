import yaml
from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
 
 
def _pps_recognizer() -> PatternRecognizer:
    """Irish PPS number: 7 digits then 1 or 2 letters."""
    pattern = Pattern(name="pps_pattern",
                      regex=r"\b\d{7}[A-Za-z]{1,2}\b",
                      score=0.6)
    return PatternRecognizer(supported_entity="IE_PPS_NUMBER",
                             patterns=[pattern],
                             context=["pps", "ppsn", "personal public service"])
 
 
def _ie_phone_recognizer() -> PatternRecognizer:
    """Irish mobile and landline formats Presidio scores too low on."""
    pattern = Pattern(name="ie_phone_pattern",
                      regex=r"\b(?:\+353[\s-]?|0)\d{1,2}[\s-]?\d{3}[\s-]?\d{4}\b",
                      score=0.7)
    return PatternRecognizer(supported_entity="PHONE_NUMBER",
                             patterns=[pattern],
                             context=["phone", "mobile", "tel", "contact"])

def _merge_spans(findings):
    """Collapse overlapping findings into single spans.
 
    Presidio often reports two entities over the same characters, for example
    PERSON and LOCATION on 'Dublin Murphy'. Replacing them one at a time
    corrupts the placeholder already written. Merging first makes the
    replacement safe and keeps both labels in the audit trail.
    """
    spans = []
    for f in sorted(findings, key=lambda x: (x.start, -x.end)):
        if spans and f.start < spans[-1]["end"]:
            spans[-1]["end"] = max(spans[-1]["end"], f.end)
            if f.entity_type not in spans[-1]["types"]:
                spans[-1]["types"].append(f.entity_type)
        else:
            spans.append({"start": f.start, "end": f.end,
                          "types": [f.entity_type]})
    return spans
 
 
def redact_text(text: str, findings) -> str:
    """Replace every finding with [REDACTED:TYPE], right to left."""
    for span in reversed(_merge_spans(findings)):
        label = "+".join(span["types"])
        text = text[:span["start"]] + f"[REDACTED:{label}]" + text[span["end"]:]
    return text

 
 
class PIIDetector:
    def __init__(self, config_path: str = "entities.yaml"):
        self.analyzer = AnalyzerEngine()
        self.analyzer.registry.add_recognizer(_pps_recognizer())
        self.analyzer.registry.add_recognizer(_ie_phone_recognizer())
        with open(config_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        self.entities = cfg["entities"]
        self.threshold = cfg.get("score_threshold", 0.4)
 
    def analyze(self, text: str):
        if not text or not text.strip():
            return []
        results = self.analyzer.analyze(text=text, language="en",
                                        entities=self.entities)
        return [r for r in results if r.score >= self.threshold]
