#tests/test_detector.py
from src.detector import PIIDetector, redact_text
 

det = PIIDetector()


def _types(text):
    return {f.entity_type for f in det.analyze(text)}
 
 
def test_detects_person_and_email():
    found = _types("Contact John Murphy at john@example.com")
    assert "PERSON" in found and "EMAIL_ADDRESS" in found
 
 
def test_detects_pps_number():
    assert "IE_PPS_NUMBER" in _types("Her PPS number is 1234567AB.")
 
 
def test_detects_irish_mobile():
    assert "PHONE_NUMBER" in _types("You can reach me on 087 123 4567.")
 
 
def test_ignores_short_numbers():
    assert "IE_PPS_NUMBER" not in _types("Invoice 12345 is attached.")
 
 
def test_empty_text_is_safe():
    assert det.analyze("") == []
 
 
def test_overlapping_findings_do_not_corrupt_text():
    text = "Fred Banda, PPS 1234567AB, Dublin."
    out = redact_text(text, det.analyze(text))
    assert "Banda" not in out and "1234567AB" not in out
    assert out.count("[REDACTED") >= 2
