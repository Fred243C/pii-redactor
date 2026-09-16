"""
recognisers.py
--------------
Pattern based recognisers for the structured identifiers listed in FR-3 and FR-5.

These run with no external dependencies, so the tool still finds emails, phone
numbers, PPS numbers, Eircodes, IBANs and dates of birth even when spaCy and
Presidio are not installed. Person names and addresses need the NLP model and
are handled in detector.py.

Every recogniser returns a list of Detection objects. Nothing in this module
ever writes the matched value anywhere except back to the caller.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# --------------------------------------------------------------------------
# Detection data class (matches the class diagram in the report)
# --------------------------------------------------------------------------
@dataclass
class Detection:
    entity_type: str        # e.g. "PPSN"
    text: str               # the matched value, held in memory only
    start: int              # character offset in the extracted text
    end: int
    score: float            # 0.0 to 1.0
    page: int = 1
    source: str = "Custom"  # "Custom", "Presidio" or "Azure"
    accepted: bool = True

    def overlaps(self, other: "Detection") -> bool:
        return self.start < other.end and other.start < self.end


# --------------------------------------------------------------------------
# PPS number, with the modulus 23 check digit
# --------------------------------------------------------------------------
# A PPSN is seven digits, then a check letter, then an optional second letter.
# Checking the format alone produces a lot of false positives, because any
# seven digit number followed by a letter looks like one. Validating the check
# character removes almost all of them.
_PPSN_PATTERN = re.compile(r"\b(\d{7})([A-W])([A-IW])?\b", re.IGNORECASE)
_CHECK_CHARS = "WABCDEFGHIJKLMNOPQRSTUV"


def ppsn_check_character(digits: str, second_letter: str | None = None) -> str:
    """Return the expected check character for a PPSN using the modulus 23 rule."""
    total = sum(int(d) * w for d, w in zip(digits, range(8, 1, -1)))
    if second_letter and second_letter.upper() != "W":
        total += (ord(second_letter.upper()) - ord("A") + 1) * 9
    return _CHECK_CHARS[total % 23]


def is_valid_ppsn(value: str) -> bool:
    match = _PPSN_PATTERN.fullmatch(value.strip())
    if not match:
        return False
    digits, check, second = match.group(1), match.group(2), match.group(3)
    return check.upper() == ppsn_check_character(digits, second)


def find_ppsn(text: str) -> list[Detection]:
    out = []
    for m in _PPSN_PATTERN.finditer(text):
        digits, check, second = m.group(1), m.group(2), m.group(3)
        valid = check.upper() == ppsn_check_character(digits, second)
        # An invalid check digit is still flagged, but at a much lower score so
        # the staff member sees it and decides. Silently dropping it would be
        # worse: a mistyped PPSN in a record is still personal data.
        out.append(Detection(
            entity_type="PPSN",
            text=m.group(0),
            start=m.start(),
            end=m.end(),
            score=0.99 if valid else 0.45,
        ))
    return out


# --------------------------------------------------------------------------
# Eircode
# --------------------------------------------------------------------------
# Routing key is a letter plus two characters, then four characters from a
# reduced alphabet (B, G, I, J, L, M, O, Q, S, U, Z are not used). D6W is the
# one routing key that breaks the letter-digit-digit rule.
_EIRCODE_PATTERN = re.compile(
    r"\b(?:D6W|[AC-FHKNPRTV-Y]\d{2})\s?[0-9AC-FHKNPRTV-Y]{4}\b",
    re.IGNORECASE,
)


def find_eircode(text: str) -> list[Detection]:
    return [
        Detection("EIRCODE", m.group(0), m.start(), m.end(), 0.95)
        for m in _EIRCODE_PATTERN.finditer(text)
    ]


# --------------------------------------------------------------------------
# Email
# --------------------------------------------------------------------------
_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)


def find_email(text: str) -> list[Detection]:
    return [
        Detection("EMAIL", m.group(0), m.start(), m.end(), 1.00)
        for m in _EMAIL_PATTERN.finditer(text)
    ]


# --------------------------------------------------------------------------
# Phone numbers (Irish mobile, landline and international format)
# --------------------------------------------------------------------------
_PHONE_PATTERN = re.compile(
    r"""(?<![\d\w])(?:
          (?:\+353|00353)\s?\(?0?\)?\s?\d{1,2}[\s\-.]?\d{3}[\s\-.]?\d{3,4}
        | 0\s?8[35-9][\s\-.]?\d{3}[\s\-.]?\d{4}
        | 0\s?1[\s\-.]?\d{3}[\s\-.]?\d{4}
        | 0\s?\d{2}[\s\-.]?\d{3}[\s\-.]?\d{3,4}
        )(?![\d\w])""",
    re.VERBOSE,
)


def find_phone(text: str) -> list[Detection]:
    out = []
    for m in _PHONE_PATTERN.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if len(digits) < 9:            # too short to be a real number
            continue
        score = 0.97 if m.group(0).strip().startswith(("+", "08", "0 8")) else 0.88
        out.append(Detection("PHONE", m.group(0).strip(), m.start(), m.end(), score))
    return out


# --------------------------------------------------------------------------
# IBAN
# --------------------------------------------------------------------------
_IBAN_PATTERN = re.compile(
    r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,3})?\b"
)


def _iban_is_valid(value: str) -> bool:
    """Standard ISO 13616 modulus 97 check."""
    v = re.sub(r"\s", "", value).upper()
    if not 15 <= len(v) <= 34:
        return False
    rearranged = v[4:] + v[:4]
    numeric = "".join(
        str(ord(c) - 55) if c.isalpha() else c for c in rearranged
    )
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def find_iban(text: str) -> list[Detection]:
    out = []
    for m in _IBAN_PATTERN.finditer(text):
        valid = _iban_is_valid(m.group(0))
        out.append(Detection(
            "IBAN", m.group(0), m.start(), m.end(), 0.99 if valid else 0.50
        ))
    return out


# --------------------------------------------------------------------------
# Dates of birth
# --------------------------------------------------------------------------
_MONTHS = (
    "january|february|march|april|may|june|july|august|september|october|"
    "november|december|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec"
)
_DATE_PATTERN = re.compile(
    rf"""\b(?:
          \d{{1,2}}[/\-.]\d{{1,2}}[/\-.](?:19|20)\d{{2}}
        | \d{{1,2}}(?:st|nd|rd|th)?\s+(?:{_MONTHS})\s+(?:19|20)\d{{2}}
        | (?:{_MONTHS})\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+(?:19|20)\d{{2}}
        )\b""",
    re.IGNORECASE | re.VERBOSE,
)
# A date on its own is not necessarily a date of birth. If one of these words
# appears just before it, it almost certainly is.
_DOB_CONTEXT = re.compile(
    r"(date of birth|d\.?o\.?b\.?|born|birthday|dob)\W{0,15}$",
    re.IGNORECASE,
)


def find_dob(text: str) -> list[Detection]:
    out = []
    for m in _DATE_PATTERN.finditer(text):
        lead_in = text[max(0, m.start() - 30):m.start()]
        has_context = bool(_DOB_CONTEXT.search(lead_in))
        out.append(Detection(
            "DOB", m.group(0), m.start(), m.end(),
            0.95 if has_context else 0.55,
        ))
    return out


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------
PATTERN_RECOGNISERS = {
    "EMAIL": find_email,
    "PHONE": find_phone,
    "PPSN": find_ppsn,
    "EIRCODE": find_eircode,
    "IBAN": find_iban,
    "DOB": find_dob,
}


def run_pattern_recognisers(text: str, entity_types: list[str]) -> list[Detection]:
    """Run every pattern recogniser whose entity type has been selected."""
    results: list[Detection] = []
    for code, fn in PATTERN_RECOGNISERS.items():
        if code in entity_types:
            results.extend(fn(text))
    return results


def merge(primary: list[Detection], extra: list[Detection]) -> list[Detection]:
    """
    Merge two lists of detections, dropping duplicates that cover the same
    span and keeping the one with the higher score. This is the step that
    causes most of the false positives, so it is kept small and testable.
    """
    merged = list(primary)
    for candidate in extra:
        clash = next((d for d in merged if d.overlaps(candidate)), None)
        if clash is None:
            merged.append(candidate)
        elif candidate.score > clash.score:
            merged[merged.index(clash)] = candidate
    return sorted(merged, key=lambda d: (d.page, d.start))
