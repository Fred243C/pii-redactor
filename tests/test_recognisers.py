"""Unit tests mapped to the test procedure in the design document."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from recognisers import (Detection, find_dob, find_eircode, find_email, find_iban,
                         find_ppsn, is_valid_ppsn, merge, ppsn_check_character)


# TC-09: PPSN recogniser against valid and invalid numbers
VALID_DIGITS = ["1234567", "0000001", "7654321", "9876543", "1112223",
                "2233445", "5566778", "8899001", "1357924", "2468013"]


@pytest.mark.parametrize("digits", VALID_DIGITS)
def test_valid_ppsn_accepted(digits):
    ppsn = digits + ppsn_check_character(digits)
    assert is_valid_ppsn(ppsn)


@pytest.mark.parametrize("digits", VALID_DIGITS)
def test_wrong_check_character_rejected(digits):
    correct = ppsn_check_character(digits)
    wrong = "A" if correct != "A" else "B"
    assert not is_valid_ppsn(digits + wrong)


def test_ppsn_with_second_letter():
    check = ppsn_check_character("1234567", "A")
    assert is_valid_ppsn(f"1234567{check}A")


def test_invalid_ppsn_still_flagged_but_low_score():
    """A mistyped PPSN is still personal data, so it is surfaced, not dropped."""
    correct = ppsn_check_character("1234567")
    wrong = "A" if correct != "A" else "B"
    found = find_ppsn(f"PPS 1234567{wrong} on file")
    assert len(found) == 1
    assert found[0].score < 0.6


def test_letter_outside_check_alphabet_not_matched():
    """X, Y and Z are never valid check characters, so they are not PPSNs."""
    assert find_ppsn("reference 1234567Z") == []


# Structured identifiers (NFR-2)
def test_eircode():
    assert [d.text for d in find_eircode("Address D06 X4F2 Dublin")] == ["D06 X4F2"]


def test_d6w_routing_key():
    assert find_eircode("D6W 1234")


def test_email():
    assert [d.text for d in find_email("write to a.b@example.ie today")] == ["a.b@example.ie"]


def test_iban_checksum():
    good = find_iban("IBAN IE29 AIBK 9311 5212 3456 78")
    bad = find_iban("IBAN IE29 AIBK 9311 5212 3456 79")
    assert good[0].score > 0.9
    assert bad[0].score < 0.6


def test_dob_context_raises_score():
    with_context = find_dob("Date of birth: 12 March 1981")
    without = find_dob("Payment made on 12 March 1981")
    assert with_context[0].score > without[0].score


# Merge logic — the step that causes most false positives
def test_merge_keeps_higher_score_on_overlap():
    a = Detection("PERSON", "Mary", 0, 4, 0.60)
    b = Detection("PERSON", "Mary", 0, 4, 0.92)
    assert merge([a], [b])[0].score == 0.92


def test_merge_keeps_non_overlapping():
    a = Detection("PERSON", "Mary", 0, 4, 0.9)
    b = Detection("EMAIL", "x@y.ie", 10, 16, 0.9)
    assert len(merge([a], [b])) == 2
