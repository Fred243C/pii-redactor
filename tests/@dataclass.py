class Detection:
    entity_type: str        # "PPSN"
    text: str               # the matched value, held in memory only
    start: int              # character offset in the extracted text
    end: int
    score: float            # 0.0 to 1.0
    page: int = 1
    source: str = "Custom"  # "Custom", "Presidio", "Fallback" or "Azure"
    accepted: bool = True

    def overlaps(self, other):
        return self.start < other.end and other.start < self.end