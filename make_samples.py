# make_samples.py  (project root)
from docx import Document
from pathlib import Path
 
Path("sample_docs").mkdir(exist_ok=True)
 
FAKE_TEXT = (
    "Dear Mr. Fred Banda, thank you for your FOI request. "
    "We have your details on file: date of birth 12/03/1985, "
    "PPS number 1234567AB, phone 087 123 4567, "
    "email fred.banda@example.com, "
    "address 14 Oak Road, Santry, Dublin 9."
)
 
# Word sample
d = Document()
d.add_heading("FOI Response – Internal Draft", level=1)
d.add_paragraph(FAKE_TEXT)
d.save("sample_docs/sample1.docx")
 
# Email sample
eml = (
    "From: Mary O'Brien <mary.obrien@example.com>\n"
    "To: FOI Unit <foi@example.gov.ie>\n"
    "Subject: Request for records\n\n" + FAKE_TEXT
)
Path("sample_docs/sample1.eml").write_text(eml, encoding="utf-8")
print("Samples created.")


