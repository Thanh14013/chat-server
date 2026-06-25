import fitz # PyMuPDF
doc = fitz.open("baocao.pdf")
page = doc[14] # Page 15 (0-indexed)
print("Page 15 text:")
print(page.get_text())
print("\nPage 16 text:")
print(doc[15].get_text())
