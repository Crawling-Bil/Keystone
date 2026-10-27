"""Word document engine shared by the document generators (LLD Generator,
later Implementation Generator).

Moved unchanged from the Document Generator (Crawling-Bil/Document-Generator,
backend/): ``docgen`` builds the .docx from a master template and a chapter
tree, ``importer`` reads an LLD Content Index workbook, ``placeholders`` fills
``{{...}}`` fields and the customer logo. The XML handling in ``docgen`` was
tuned against real templates; change it only with a golden test.
"""
