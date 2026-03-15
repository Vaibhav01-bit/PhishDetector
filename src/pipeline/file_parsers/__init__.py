from .pdf_parser import PDFParser
from .docx_parser import DOCXParser
from .xlsx_parser import XLSXParser
from .html_parser import HTMLParser
from .txt_parser import TXTParser
from .zip_parser import ZIPParser

__all__ = [
    "PDFParser",
    "DOCXParser",
    "XLSXParser",
    "HTMLParser",
    "TXTParser",
    "ZIPParser",
]
