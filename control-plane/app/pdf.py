"""Dependency-free PDF writer for the platform's plain text documents.

Extracted from api/engagements.py, where it was written for the authorization
document, so the generated report (REQ-REPORT-001) renders through the same
writer instead of a second, divergent implementation. No behavior change: the
functions are moved verbatim.

Deliberately not a PDF library: these documents are plain, wrapped, monospaced
prose with no images or tables, and the output has to be reproducible byte-for
-byte for the authorization document's configuration checksum to mean anything.
"""

from __future__ import annotations

import textwrap

# 47 lines per page and 94 characters per line are what Helvetica 10pt at 14pt
# leading fits inside a US Letter page with the 50pt margin used below.
LINES_PER_PAGE = 47
WRAP_WIDTH = 94


def text(value: object) -> str:
    return str(value if value is not None else "-").replace("\r", " ").replace("\n", " ")


def pdf_escape(value: object) -> str:
    return text(value).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def wrap_pdf_lines(lines: list[str], width: int = WRAP_WIDTH) -> list[str]:
    wrapped: list[str] = []
    for line in lines:
        if not line:
            wrapped.append("")
            continue
        parts = textwrap.wrap(line, width=width, replace_whitespace=False, drop_whitespace=True)
        wrapped.extend(parts or [""])
    return wrapped


def simple_pdf(title: str, lines: list[str]) -> bytes:
    """Small dependency-free PDF writer for plain authorization documents."""
    all_lines = wrap_pdf_lines([title, ""] + lines)
    pages = [all_lines[i:i + LINES_PER_PAGE] for i in range(0, len(all_lines), LINES_PER_PAGE)] or [[title]]
    objects: dict[int, bytes] = {}
    page_ids: list[int] = []

    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

    for index, page_lines in enumerate(pages):
        content_id = 4 + index * 2
        page_id = 5 + index * 2
        page_ids.append(page_id)
        stream_lines = ["BT", "/F1 10 Tf", "50 790 Td", "14 TL"]
        for line in page_lines:
            stream_lines.append(f"({pdf_escape(line)}) Tj")
            stream_lines.append("T*")
        stream_lines.append("ET")
        content = ("\n".join(stream_lines) + "\n").encode("latin-1", "replace")
        objects[content_id] = b"<< /Length " + str(len(content)).encode("ascii") + b" >>\nstream\n" + content + b"endstream"
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")

    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = {0: 0}
    for object_id in sorted(objects):
        offsets[object_id] = len(output)
        output.extend(f"{object_id} 0 obj\n".encode("ascii"))
        output.extend(objects[object_id])
        output.extend(b"\nendobj\n")

    xref_at = len(output)
    max_id = max(objects)
    output.extend(f"xref\n0 {max_id + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for object_id in range(1, max_id + 1):
        output.extend(f"{offsets.get(object_id, 0):010d} 00000 n \n".encode("ascii"))
    output.extend(f"trailer\n<< /Size {max_id + 1} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n".encode("ascii"))
    return bytes(output)
