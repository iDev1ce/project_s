from pathlib import Path
from functools import lru_cache
from markitdown import MarkItDown
from openai import OpenAI

OCR_PROMPT = """
Extract all visible text exactly as written.
Preserve hashes, IPs, domains, URLs, emails, filenames, and table content exactly.
Do not summarize.
Do not paraphrase.
Do not correct OCR mistakes unless the text is unambiguous.
Maintain reading order as much as possible.
"""

@lru_cache(maxsize = 1)
def get_markitdown():
    return MarkItDown(
        enable_plugins=True,
        llm_client=OpenAI(),
        llm_model="gpt-5.4-mini",
        llm_prompt=OCR_PROMPT,
    )


def clean_extracted_text(text):
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\u00ad", "")   # soft hyphen
    text = text.replace("\u200b", "")   # zero-width space
    text = text.replace("\ufeff", "")   # BOM / zero-width no-break

    return text.strip()


def load_document(file_path: str):
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Document not found: {file_path}")

    md = get_markitdown()
    result = md.convert(str(path))

    return clean_extracted_text(result.text_content)