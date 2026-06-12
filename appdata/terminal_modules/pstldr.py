#!/usr/bin/env python3
"""
pstldr.py — AI-powered TL;DR summarizer for PurrSh3ll.
Accepts text directly, a file path, or stdin via pipe.
"""

import os
import sys

_BINARY_CHECK_BYTES = 512


def _is_binary(path: str) -> bool:
    """Return True if the file appears to be binary (contains null bytes)."""
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(_BINARY_CHECK_BYTES)
    except Exception:
        return True


def _read_pdf(path: str) -> str | None:
    """Extract text from a PDF using PyMuPDF (fitz) or pypdf as fallback."""
    # Try PyMuPDF first (faster, better extraction)
    try:
        import fitz
        doc = fitz.open(path)
        pages = []
        try:
            for i in range(len(doc)):
                text = doc[i].get_text()
                if text.strip():
                    pages.append(text)
        finally:
            doc.close()
        return "\n\n".join(pages) if pages else None
    except ImportError:
        pass
    except Exception:
        return None

    # Fallback: pypdf
    try:
        from pypdf import PdfReader
        reader = PdfReader(path)
        pages = []
        for page in reader.pages:
            text = page.extract_text() or ""
            if text.strip():
                pages.append(text)
        return "\n\n".join(pages) if pages else None
    except ImportError:
        return None
    except Exception:
        return None


def _read_file(path: str) -> str | None:
    """Try to read a text file with common encodings."""
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, LookupError):
            continue
    return None


def main():
    import argparse

    parser = argparse.ArgumentParser(prog="pstldr", add_help=False)
    parser.add_argument("input", nargs="*",
                        help="Text to summarize, or path to a file")
    parser.add_argument("--base-dir", default=None, metavar="DIR")
    parser.add_argument("-p", "--profile", default=None, metavar="PROFILE",
                        dest="profile", help="Use a specific saved profile by name")
    parser.add_argument("--head", nargs="?", const=4000, type=int, metavar="N",
                        help="Send only the first N characters (default 4000)")
    parser.add_argument("--tail", nargs="?", const=4000, type=int, metavar="N",
                        help="Send only the last N characters (default 4000)")
    parser.add_argument("-h", "--help", action="store_true")
    args = parser.parse_args()

    if args.help:
        print(
            "pstldr — AI-powered TL;DR summarizer\n\n"
            "Usage:\n"
            "  pstldr <file>                    Summarize a text or PDF file\n"
            "  pstldr \"<text>\"                  Summarize text passed directly\n"
            "  cat file | pstldr               Summarize piped input\n"
            "  pstldr -p, --profile <name>     Use a specific saved profile\n"
            "  pstldr --head [N] <file>         Send only the first N chars (default 4000)\n"
            "  pstldr --tail [N] <file>         Send only the last N chars (default 4000, useful for logs)\n\n"
            "Supported file types:\n"
            "  Plain text  — .txt, .md, .log, source code, and any UTF-8 text file\n"
            "  PDF         — .pdf (extracted via PyMuPDF; pypdf used as fallback)\n"
        )
        sys.exit(0)

    base_dir = args.base_dir or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )

    sys.path.insert(0, os.path.dirname(__file__))
    import psai as _ai

    config  = _ai._load_config(base_dir)
    profile = _ai._resolve_profile(config, args.profile)
    if not profile:
        if not args.profile:
            _ai._err("No active API profile. Set one in AI Settings > API Providers.")
        sys.exit(1)

    api_key          = _ai._load_api_key(profile.get("name", ""), base_dir)
    provider         = profile.get("provider", "ollama")
    url              = profile.get("url", "") or _ai._DEFAULT_URLS.get(provider, "")
    model            = profile.get("model", "")
    custom_params    = _ai._parse_custom_params(profile)
    disable_thinking = bool(profile.get("disable_thinking", False)) and not custom_params

    # ── Resolve input ──────────────────────────────────────────────────────────
    source_label = "text"
    content = ""
    is_file = False

    if not sys.stdin.isatty():
        # Piped input
        content = sys.stdin.read()
        source_label = "piped text"
    elif args.input:
        joined = " ".join(args.input)
        if os.path.isfile(joined):
            if joined.lower().endswith(".pdf"):
                content = _read_pdf(joined)
                if content is None:
                    _ai._err(
                        f"Cannot extract text from PDF: {joined}\n"
                        "Make sure PyMuPDF (pip install pymupdf) or pypdf (pip install pypdf) is installed."
                    )
                    sys.exit(1)
            elif _is_binary(joined):
                _ai._err(f"File appears to be binary: {joined}\nOnly text files are supported.")
                sys.exit(1)
            else:
                content = _read_file(joined)
                if content is None:
                    _ai._err(f"Cannot decode file (tried utf-8, utf-8-sig, latin-1): {joined}")
                    sys.exit(1)
            source_label = f"file: {os.path.basename(joined)}"
            is_file = True
        else:
            content = joined
            source_label = "text"
    else:
        _ai._err("No input provided. Pass text, a file path, or pipe content via stdin.")
        sys.exit(1)

    content = content.strip()
    if not content:
        _ai._err("Input is empty — nothing to summarize.")
        sys.exit(1)

    if args.head is not None:
        content = content[:args.head]
    elif args.tail is not None:
        content = content[-args.tail:]

    # ── Build prompt ───────────────────────────────────────────────────────────
    prompt = (
        f"Summarize the following {source_label} concisely. "
        "Highlight the key points. Be clear and practical.\n\n"
        f"{content}"
    )

    if _ai._SHOW_QUERYING:
        _ai._info(f"Querying {model} via {provider}…\n")
    _ai._info(f"Summarizing {source_label}...\n")
    messages = [{"role": "user", "content": prompt}]
    _ai._run_llm(provider, model, messages, url, api_key, disable_thinking, custom_params)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()
        sys.exit(130)
