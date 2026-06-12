import bisect

from pygments.token import Comment, Keyword, Name, String, Number, Operator, Generic, Literal
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont

# Ordered most-specific → least-specific so the first match wins.
_TOKEN_STYLE_MAP = [
    (Comment.Multiline,     "block_comment"),
    (Comment.Hashbang,      "shebang"),
    (Comment,               "comment"),
    (Keyword.Type,          "type"),
    (Keyword,               "keyword"),
    (Name.Builtin.Pseudo,   "keyword"),
    (Name.Builtin,          "builtin"),
    (Name.Function.Magic,   "function"),
    (Name.Function,         "function"),
    (Name.Class,            "class"),
    (Name.Namespace,        "namespace"),
    (Name.Decorator,        "preprocessor"),
    (Name.Label,            "label"),
    (Name.Variable,         "variable"),
    (Name.Tag,              "tag"),
    (Name.Attribute,        "attribute"),
    (String.Doc,            "block_comment"),
    (String.Interpol,       "interpolation"),
    (String.Regex,          "regex"),
    (String.Heredoc,        "heredoc"),
    (String,                "string"),
    (Literal.String,        "string"),
    (Number,                "number"),
    (Literal.Number,        "number"),
    (Operator.Word,         "keyword"),
    (Generic.Heading,       "function"),
    (Generic.Subheading,    "builtin"),
]

_STYLE_FLAGS = {
    "keyword":       "bold",
    "function":      "bold",
    "class":         "bold",
    "comment":       "italic",
    "block_comment": "italic",
}


def _resolve_style_key(ttype):
    for token_type, style_key in _TOKEN_STYLE_MAP:
        if ttype is token_type or ttype in token_type:
            return style_key
    return None


class PygmentsHighlighter(QSyntaxHighlighter):
    """QSyntaxHighlighter backed by Pygments tokenizer.

    Drop-in replacement for all hand-written regex highlighters.
    Interface: __init__(document, controller, lexer)  +  update_colors().
    """

    def __init__(self, document, controller, lexer):
        super().__init__(document)
        self.controller = controller
        self._lexer = lexer
        self._lexer.stripnl = False  # preserve exact text length
        self._dirty = True
        self._token_cache: dict[int, list[tuple[int, int, QTextCharFormat]]] = {}
        self._formats: dict[str, QTextCharFormat] = {}
        self._build_formats()
        document.contentsChanged.connect(self._mark_dirty)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _mark_dirty(self):
        self._dirty = True

    def _build_formats(self):
        q = getattr(self.controller, "qss_QPainter", {})
        self._formats = {}
        seen: set[str] = set()
        for _, style_key in _TOKEN_STYLE_MAP:
            if style_key in seen:
                continue
            seen.add(style_key)
            color = q.get(style_key)
            if not color:
                continue
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(color))
            flags = _STYLE_FLAGS.get(style_key, "")
            if "bold" in flags:
                fmt.setFontWeight(QFont.Weight.Bold)
            if "italic" in flags:
                fmt.setFontItalic(True)
            self._formats[style_key] = fmt

    def _tokenize(self):
        """Tokenize the whole document with Pygments and populate _token_cache."""
        self._dirty = False
        self._token_cache = {}
        doc = self.document()
        full_text = doc.toPlainText()
        if not full_text:
            return

        # Pre-build line-start character positions for O(log n) block lookup.
        line_starts = [0]
        for i, ch in enumerate(full_text):
            if ch == '\n':
                line_starts.append(i + 1)

        try:
            tokens = self._lexer.get_tokens(full_text)
        except Exception:
            return

        pos = 0
        for ttype, value in tokens:
            vlen = len(value)
            if not vlen:
                continue

            style_key = _resolve_style_key(ttype)
            fmt = self._formats.get(style_key) if style_key else None

            if fmt is not None:
                if '\n' not in value:
                    # Fast path: single-line token.
                    line_idx = bisect.bisect_right(line_starts, pos) - 1
                    self._token_cache.setdefault(line_idx, []).append(
                        (pos - line_starts[line_idx], vlen, fmt)
                    )
                else:
                    # Slow path: token spans multiple lines.
                    rpos = pos
                    remaining = value
                    while remaining:
                        nl = remaining.find('\n')
                        chunk_len = nl if nl != -1 else len(remaining)
                        if chunk_len:
                            line_idx = bisect.bisect_right(line_starts, rpos) - 1
                            self._token_cache.setdefault(line_idx, []).append(
                                (rpos - line_starts[line_idx], chunk_len, fmt)
                            )
                        if nl == -1:
                            break
                        rpos += nl + 1
                        remaining = remaining[nl + 1:]

            pos += vlen

    # ------------------------------------------------------------------
    # QSyntaxHighlighter interface
    # ------------------------------------------------------------------

    def highlightBlock(self, text):  # noqa: N802
        if self._dirty:
            self._tokenize()
        block_num = self.currentBlock().blockNumber()
        for start, length, fmt in self._token_cache.get(block_num, ()):
            self.setFormat(start, length, fmt)

    # ------------------------------------------------------------------
    # Public API (matches old highlighters)
    # ------------------------------------------------------------------

    def update_colors(self, mapping: dict | None = None):
        if mapping is not None:
            # Merge partial update into controller's palette so _build_formats
            # can read a complete picture.
            q = getattr(self.controller, "qss_QPainter", {})
            q.update(mapping)
        self._build_formats()
        self._dirty = True
        try:
            self.rehighlight()
        except Exception:
            pass
