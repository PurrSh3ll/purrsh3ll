from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class GoHighlighter(QSyntaxHighlighter):
    BLOCK_COMMENT_STATE = 1
    RAWSTRING_BLOCK_STATE = 2

    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "keyword": "bold",
            "type": "bold",
            "builtin": "",
            "comment": "italic",
            "string": "",
            "rune": "",
            "number": "",
            "function": "bold",
            "preprocessor": "bold",
            "package": "bold",
            "method": "bold",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, "#ffffff")
            self.styles[name] = self._format(color, flag)

        keywords = [
            "break", "default", "func", "interface", "select", "case", "defer",
            "go", "map", "struct", "chan", "else", "goto", "package", "switch",
            "const", "fallthrough", "if", "range", "type", "continue", "for",
            "import", "return", "var"
        ]
        types = [
            "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16",
            "uint32", "uint64", "uintptr", "byte", "rune", "float32", "float64",
            "complex64", "complex128", "bool", "string", "error", "any"
        ]
        builtins = [
            "append", "cap", "close", "complex", "copy", "delete", "imag", "len",
            "make", "new", "panic", "print", "println", "real", "recover"
        ]

        self.rules = []

        self.rules += [(r"\bfunc\s+(?:\([^\)]*\)\s*)?([A-Za-z_]\w*)\b", "function")]

        self.rules += [(r"^\s*package\s+[A-Za-z_]\w*\b", "package")]
        self.rules += [(r"^\s*import\b.*", "preprocessor")]

        self.rules += [(fr"\b{kw}\b", "keyword") for kw in keywords]
        self.rules += [(fr"\b{t}\b", "type") for t in types]

        self.rules += [(fr"\b{bi}\b(?!\s*\()", "builtin") for bi in builtins]

        self.rules += [(r"\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\b", "type")]

        self.rules += [(r"\b0b[01]+(?:_[01]+)*\b", "number")]
        self.rules += [(r"\b0x[0-9A-Fa-f]+(?:_[0-9A-Fa-f]+)*\b", "number")]
        self.rules += [(r"\b[0-9]+(?:_[0-9]+)*(?:\.[0-9]+(?:_[0-9]+)*)?(?:[eE][+-]?[0-9]+(?:_[0-9]+)*)?\b", "number")]

        self.rules += [(r"\b([A-Za-z_]\w*)\s*(?=\()", "method")]

        self.rules += [(r"//.*", "comment")]

        self.compiled_rules = []
        for pattern, style_name in self.rules:
            try:
                self.compiled_rules.append((QRegularExpression(pattern), style_name))
            except Exception:
                pass

        self.double_string_re = QRegularExpression(r'"(?:[^"\\\n]|\\.)*"')
        self.rune_re = QRegularExpression(r"\'(?:[^'\\\n]|\\.)\'")
        self.comment_start = QRegularExpression(r"/\*")
        self.comment_end = QRegularExpression(r"\*/")

    def _format(self, color, style=""):
        fmt = QTextCharFormat()
        if isinstance(color, QColor):
            fmt.setForeground(color)
        else:
            try:
                fmt.setForeground(QColor(color))
            except Exception:
                fmt.setForeground(QColor("#ffffff"))
        if "bold" in style:
            fmt.setFontWeight(QFont.Weight.Bold)
        if "italic" in style:
            fmt.setFontItalic(True)
        return fmt

    def update_colors(self, mapping: dict | None = None):
        src = mapping if mapping is not None else getattr(self.controller, "qss_QPainter", {})
        updated = False
        for name, flag in self._style_flags.items():
            if name in src:
                color = src[name]
                self.styles[name] = self._format(color, flag)
                updated = True
        if updated:
            try:
                self.rehighlight()
            except Exception:
                pass

    def _find_spans(self, qre: QRegularExpression, text: str):
        spans = []
        it = qre.globalMatch(text)
        while it.hasNext():
            m = it.next()
            s = m.capturedStart(0)
            l = m.capturedLength(0)
            if s >= 0 and l > 0:
                spans.append((s, l))
        return spans

    def _inside_any(self, pos: int, spans: list[tuple[int,int]]) -> bool:
        for s, l in spans:
            if pos >= s and pos < s + l:
                return True
        return False

    def _find_rawstring_spans(self, text: str):
        spans = []
        pos_search = 0

        if self.previousBlockState() == self.RAWSTRING_BLOCK_STATE:
            start_index = 0
        else:
            start_index = text.find("`", 0)

        while start_index != -1:
            end_index = text.find("`", start_index + 1)
            if end_index != -1:
                spans.append((start_index, end_index - start_index + 1))
                start_index = text.find("`", end_index + 1)
            else:
                spans.append((start_index, len(text) - start_index))
                return spans, True
        return spans, False

    def highlightBlock(self, text):
        styles = self.styles

        if self.previousBlockState() == self.BLOCK_COMMENT_STATE:
            end_match = self.comment_end.match(text)
            if end_match.hasMatch():
                end_pos = end_match.capturedEnd()
                comment_fmt = styles.get("comment")
                if comment_fmt:
                    self.setFormat(0, end_pos, comment_fmt)
                rest = text[end_pos:]
                self.setCurrentBlockState(0)
                text_after = rest
                text = text_after
            else:
                comment_fmt = styles.get("comment")
                if comment_fmt:
                    self.setFormat(0, len(text), comment_fmt)
                self.setCurrentBlockState(self.BLOCK_COMMENT_STATE)
                return

        raw_spans, raw_open = self._find_rawstring_spans(text)
        if raw_open:
            self.setCurrentBlockState(self.RAWSTRING_BLOCK_STATE)
        else:
            if self.currentBlockState() == self.RAWSTRING_BLOCK_STATE:
                self.setCurrentBlockState(0)

        string_fmt = styles.get("string")
        if string_fmt:
            for s, l in raw_spans:
                self.setFormat(s, l, string_fmt)

        if self.previousBlockState() == self.RAWSTRING_BLOCK_STATE and raw_open:
            return
        if raw_open:
            return

        string_spans = self._find_spans(self.double_string_re, text)
        rune_spans = self._find_spans(self.rune_re, text)

        if string_fmt:
            for s, l in string_spans:
                self.setFormat(s, l, string_fmt)
        rune_fmt = styles.get("rune")
        if rune_fmt:
            for s, l in rune_spans:
                self.setFormat(s, l, rune_fmt)

        it_c = QRegularExpression(r"//.*").globalMatch(text)
        comment_fmt = styles.get("comment")
        while it_c.hasNext():
            m = it_c.next()
            s = m.capturedStart(0); l = m.capturedLength(0)
            blocked = string_spans + rune_spans + raw_spans
            if not self._inside_any(s, blocked):
                if comment_fmt:
                    self.setFormat(s, l, comment_fmt)

        blocked_spans = list(string_spans) + list(rune_spans) + list(raw_spans)
        comment_spans = self._find_spans(QRegularExpression(r"//.*"), text)
        blocked_spans += comment_spans

        for qre, style_name in getattr(self, "compiled_rules", ()):
            it = qre.globalMatch(text)
            while it.hasNext():
                m = it.next()
                try:
                    if m.capturedStart(1) != -1:
                        start = m.capturedStart(1); length = m.capturedLength(1)
                    elif m.capturedStart(2) != -1:
                        start = m.capturedStart(2); length = m.capturedLength(2)
                    else:
                        start = m.capturedStart(0); length = m.capturedLength(0)
                except Exception:
                    start = m.capturedStart(0); length = m.capturedLength(0)

                if length > 0 and start >= 0:
                    if self._inside_any(start, blocked_spans):
                        continue
                    fmt = styles.get(style_name)
                    if fmt:
                        self.setFormat(start, length, fmt)

        if self.currentBlockState() not in (self.BLOCK_COMMENT_STATE, self.RAWSTRING_BLOCK_STATE):
            self.setCurrentBlockState(0)
