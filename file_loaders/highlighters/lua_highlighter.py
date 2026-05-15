from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class LuaHighlighter(QSyntaxHighlighter):
    BLOCK_COMMENT_STATE = 1
    LONGSTRING_BLOCK_STATE = 2

    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "keyword": "bold",
            "builtin": "",
            "comment": "italic",
            "string": "",
            "number": "",
            "function": "bold",
            "preprocessor": "bold",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, "#ffffff")
            self.styles[name] = self._format(color, flag)

        keywords = [
            "and", "break", "do", "else", "elseif", "end", "false", "for",
            "function", "if", "in", "local", "nil", "not", "or", "repeat",
            "return", "then", "true", "until", "while", "goto"
        ]
        builtins = [
            "print", "pairs", "ipairs", "next", "tonumber", "tostring",
            "type", "table", "string", "math", "coroutine", "io", "os", "debug"
        ]

        self.rules = []
        self.rules += [(r"\b(?:local\s+)?function\s+([A-Za-z_]\w*(?::[A-Za-z_]\w*|(?:\.[A-Za-z_]\w*)*)?)", "function")]
        self.rules += [(r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*(?=\()", "function")]
        self.rules += [(fr"\b{kw}\b", "keyword") for kw in keywords]
        self.rules += [(fr"\b{bi}\b(?!\s*\()", "builtin") for bi in builtins]
        self.rules += [(r"\b0x[0-9A-Fa-f]+\b", "number")]
        self.rules += [(r"\b[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?\b", "number")]
        self.rules += [(r"^\s*#!.*", "preprocessor")]
        self.rules += [(r"^\s*--[@!].*", "preprocessor")]

        self.compiled_rules = []
        for pattern, style_name in self.rules:
            try:
                self.compiled_rules.append((QRegularExpression(pattern), style_name))
            except Exception:
                pass

        self.long_open_re = QRegularExpression(r"\[(=*)\[")
        self.long_close_re = QRegularExpression(r"\](=*)\]")

        self.double_string_re = QRegularExpression(r'"(?:[^"\\\n]|\\.)*"')
        self.single_string_re = QRegularExpression(r"'(?:[^'\\\n]|\\.)*'")

        self.line_comment_re = QRegularExpression(r"--[^\n]*")
        self.block_comment_start = QRegularExpression(r"--\[(=*)\[")
        self.block_comment_end = QRegularExpression(r"\](=*)\]")

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

    def _match_long_open_at(self, text: str, pos: int):
        m = self.long_open_re.match(text, pos)
        if m.hasMatch():
            return len(m.captured(1))
        return -1

    def _find_long_close(self, text: str, eq_count: int, start_pos: int):
        seq = "]" + ("=" * eq_count) + "]"
        idx = text.find(seq, start_pos)
        return idx

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

    def highlightBlock(self, text):
        styles = self.styles

        if self.previousBlockState() == self.BLOCK_COMMENT_STATE:
            mclose = self.block_comment_end.match(text)
            if mclose.hasMatch():
                end = mclose.capturedEnd()
                fmt = styles.get("comment")
                if fmt:
                    self.setFormat(0, end, fmt)
                rest = text[end:]
                self.setCurrentBlockState(0)
                text = rest
            else:
                fmt = styles.get("comment")
                if fmt:
                    self.setFormat(0, len(text), fmt)
                self.setCurrentBlockState(self.BLOCK_COMMENT_STATE)
                return

        if self.previousBlockState() == self.LONGSTRING_BLOCK_STATE:
            mclose = self.long_close_re.match(text)
            if mclose.hasMatch():
                end = mclose.capturedEnd()
                fmt = styles.get("string")
                if fmt:
                    self.setFormat(0, end, fmt)
                self.setCurrentBlockState(0)
                text = text[end:]
            else:
                fmt = styles.get("string")
                if fmt:
                    self.setFormat(0, len(text), fmt)
                self.setCurrentBlockState(self.LONGSTRING_BLOCK_STATE)
                return

        long_spans = []
        comment_spans = []

        i = 0
        L = len(text)
        while i < L:
            if text.startswith("--[", i):
                j = i + 2
                if j < L and text[j] == "[":
                    k = j + 1
                    eq_count = 0
                    while k < L and text[k] == "=":
                        eq_count += 1
                        k += 1
                    if k < L and text[k] == "[":
                        close_seq = "]" + ("=" * eq_count) + "]"
                        end_idx = text.find(close_seq, k + 1)
                        if end_idx != -1:
                            span_len = end_idx + len(close_seq) - i
                            comment_spans.append((i, span_len))
                            i = end_idx + len(close_seq)
                            continue
                        else:
                            comment_spans.append((i, len(text) - i))
                            self.setCurrentBlockState(self.BLOCK_COMMENT_STATE)
                            break
            if text.startswith("[", i):
                j = i
                k = j + 1
                eq_count = 0
                while k < L and text[k] == "=":
                    eq_count += 1
                    k += 1
                if k < L and text[k] == "[":
                    close_seq = "]" + ("=" * eq_count) + "]"
                    end_idx = text.find(close_seq, k + 1)
                    if end_idx != -1:
                        span_len = end_idx + len(close_seq) - j
                        long_spans.append((j, span_len))
                        i = end_idx + len(close_seq)
                        continue
                    else:
                        long_spans.append((j, len(text) - j))
                        self.setCurrentBlockState(self.LONGSTRING_BLOCK_STATE)
                        break
            i += 1

        str_fmt = styles.get("string")
        if str_fmt:
            for s, l in long_spans:
                self.setFormat(s, l, str_fmt)
        com_fmt = styles.get("comment")
        if com_fmt:
            for s, l in comment_spans:
                self.setFormat(s, l, com_fmt)

        string_spans = []
        string_spans += self._find_spans(self.double_string_re, text)
        string_spans += self._find_spans(self.single_string_re, text)
        if str_fmt:
            for s, l in string_spans:
                if not self._inside_any(s, long_spans + comment_spans):
                    self.setFormat(s, l, str_fmt)

        line_comments = self._find_spans(self.line_comment_re, text)
        if com_fmt:
            for s, l in line_comments:
                if not self._inside_any(s, long_spans + string_spans):
                    self.setFormat(s, l, com_fmt)

        blocked_spans = list(long_spans) + list(string_spans) + list(comment_spans) + list(line_comments)

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

        if self.currentBlockState() not in (self.BLOCK_COMMENT_STATE, self.LONGSTRING_BLOCK_STATE):
            self.setCurrentBlockState(0)
