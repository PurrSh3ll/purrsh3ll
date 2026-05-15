from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class RubyHighlighter(QSyntaxHighlighter):
    BLOCK_COMMENT_STATE = 1

    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "keyword": "bold",
            "builtin": "",
            "comment": "italic",
            "string": "",
            "interpolation": "bold",
            "regex": "",
            "symbol": "",
            "number": "",
            "function": "bold",
            "class": "bold",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, "#ffffff")
            self.styles[name] = self._format(color, flag)

        keywords = [
            "BEGIN", "END", "alias", "and", "begin", "break", "case", "class",
            "def", "defined?", "do", "else", "elsif", "end", "ensure", "for",
            "if", "in", "module", "next", "nil", "not", "or", "redo", "rescue",
            "retry", "return", "self", "super", "then", "undef", "unless",
            "until", "when", "while", "yield", "include", "extend", "private",
            "protected", "public", "attr_reader", "attr_writer", "attr_accessor"
        ]
        builtins = [
            "puts", "print", "p", "require", "load", "raise", "fail", "lambda",
            "proc", "Integer", "String", "Array", "Hash", "Enumerable", "File",
            "Dir", "Time"
        ]

        self.rules = []

        self.rules += [(r"\b(class|module)\s+([A-Za-z_]\w*)\b", "class")]
        self.rules += [(r"\bdef\s+([A-Za-z_]\w*[!?=]?)\b", "function")]

        self.rules += [(r':"([^"\\]|\\.)*"', "symbol")]
        self.rules += [(r":[A-Za-z_]\w*[!?=]?", "symbol")]

        self.rules += [(r'%r\{[^}]*\}', "regex")]
        self.rules += [(r'/(?:\\.|[^/\\\n])+/[mixounse]*', "regex")]

        self.rules += [(r"\b0b[01_]+\b", "number")]
        self.rules += [(r"\b0x[0-9A-Fa-f_]+\b", "number")]
        self.rules += [(r"\b[0-9][0-9_]*(\.[0-9_]+)?([eE][+-]?[0-9_]+)?\b", "number")]

        self.rules += [(fr"\b{kw}\b", "keyword") for kw in keywords]
        self.rules += [(fr"\b{bi}\b(?!\s*\()", "builtin") for bi in builtins]

        self.rules += [(r"#.*", "comment")]

        self.compiled_rules = []
        for pattern, style_name in self.rules:
            try:
                self.compiled_rules.append((QRegularExpression(pattern), style_name))
            except Exception:
                pass

        self.double_string_re = QRegularExpression(r'"(?:[^"\\\n]|\\.)*"')
        self.single_string_re = QRegularExpression(r'\'(?:[^\'\\\n]|\\.)*\'')

        self.percent_q_re = QRegularExpression(r'%q\{[^\}]*\}|%q\([^\)]*\]|%q\[^[\]]*\]')
        self.percent_Q_re = QRegularExpression(r'%Q\{[^\}]*\}|%Q\([^\)]*\]|%Q\[^[\]]*\]')

        self.line_comment_re = QRegularExpression(r"#.*")

        self.block_comment_start = QRegularExpression(r"^\s*=begin\b")
        self.block_comment_end = QRegularExpression(r"^\s*=end\b")

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

    def _find_interpolations_in(self, text: str, span_start: int, span_len: int):
        spans = []
        i = span_start
        end = span_start + span_len
        while True:
            idx = text.find("#{", i, end)
            if idx == -1:
                break
            depth = 0
            j = idx
            while j < end:
                ch = text[j]
                if text[j:j+2] == "#{":
                    depth += 1
                    j += 2
                    continue
                if ch == "}":
                    depth -= 1
                    j += 1
                    if depth == 0:
                        spans.append((idx, j - idx))
                        break
                    continue
                j += 1
            i = idx + 2
        return spans

    def highlightBlock(self, text):
        styles = self.styles

        if self.previousBlockState() == self.BLOCK_COMMENT_STATE:
            end_match = self.block_comment_end.match(text)
            if end_match.hasMatch():
                end_pos = end_match.capturedEnd()
                fmt = styles.get("comment")
                if fmt:
                    self.setFormat(0, end_pos, fmt)
                self.setCurrentBlockState(0)
            else:
                fmt = styles.get("comment")
                if fmt:
                    self.setFormat(0, len(text), fmt)
                self.setCurrentBlockState(self.BLOCK_COMMENT_STATE)
            return
        else:
            start_match = self.block_comment_start.match(text)
            if start_match.hasMatch():
                fmt = styles.get("comment")
                if fmt:
                    self.setFormat(0, len(text), fmt)
                self.setCurrentBlockState(self.BLOCK_COMMENT_STATE)
                return

        string_spans = []
        string_spans += self._find_spans(self.double_string_re, text)
        string_spans += self._find_spans(self.single_string_re, text)
        string_spans += self._find_spans(self.percent_Q_re, text)
        string_spans += self._find_spans(self.percent_q_re, text)

        s_fmt = styles.get("string")
        if s_fmt:
            for s, l in string_spans:
                self.setFormat(s, l, s_fmt)

        interp_fmt = styles.get("interpolation")
        interp_spans = []
        for s, l in string_spans:
            if s < len(text) and (text[s] == '"' or text[s:s+2] == '%Q' or '#{' in text[s:s+l]):
                found = self._find_interpolations_in(text, s, l)
                if found:
                    for is_, il in found:
                        if interp_fmt:
                            self.setFormat(is_, il, interp_fmt)
                        interp_spans.append((is_, il))

        it = self.line_comment_re.globalMatch(text)
        comment_fmt = styles.get("comment")
        while it.hasNext():
            m = it.next()
            s = m.capturedStart(0)
            l = m.capturedLength(0)
            if not self._inside_any(s, string_spans):
                if comment_fmt:
                    self.setFormat(s, l, comment_fmt)

        blocked_spans = list(string_spans) + list(interp_spans)
        comment_spans = self._find_spans(self.line_comment_re, text)
        blocked_spans += comment_spans

        for qre, style_name in getattr(self, "compiled_rules", ()):
            it = qre.globalMatch(text)
            while it.hasNext():
                m = it.next()
                try:
                    if m.capturedStart(2) != -1:
                        start = m.capturedStart(2); length = m.capturedLength(2)
                    elif m.capturedStart(1) != -1:
                        start = m.capturedStart(1); length = m.capturedLength(1)
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

        self.setCurrentBlockState(0)
