from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class PerlHighlighter(QSyntaxHighlighter):
    POD_STATE = 1
    HEREDOC_STATE = 2

    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "keyword": "bold",
            "builtin": "",
            "comment": "italic",
            "pod": "italic",
            "string": "",
            "regex": "",
            "variable": "",
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
            "sub", "my", "our", "local", "use", "require", "package", "if", "else",
            "elsif", "for", "foreach", "while", "until", "given", "when", "return",
            "last", "next", "redo", "die", "warn", "eval", "do", "BEGIN", "END"
        ]
        builtins = [
            "print", "say", "chomp", "chop", "split", "join", "map", "grep", "open",
            "close", "die", "warn", "scalar", "bless", "ref", "undef", "pack", "unpack"
        ]

        self.rules = []

        self.rules += [(r"\bsub\s+([A-Za-z_]\w*)\b", "function")]
        self.rules += [(r"\b([A-Za-z_]\w*)\s*(?=\()", "function")]

        self.rules += [(fr"\b{kw}\b", "keyword") for kw in keywords]

        self.rules += [(fr"\b{bi}\b(?!\s*\()", "builtin") for bi in builtins]

        self.rules += [(r"[\$\@\%][A-Za-z_]\w*(?:::[A-Za-z_]\w*)*", "variable")]

        self.rules += [(r"\b0x[0-9A-Fa-f]+\b", "number")]
        self.rules += [(r"\b[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b", "number")]

        self.rules += [(r"^\s*use\b.*", "preprocessor")]
        self.rules += [(r"^\s*require\b.*", "preprocessor")]
        self.rules += [(r"^\s*package\b.*", "preprocessor")]

        self.rules += [(r"#.*", "comment")]

        self.compiled_rules = []
        for pattern, style_name in self.rules:
            try:
                self.compiled_rules.append((QRegularExpression(pattern), style_name))
            except Exception:
                pass

        self.double_string_re = QRegularExpression(r'"(?:[^"\\\n]|\\.)*"')
        self.single_string_re = QRegularExpression(r"'(?:[^'\\\n]|\\.)*'")

        self.qq_re = QRegularExpression(r'qq[^\s\w]?[^ \t\n\r]*?[^\s\w]?')
        self.qx_re = QRegularExpression(r'qx[^\s\w]?[^ \t\n\r]*?[^\s\w]?')
        self.q_re = QRegularExpression(r"q[^\s\w]?[^ \t\n\r]*?[^\s\w]?")

        self.re_simple = QRegularExpression(r'(?:qr|m|s|tr)?\s*([/|{(\[])(?:\\.|[^\\\1\]\)\}])*[\1\]\)\}]?[imsx]*')
        self.slash_regex = QRegularExpression(r'/(?:\\.|[^/\\\n])+/[imsx]*')

        self.line_comment_re = QRegularExpression(r"#.*")

        self.pod_start_re = QRegularExpression(r"^\s*=(?:pod|head\d|item|over|back|begin)\b")
        self.pod_end_re = QRegularExpression(r"^\s*=cut\b")

        self.heredoc_start_re = QRegularExpression(r"<<\s*('?\"?)([A-Za-z_]\w*)\1")
        self.heredoc_simple_re = QRegularExpression(r"<<\s*([A-Za-z_]\w*)")

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

    def _detect_heredoc_start(self, text: str):
        it = self.heredoc_start_re.globalMatch(text)
        if it.hasNext():
            m = it.next()
            quote = m.captured(1)
            delim = m.captured(2)
            quoted = (quote == "'")
            start_pos = m.capturedStart(0)
            return start_pos, delim, quoted
        it2 = self.heredoc_simple_re.globalMatch(text)
        if it2.hasNext():
            m = it2.next()
            delim = m.captured(1)
            start_pos = m.capturedStart(0)
            return start_pos, delim, False
        return None

    def highlightBlock(self, text):
        styles = self.styles

        if self.previousBlockState() == self.POD_STATE:
            end_match = self.pod_end_re.match(text)
            if end_match.hasMatch():
                end_pos = end_match.capturedEnd()
                pod_fmt = styles.get("pod") or styles.get("comment")
                if pod_fmt:
                    self.setFormat(0, end_pos, pod_fmt)
                rest = text[end_pos:]
                self.setCurrentBlockState(0)
                text = rest
            else:
                pod_fmt = styles.get("pod") or styles.get("comment")
                if pod_fmt:
                    self.setFormat(0, len(text), pod_fmt)
                self.setCurrentBlockState(self.POD_STATE)
                return
        else:
            start_it = self.pod_start_re.globalMatch(text)
            if start_it.hasNext():
                m = start_it.next()
                start_pos = m.capturedStart(0)
                pod_fmt = styles.get("pod") or styles.get("comment")
                if pod_fmt:
                    self.setFormat(start_pos, len(text) - start_pos, pod_fmt)
                self.setCurrentBlockState(self.POD_STATE)
                return

        if self.previousBlockState() == self.HEREDOC_STATE:
            pass

        heredoc_info = self._detect_heredoc_start(text)
        heredoc_spans = []
        if heredoc_info:
            start_pos, delim, quoted = heredoc_info
            it = self.heredoc_start_re.globalMatch(text)
            if it.hasNext():
                m = it.next()
                s = m.capturedStart(0); l = m.capturedLength(0)
                heredoc_spans.append((s, l))
        str_fmt = styles.get("string")
        if str_fmt:
            for s, l in heredoc_spans:
                self.setFormat(s, l, str_fmt)

        string_spans = []
        string_spans += self._find_spans(self.double_string_re, text)
        string_spans += self._find_spans(self.single_string_re, text)
        string_spans += self._find_spans(self.qq_re, text)
        string_spans += self._find_spans(self.qx_re, text)
        string_spans += self._find_spans(self.q_re, text)

        if str_fmt:
            for s, l in string_spans:
                self.setFormat(s, l, str_fmt)

        regex_spans = []
        regex_spans += self._find_spans(self.slash_regex, text)
        regex_spans += self._find_spans(self.re_simple, text)
        regex_fmt = styles.get("regex")
        if regex_fmt:
            for s, l in regex_spans:
                if not self._inside_any(s, string_spans):
                    self.setFormat(s, l, regex_fmt)

        comment_spans = self._find_spans(self.line_comment_re, text)
        com_fmt = styles.get("comment")
        if com_fmt:
            for s, l in comment_spans:
                if not self._inside_any(s, string_spans + regex_spans + heredoc_spans):
                    self.setFormat(s, l, com_fmt)

        blocked_spans = list(string_spans) + list(regex_spans) + list(comment_spans) + list(heredoc_spans)

        for qre, style_name in getattr(self, "compiled_rules", ()):
            it = qre.globalMatch(text)
            while it.hasNext():
                m = it.next()
                try:
                    if m.capturedStart(1) != -1:
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

        if self.currentBlockState() not in (self.POD_STATE, self.HEREDOC_STATE):
            self.setCurrentBlockState(0)
