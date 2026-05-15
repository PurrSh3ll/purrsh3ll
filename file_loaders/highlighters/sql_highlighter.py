import re
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class SqlHighlighter(QSyntaxHighlighter):

    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "keyword": "bold",
            "type": "bold",
            "function": "",
            "comment": "italic",
            "string": "",
            "number": "",
            "identifier": "",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, "#ffffff")
            self.styles[name] = self._format(color, flag)

        self.keywords = [
            "select", "insert", "update", "delete", "from", "where", "join", "left", "right",
            "inner", "outer", "on", "group", "by", "order", "having", "limit", "offset",
            "union", "all", "distinct", "into", "values", "create", "alter", "drop", "table",
            "view", "index", "primary", "key", "foreign", "constraint", "references",
            "if", "exists", "case", "when", "then", "else", "end", "as", "with", "begin", "commit"
        ]

        self.types = [
            "int", "integer", "smallint", "bigint", "varchar", "char", "text", "boolean",
            "bool", "date", "time", "timestamp", "numeric", "decimal", "float", "real", "double"
        ]

        self.functions = [
            "count", "sum", "min", "max", "avg", "now", "coalesce", "upper", "lower", "substr",
            "substring", "length", "round", "concat"
        ]

        def escaped_alt(words):
            esc = [re.escape(w) for w in words]
            esc.sort(key=len, reverse=True)
            return "|".join(esc)

        self.rules = []

        self.rules.append((r"--.*", "comment"))

        self.rules.append((r"'(?:[^'\\\n]|\\.)*'", "string"))
        self.rules.append((r'"(?:[^"\\\n]|\\.)*"', "string"))

        self.rules.append((r"\b\d+\.\d+\b", "number"))
        self.rules.append((r"\b\d+\b", "number"))

        self.rules.append((r"\b([A-Za-z_][\w]*)\s*(?=\()", "function"))

        if self.types:
            types_pat = rf"(?i)\b(?:{escaped_alt(self.types)})\b"
            self.rules.append((types_pat, "type"))
        if self.keywords:
            kw_pat = rf"(?i)\b(?:{escaped_alt(self.keywords)})\b"
            self.rules.append((kw_pat, "keyword"))

        self.rules.append((r"\b[A-Za-z_][\w]*\.[A-Za-z_][\w]*\b", "identifier"))

        self.compiled_rules = []
        for pattern, name in self.rules:
            try:
                qre = QRegularExpression(pattern)
                if qre.isValid():
                    self.compiled_rules.append((qre, name))
            except Exception:
                pass

        self.comment_start = QRegularExpression(r"/\*")
        self.comment_end = QRegularExpression(r"\*/")

        self.string_re = QRegularExpression(r"'(?:[^'\\\n]|\\.)*'")
        self.string_double_re = QRegularExpression(r'"(?:[^"\\\n]|\\.)*"')
        self.line_comment_re = QRegularExpression(r"--.*")

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

    def _find_spans(self, qre: QRegularExpression, text: str):
        spans = []
        it = qre.globalMatch(text)
        while it.hasNext():
            m = it.next()
            s = m.capturedStart(0); l = m.capturedLength(0)
            if s >= 0 and l > 0:
                spans.append((s, l, m))
        return spans

    def _inside_any(self, pos: int, spans: list[tuple[int, int]]):
        for s, l in spans:
            if pos >= s and pos < s + l:
                return True
        return False

    def update_colors(self, mapping: dict | None = None):
        src = mapping if mapping is not None else getattr(self.controller, "qss_QPainter", {})
        updated = False
        for name, flag in self._style_flags.items():
            if name in src:
                self.styles[name] = self._format(src[name], flag)
                updated = True
        if updated:
            try:
                self.rehighlight()
            except Exception:
                pass

    def highlightBlock(self, text):
        styles = self.styles

        start_index = 0
        if self.previousBlockState() != 1:
            start_match = self.comment_start.match(text)
            start_index = start_match.capturedStart() if start_match.hasMatch() else -1
        else:
            start_index = 0

        comment_fmt = styles.get("comment")
        while start_index >= 0:
            end_match = self.comment_end.match(text, start_index + (0 if self.previousBlockState() == 1 else 0))
            if end_match.hasMatch():
                end_index = end_match.capturedEnd()
                length = end_index - start_index
                if comment_fmt:
                    self.setFormat(start_index, length, comment_fmt)
                start_match = self.comment_start.match(text, end_index)
                start_index = start_match.capturedStart() if start_match.hasMatch() else -1
                self.setCurrentBlockState(0)
            else:
                if comment_fmt:
                    self.setFormat(start_index, len(text) - start_index, comment_fmt)
                self.setCurrentBlockState(1)
                break

        if self.currentBlockState() != 1:
            self.setCurrentBlockState(0)

        comment_spans = []
        it = self.line_comment_re.globalMatch(text)
        while it.hasNext():
            m = it.next()
            s = m.capturedStart(0); l = m.capturedLength(0)
            if s >= 0 and l > 0:
                comment_spans.append((s, l))
        if comment_fmt:
            for s, l in comment_spans:
                self.setFormat(s, l, comment_fmt)

        string_spans = []
        it = self.string_re.globalMatch(text)
        while it.hasNext():
            m = it.next()
            s = m.capturedStart(0); l = m.capturedLength(0)
            if s >= 0 and l > 0:
                string_spans.append((s, l))
        it = self.string_double_re.globalMatch(text)
        while it.hasNext():
            m = it.next()
            s = m.capturedStart(0); l = m.capturedLength(0)
            if s >= 0 and l > 0:
                string_spans.append((s, l))

        str_fmt = styles.get("string")
        if str_fmt:
            for s, l in string_spans:
                if not self._inside_any(s, comment_spans):
                    self.setFormat(s, l, str_fmt)

        blocked_spans = list(comment_spans) + list(string_spans)

        for qre, style_name in getattr(self, "compiled_rules", ()):
            if style_name in ("comment", "string"):
                continue
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

                if length <= 0 or start < 0:
                    continue
                if self._inside_any(start, blocked_spans):
                    continue
                fmt = styles.get(style_name)
                if fmt:
                    self.setFormat(start, length, fmt)

        self.setCurrentBlockState(0)
