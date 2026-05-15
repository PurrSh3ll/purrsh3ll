import re
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class HtaccessHighlighter(QSyntaxHighlighter):

    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "directive": "bold",
            "section": "bold",
            "comment": "italic",
            "string": "",
            "variable": "",
            "number": "",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, "#ffffff")
            self.styles[name] = self._format(color, flag)

        directives = [
            "RewriteEngine", "RewriteRule", "RewriteCond", "Redirect", "RedirectMatch",
            "ErrorDocument", "DirectoryIndex", "SetEnv", "SetEnvIf", "Header", "AddType",
            "AuthType", "AuthName", "Require", "Allow", "Deny", "Order"
        ]

        def escaped_alt(words):
            esc = [re.escape(w) for w in words]
            esc.sort(key=len, reverse=True)
            return "|".join(esc)

        self.rules = []

        self.rules.append((r"(?i)<\/?\s*(IfModule|Directory|Files|VirtualHost|Location|Limit|LimitExcept)\b[^>]*>", "section"))

        if directives:
            dirs_pat = rf"(?m)\b(?:{escaped_alt(directives)})\b"
            self.rules.append((dirs_pat, "directive"))

        self.rules.append((r"#.*", "comment"))

        self.rules.append((r'"(?:[^"\\\n]|\\.)*"', "string"))
        self.rules.append((r"'(?:[^'\\\n]|\\.)*'", "string"))

        self.rules.append((r"%\{[A-Za-z0-9_:\-]+\}", "variable"))

        self.rules.append((r"\b(?:\d{1,3}(?:\.\d{1,3}){3})\b", "number"))
        self.rules.append((r"\b\d+\b", "number"))

        self.compiled_rules = []
        for pattern, name in self.rules:
            try:
                qre = QRegularExpression(pattern)
                if qre.isValid():
                    self.compiled_rules.append((qre, name))
            except Exception:
                pass

        self.string_re = QRegularExpression(r'"(?:[^"\\\n]|\\.)*"')
        self.string_single_re = QRegularExpression(r"'(?:[^'\\\n]|\\.)*'")
        self.comment_re = QRegularExpression(r"#.*")

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
            s = m.capturedStart(0)
            l = m.capturedLength(0)
            if s >= 0 and l > 0:
                spans.append((s, l))
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

        section_fmt = styles.get("section")
        section_spans = []
        if section_fmt:
            for qre, name in getattr(self, "compiled_rules", ()):
                if name == "section":
                    it = qre.globalMatch(text)
                    while it.hasNext():
                        m = it.next()
                        s = m.capturedStart(0); l = m.capturedLength(0)
                        if s >= 0 and l > 0:
                            self.setFormat(s, l, section_fmt)
                            section_spans.append((s, l))
                    break

        comment_spans = self._find_spans(self.comment_re, text)
        comment_fmt = styles.get("comment")
        if comment_fmt:
            for s, l in comment_spans:
                self.setFormat(s, l, comment_fmt)

        string_spans = []
        string_spans += self._find_spans(self.string_re, text)
        string_spans += self._find_spans(self.string_single_re, text)
        str_fmt = styles.get("string")
        if str_fmt:
            for s, l in string_spans:
                if not self._inside_any(s, comment_spans):
                    self.setFormat(s, l, str_fmt)

        blocked_spans = list(section_spans) + list(comment_spans) + list(string_spans)

        for qre, style_name in getattr(self, "compiled_rules", ()):
            if style_name in ("section", "comment", "string"):
                continue
            it = qre.globalMatch(text)
            while it.hasNext():
                m = it.next()
                start = m.capturedStart(0)
                length = m.capturedLength(0)
                if length <= 0 or start < 0:
                    continue
                if self._inside_any(start, blocked_spans):
                    continue
                fmt = styles.get(style_name)
                if fmt:
                    self.setFormat(start, length, fmt)

        self.setCurrentBlockState(0)
