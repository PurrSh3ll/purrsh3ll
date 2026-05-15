import re
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class BatchHighlighter(QSyntaxHighlighter):

    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "label": "bold",
            "keyword": "bold",
            "builtin": "",
            "function": "bold",
            "comment": "italic",
            "string": "",
            "variable": "",
            "number": "",
            "command": "",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        defaults = {
            "label": "#ffd700",
            "keyword": "#cc99ff",
            "builtin": "#66d9ef",
            "function": "#ffd700",
            "comment": "#7f8c8d",
            "string": "#a6e22e",
            "variable": "#f8f8f2",
            "number": "#ae81ff",
            "command": "#f92672",
        }

        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, defaults.get(name, "#ffffff"))
            self.styles[name] = self._format(color, flag)

        keywords = [
            "if", "else", "for", "in", "do", "goto", "call", "exit",
            "setlocal", "endlocal", "enabledelayedexpansion", "disabledelayedexpansion",
            "pushd", "popd",
        ]

        builtins = [
            "echo", "set", "cd", "chdir", "dir", "del", "erase", "copy", "xcopy", "move",
            "ren", "rename", "md", "mkdir", "rd", "rmdir", "type", "start", "assoc",
            "attrib", "cls", "color", "date", "time", "pause", "tasklist", "taskkill",
            "call", "goto", "if", "for", "exit",
        ]

        def escaped_alt(words):
            esc = [re.escape(w) for w in words]
            esc.sort(key=len, reverse=True)
            return "|".join(esc)

        self.rules = []

        self.rules.append((r"^::.*", "comment"))
        self.rules.append((r"(?i)\brem\b.*", "comment"))

        self.rules.append((r"^:([A-Za-z0-9_\-]+)", "function"))

        self.rules.append((r"%~?[A-Za-z0-9_@\-\^!$%]+%", "variable"))
        self.rules.append((r"%%[A-Za-z0-9]", "variable"))

        self.rules.append((r'"(?:[^"\\\n]|\\.)*"', "string"))

        self.rules.append((r"\b\d+\b", "number"))

        if builtins:
            builtins_pat = rf"\b(?:{escaped_alt(builtins)})\b"
            self.rules.append((builtins_pat, "builtin"))
        if keywords:
            kw_pat = rf"\b(?:{escaped_alt(keywords)})\b"
            self.rules.append((kw_pat, "keyword"))

        self.compiled_rules = []
        for pattern, name in self.rules:
            try:
                qre = QRegularExpression(pattern)
                if qre.isValid():
                    self.compiled_rules.append((qre, name))
            except Exception:
                pass

        self.comment_re = QRegularExpression(r"^::.*|(?i)\brem\b.*")
        self.string_re = QRegularExpression(r'"(?:[^"\\\n]|\\.)*"')
        self.label_re = QRegularExpression(r"^:([A-Za-z0-9_\-]+)")
        self.variable_re = QRegularExpression(r"%~?[A-Za-z0-9_@\-\^!$%]+%|%%[A-Za-z0-9]")

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

        comment_spans = self._find_spans(self.comment_re, text)
        comment_fmt = styles.get("comment")
        if comment_fmt:
            for s, l in comment_spans:
                self.setFormat(s, l, comment_fmt)

        string_spans = self._find_spans(self.string_re, text)
        str_fmt = styles.get("string")
        if str_fmt:
            for s, l in string_spans:
                if self._inside_any(s, comment_spans):
                    continue
                self.setFormat(s, l, str_fmt)

        label_spans = self._find_spans(self.label_re, text)
        label_fmt = styles.get("label")
        if label_fmt:
            for s, l in label_spans:
                self.setFormat(s, l, label_fmt)

        var_spans = self._find_spans(self.variable_re, text)
        var_fmt = styles.get("variable")
        if var_fmt:
            for s, l in var_spans:
                if self._inside_any(s, comment_spans) or self._inside_any(s, string_spans):
                    continue
                self.setFormat(s, l, var_fmt)

        blocked_spans = comment_spans + string_spans + label_spans + var_spans
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
