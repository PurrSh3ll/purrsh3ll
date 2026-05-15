import re
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class PowerShellHighlighter(QSyntaxHighlighter):
    STATE_NORMAL = 0
    STATE_BLOCK_COMMENT = 1
    STATE_HEREDOC_DOUBLE = 2
    STATE_HEREDOC_SINGLE = 3

    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "comment": "italic",
            "block_comment": "italic",
            "string": "",
            "heredoc": "",
            "variable": "",
            "number": "",
            "keyword": "bold",
            "builtin": "",
            "command": "",
            "type": "italic",
        }
        q = getattr(self.controller, "qss_QPainter", {})
        defaults = {
            "comment": "#7f8c8d",
            "block_comment": "#7f8c8d",
            "string": "#a6e22e",
            "heredoc": "#bfbfbf",
            "variable": "#f8f8f2",
            "number": "#ae81ff",
            "keyword": "#cc99ff",
            "builtin": "#66d9ef",
            "command": "#f92672",
            "type": "#99ccff",
        }
        self.styles = {name: self._format(q.get(name, defaults[name]), flag)
                       for name, flag in self._style_flags.items()}

        keywords = ["if", "else", "elseif", "switch", "for", "foreach", "while",
                    "do", "break", "continue", "return", "function", "param",
                    "try", "catch", "finally", "throw", "trap", "in", "begin", "process", "end"]
        builtins = ["Get-ChildItem", "Get-Content", "Set-Content", "Write-Host", "Write-Output", "Get-Date"]
        types = ["int", "string", "bool", "object", "hashtable", "datetime"]

        def escaped_alt(ws):
            esc = [re.escape(w) for w in ws]
            esc.sort(key=len, reverse=True)
            return "|".join(esc)

        self.rules = []
        self.rules.append((r"#.*", "comment"))
        self.rules.append((r"'(?:[^'\\\n]|\\.)*'", "string"))
        self.rules.append((r'"(?:[^"\\\n]|\\.)*"', "string"))
        self.rules.append((r"\$\([^()]*\)", "command"))
        if builtins:
            self.rules.append((rf"\b(?:{escaped_alt(builtins)})\b", "builtin"))
        if keywords:
            self.rules.append((rf"\b(?:{escaped_alt(keywords)})\b", "keyword"))
        if types:
            self.rules.append((rf"\[\s*(?:{escaped_alt(types)})\s*\]", "type"))
        self.rules.append((r"\b\d+(?:\.\d+)?\b", "number"))

        self.compiled_rules = []
        for pat, name in self.rules:
            try:
                qre = QRegularExpression(pat)
                if qre.isValid():
                    self.compiled_rules.append((qre, name))
            except Exception:
                pass

        self.block_comment_start = QRegularExpression(r"<#")
        self.block_comment_end = QRegularExpression(r"#>")
        self.heredoc_double_start = QRegularExpression(r'@"')
        self.heredoc_double_end = QRegularExpression(r'"@')
        self.heredoc_single_start = QRegularExpression(r"@'")
        self.heredoc_single_end = QRegularExpression(r"'@")
        self.line_comment_re = QRegularExpression(r"#.*")
        self.string_single_re = QRegularExpression(r"'(?:[^'\\\n]|\\.)*'")
        self.string_double_re = QRegularExpression(r'"(?:[^"\\\n]|\\.)*"')
        self.variable_re = QRegularExpression(r"(?<![\w\$])\$(?:\{[^}]+\}|[A-Za-z_][A-Za-z0-9_:\.\[\]]*)")

    def _format(self, color, style=""):
        fmt = QTextCharFormat()
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

    def _inside_any(self, pos: int, spans: list[tuple[int,int]]):
        for s, l in spans:
            if s <= pos < s + l:
                return True
        return False

    def highlightBlock(self, text: str):
        styles = self.styles

        prev_state = self.previousBlockState()
        if prev_state == self.STATE_BLOCK_COMMENT:
            end_it = self.block_comment_end.globalMatch(text)
            if end_it.hasNext():
                m = end_it.next()
                end = m.capturedStart(0) + m.capturedLength(0)
                self.setFormat(0, end, styles["block_comment"])
                text = text[end:]
            else:
                self.setFormat(0, len(text), styles["block_comment"])
                self.setCurrentBlockState(self.STATE_BLOCK_COMMENT)
                return

        if prev_state in (self.STATE_HEREDOC_DOUBLE, self.STATE_HEREDOC_SINGLE):
            end_qre = self.heredoc_double_end if prev_state == self.STATE_HEREDOC_DOUBLE else self.heredoc_single_end
            end_it = end_qre.globalMatch(text)
            if end_it.hasNext():
                m = end_it.next()
                end = m.capturedStart(0) + m.capturedLength(0)
                self.setFormat(0, end, styles["heredoc"])
                text = text[end:]
            else:
                self.setFormat(0, len(text), styles["heredoc"])
                self.setCurrentBlockState(prev_state)
                return

        self.setCurrentBlockState(self.STATE_NORMAL)

        bc_spans = []
        it_start = self.block_comment_start.globalMatch(text)
        while it_start.hasNext():
            m = it_start.next()
            s = m.capturedStart(0)
            end_it = self.block_comment_end.globalMatch(text[s+2:])
            if end_it.hasNext():
                m2 = end_it.next()
                l = m2.capturedStart(0) + m2.capturedLength(0) + 2
                bc_spans.append((s, l))
            else:
                self.setFormat(s, len(text)-s, styles["block_comment"])
                self.setCurrentBlockState(self.STATE_BLOCK_COMMENT)
                return

        heredoc_spans = []
        it_hd = self.heredoc_double_start.globalMatch(text)
        while it_hd.hasNext():
            m = it_hd.next(); s = m.capturedStart(0)
            end_it = self.heredoc_double_end.globalMatch(text[s+2:])
            if end_it.hasNext():
                m2 = end_it.next(); l = m2.capturedStart(0) + m2.capturedLength(0) + 2
                heredoc_spans.append((s, l))
            else:
                self.setFormat(s, len(text)-s, styles["heredoc"])
                self.setCurrentBlockState(self.STATE_HEREDOC_DOUBLE)
                return
        it_hd2 = self.heredoc_single_start.globalMatch(text)
        while it_hd2.hasNext():
            m = it_hd2.next(); s = m.capturedStart(0)
            end_it = self.heredoc_single_end.globalMatch(text[s+2:])
            if end_it.hasNext():
                m2 = end_it.next(); l = m2.capturedStart(0) + m2.capturedLength(0) + 2
                heredoc_spans.append((s, l))
            else:
                self.setFormat(s, len(text)-s, styles["heredoc"])
                self.setCurrentBlockState(self.STATE_HEREDOC_SINGLE)
                return

        comment_spans = self._find_spans(self.line_comment_re, text)
        for s, l in comment_spans:
            if self._inside_any(s, bc_spans):
                continue
            self.setFormat(s, l, styles["comment"])

        string_spans = []
        string_spans += self._find_spans(self.string_single_re, text)
        string_spans += self._find_spans(self.string_double_re, text)
        for s, l in string_spans:
            if self._inside_any(s, bc_spans):
                continue
            if self._inside_any(s, comment_spans):
                continue
            self.setFormat(s, l, styles["string"])

        var_spans = self._find_spans(self.variable_re, text)
        for s, l in var_spans:
            if (self._inside_any(s, bc_spans) or self._inside_any(s, comment_spans)
                    or self._inside_any(s, string_spans) or self._inside_any(s, heredoc_spans)):
                continue
            self.setFormat(s, l, styles["variable"])

        cmd_spans = self._find_spans(QRegularExpression(r"\$\([^()]*\)"), text)
        for s, l in cmd_spans:
            if (self._inside_any(s, bc_spans) or self._inside_any(s, comment_spans)
                    or self._inside_any(s, string_spans) or self._inside_any(s, heredoc_spans)):
                continue
            self.setFormat(s, l, styles["command"])

        blocked = bc_spans + comment_spans + string_spans + var_spans + cmd_spans + heredoc_spans

        for qre, style_name in self.compiled_rules:
            if style_name in ("comment", "string"):
                continue
            it = qre.globalMatch(text)
            while it.hasNext():
                m = it.next()
                start = m.capturedStart(1) if (m.capturedLength(1) > 0) else m.capturedStart(0)
                length = m.capturedLength(1) if (m.capturedLength(1) > 0) else m.capturedLength(0)
                if length <= 0 or start < 0:
                    continue
                if self._inside_any(start, blocked):
                    continue
                fmt = styles.get(style_name)
                if fmt:
                    self.setFormat(start, length, fmt)

        self.setCurrentBlockState(self.STATE_NORMAL)

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
