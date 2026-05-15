import re
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class ShellHighlighter(QSyntaxHighlighter):

    def __init__(self, document, controller, file_name = None):
        super().__init__(document)
        self.controller = controller

        self.file_name = file_name or getattr(controller, "file_name", None) or getattr(controller, "file_path", None)

        self._style_flags = {
            "shebang": "bold",
            "keyword": "bold",
            "builtin": "",
            "function": "bold",
            "comment": "italic",
            "string": "",
            "variable": "",
            "number": "",
            "command": "",
            "heredoc": "italic",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        defaults = {
            "shebang": "#ffcc66",
            "keyword": "#cc99ff",
            "builtin": "#66d9ef",
            "function": "#ffd700",
            "comment": "#7f8c8d",
            "string": "#a6e22e",
            "variable": "#f8f8f2",
            "number": "#ae81ff",
            "command": "#f92672",
            "heredoc": "#bfbfbf",
        }
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, defaults.get(name, "#ffffff"))
            self.styles[name] = self._format(color, flag)

        keywords = [
            "if", "then", "else", "elif", "fi", "for", "in", "do", "done",
            "while", "until", "case", "esac", "function", "select", "break",
            "continue", "return", "exit", "local", "declare", "typeset",
            "set", "unset", "readonly", "repeat", "if", "elif", "else",
            "time", "coproc"
        ]

        builtins = [
            "cd", "echo", "printf", "read", "export", "unset", "eval", "exec",
            "test", "trap", "source", ".", "pwd", "shift", "getopts",
            "autoload", "emulate", "setopt", "unsetopt", "whence", "hash",
            "bindkey", "fc", "functions",
            "shopt", "let", "mapfile", "readarray", "alias", "unalias",
            "complete", "compgen", "compopt", "builtin", "enable", "help",
        ]

        def escaped_alt(words):
            esc = [re.escape(w) for w in words]
            esc.sort(key=len, reverse=True)
            return "|".join(esc)

        self.rules = []
        self.rules.append((r"#.*", "comment"))

        self.rules.append((r"'(?:[^'\\\n]|\\.)*'", "string"))
        self.rules.append((r'"(?:[^"\\\n]|\\.)*"', "string"))

        self.rules.append((r"\$\{[^}]+\}", "variable"))
        self.rules.append((r"\$[A-Za-z_][A-Za-z0-9_]*", "variable"))
        self.rules.append((r"\$\d+", "variable"))

        self.rules.append((r"\b\d+\b", "number"))

        self.rules.append((r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{", "function"))
        self.rules.append((r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\b", "function"))

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

        self.string_re = QRegularExpression(r"'(?:[^'\\\n]|\\.)*'")
        self.string_double_re = QRegularExpression(r'"(?:[^"\\\n]|\\.)*"')
        self.comment_re = QRegularExpression(r"#.*")
        self.command_sub_re = QRegularExpression(r"\$\([^()]*\)")
        self.backtick_re = QRegularExpression(r"`[^`]*`")
        self.arith_re = QRegularExpression(r"\$\(\([^)]*\)\)")
        self.proc_sub_re = QRegularExpression(r"[<>]\([^()]*\)")
        self.herestring_re = QRegularExpression(r"<<<[^\n]*")
        self.heredoc_start_re = QRegularExpression(r"<<[-]?\s*(['\"]?)([A-Za-z0-9_\-]+)\1")
        self.double_bracket_re = QRegularExpression(r"\[\[[^\]]*\]\]")

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

        shebang_fmt = styles.get("shebang")
        shebang_spans = []
        shebang_re = QRegularExpression(r"^\s*#!.*")
        it = shebang_re.globalMatch(text)
        while it.hasNext():
            m = it.next()
            s = m.capturedStart(0); l = m.capturedLength(0)
            if s >= 0 and l > 0:
                if shebang_fmt:
                    self.setFormat(s, l, shebang_fmt)
                shebang_spans.append((s, l))

        comment_spans = self._find_spans(self.comment_re, text)
        comment_fmt = styles.get("comment")
        if comment_fmt:
            for s, l in comment_spans:
                if self._inside_any(s, shebang_spans):
                    continue
                self.setFormat(s, l, comment_fmt)

        string_spans = []
        string_spans += self._find_spans(self.string_re, text)
        string_spans += self._find_spans(self.string_double_re, text)
        str_fmt = styles.get("string")
        if str_fmt:
            for s, l in string_spans:
                if self._inside_any(s, shebang_spans) or self._inside_any(s, comment_spans):
                    continue
                self.setFormat(s, l, str_fmt)

        heredoc_spans = self._find_spans(self.heredoc_start_re, text)
        heredoc_fmt = styles.get("heredoc")
        if heredoc_fmt:
            for s, l in heredoc_spans:
                if self._inside_any(s, shebang_spans) or self._inside_any(s, comment_spans) or self._inside_any(s, string_spans):
                    continue
                self.setFormat(s, l, heredoc_fmt)

        herestring_spans = self._find_spans(self.herestring_re, text)
        if heredoc_fmt:
            for s, l in herestring_spans:
                if self._inside_any(s, shebang_spans) or self._inside_any(s, comment_spans) or self._inside_any(s, string_spans):
                    continue
                self.setFormat(s, l, heredoc_fmt)

        cmd_spans = []
        cmd_spans += self._find_spans(self.command_sub_re, text)
        cmd_spans += self._find_spans(self.backtick_re, text)
        cmd_spans += self._find_spans(self.arith_re, text)
        cmd_spans += self._find_spans(self.proc_sub_re, text)
        cmd_fmt = styles.get("command")
        if cmd_fmt:
            for s, l in cmd_spans:
                if self._inside_any(s, shebang_spans) or self._inside_any(s, comment_spans) or self._inside_any(s, string_spans):
                    continue
                self.setFormat(s, l, cmd_fmt)

        blocked_spans = list(shebang_spans) + list(comment_spans) + list(string_spans) + list(cmd_spans) + list(heredoc_spans) + list(herestring_spans)

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
