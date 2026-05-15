from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class JsHighlighter(QSyntaxHighlighter):
    TEMPLATE_BLOCK_STATE = 2

    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "keyword": "bold",
            "builtin": "",
            "comment": "italic",
            "string": "",
            "template": "",
            "regex": "",
            "number": "",
            "function": "bold",
            "preprocessor": "bold",
            "class": "bold",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, "#ffffff")
            self.styles[name] = self._format(color, flag)

        keywords = [
            "break", "case", "catch", "class", "const", "continue", "debugger",
            "default", "delete", "do", "else", "export", "extends", "finally",
            "for", "function", "if", "import", "in", "instanceof", "let", "new",
            "return", "super", "switch", "this", "throw", "try", "typeof", "var",
            "void", "while", "with", "yield", "await", "async", "of", "static",
            "get", "set", "constructor"
        ]

        builtins = [
            "console", "Math", "JSON", "Array", "Object", "String", "Number",
            "Boolean", "Promise", "Set", "Map", "WeakMap", "WeakSet",
            "Date", "RegExp", "parseInt", "parseFloat", "isNaN",
            "isFinite", "encodeURI", "decodeURI", "require", "module", "exports"
        ]

        self.rules = []

        self.rules += [(r"\b([A-Za-z_$][\w$]*)\s*(?=\()", "function")]

        self.rules += [(r"\b([A-Za-z_$][\w$]*)\s*(?=\s*=\s*(?:\([^\)]*\)|[A-Za-z_$][\w$]*)\s*=>)", "function")]

        self.rules += [(fr"\b{kw}\b", "keyword") for kw in keywords]

        self.rules += [(r"\bclass\s+([A-Za-z_$][\w$]*)\b", "class")]

        self.rules += [(fr"\b{bi}\b(?!\s*\()", "builtin") for bi in builtins]
        self.rules += [(r"\b(?:console|Math|JSON|Array|Object|Promise)\.[A-Za-z_$][\w$]*\b(?!\s*\()", "builtin")]

        self.rules += [(r"^\s*import\s+.*", "preprocessor")]
        self.rules += [(r"^\s*export\s+.*", "preprocessor")]
        self.rules += [(r"\brequire\s*\(\s*['\"][^'\"]+['\"]\s*\)", "preprocessor")]

        self.rules += [(r'"([^"\\]|\\.)*"', "string")]
        self.rules += [(r"'([^'\\]|\\.)*'", "string")]

        self.rules += [(r'/(?:(?:\\.|[^/\\\n])+)/[gimuy]*', "regex")]

        self.rules += [(r"\b0[bB][01]+\b", "number")]
        self.rules += [(r"\b0[xX][0-9A-Fa-f]+\b", "number")]
        self.rules += [(r"\b[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?\b", "number")]

        self.rules += [(r"/\*\*.*\*/", "comment")]
        self.rules += [(r"//.*", "comment")]

        self.compiled_rules = []
        for pattern, style_name in self.rules:
            try:
                self.compiled_rules.append((QRegularExpression(pattern), style_name))
            except Exception:
                pass

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

    def _is_escaped(self, text: str, pos: int) -> bool:
        i = pos - 1
        count = 0
        while i >= 0 and text[i] == "\\":
            count += 1
            i -= 1
        return (count % 2) == 1

    def highlightBlock(self, text):
        template_fmt = self.styles.get("template")
        template_spans = []

        if self.previousBlockState() == self.TEMPLATE_BLOCK_STATE:
            start_index = 0
        else:
            start_index = -1
            pos = 0
            while True:
                idx = text.find("`", pos)
                if idx == -1:
                    break
                if not self._is_escaped(text, idx):
                    start_index = idx
                    break
                pos = idx + 1

        pos_search = start_index
        while pos_search != -1 and pos_search < len(text):
            end_idx = -1
            pos = pos_search + 1
            while True:
                idx = text.find("`", pos)
                if idx == -1:
                    break
                if not self._is_escaped(text, idx):
                    end_idx = idx
                    break
                pos = idx + 1

            if end_idx != -1:
                length = end_idx - pos_search + 1
                template_spans.append((pos_search, length))
                pos2 = end_idx + 1
                next_idx = -1
                while True:
                    idx2 = text.find("`", pos2)
                    if idx2 == -1:
                        next_idx = -1
                        break
                    if not self._is_escaped(text, idx2):
                        next_idx = idx2
                        break
                    pos2 = idx2 + 1
                pos_search = next_idx
            else:
                length = len(text) - pos_search
                template_spans.append((pos_search, length))
                self.setCurrentBlockState(self.TEMPLATE_BLOCK_STATE)
                pos_search = -1

        if self.currentBlockState() != self.TEMPLATE_BLOCK_STATE:
            self.setCurrentBlockState(0)

        if template_fmt:
            for s, l in template_spans:
                if l > 0:
                    self.setFormat(s, l, template_fmt)

        if self.previousBlockState() != 1:
            match = self.comment_start.match(text)
            comment_start_index = match.capturedStart() if match.hasMatch() else -1
        else:
            comment_start_index = 0

        comment_fmt = self.styles.get("comment")
        while comment_start_index >= 0:
            end_match = self.comment_end.match(text, comment_start_index)
            if end_match.hasMatch():
                end_index = end_match.capturedEnd()
                length = end_index - comment_start_index
                if comment_fmt:
                    self.setFormat(comment_start_index, length, comment_fmt)
                match = self.comment_start.match(text, end_index)
                comment_start_index = match.capturedStart() if match.hasMatch() else -1
                self.setCurrentBlockState(0)
            else:
                if comment_fmt:
                    self.setFormat(comment_start_index, len(text) - comment_start_index, comment_fmt)
                self.setCurrentBlockState(1)
                break

        if self.currentBlockState() != 1 and self.currentBlockState() != self.TEMPLATE_BLOCK_STATE:
            self.setCurrentBlockState(0)

        compiled = getattr(self, "compiled_rules", ())
        styles = self.styles

        def inside_template(start_pos: int) -> bool:
            for s, l in template_spans:
                if start_pos >= s and start_pos < s + l:
                    return True
            return False

        for qre, style_name in compiled:
            it = qre.globalMatch(text)
            while it.hasNext():
                m = it.next()
                try:
                    if m.capturedStart(1) != -1:
                        start = m.capturedStart(1)
                        length = m.capturedLength(1)
                    else:
                        start = m.capturedStart(0)
                        length = m.capturedLength(0)
                except Exception:
                    start = m.capturedStart()
                    length = m.capturedLength()

                if length > 0 and start >= 0:
                    if inside_template(start):
                        continue
                    fmt = styles.get(style_name)
                    if fmt:
                        self.setFormat(start, length, fmt)

        if self.currentBlockState() != self.TEMPLATE_BLOCK_STATE and self.currentBlockState() != 1:
            self.setCurrentBlockState(0)
