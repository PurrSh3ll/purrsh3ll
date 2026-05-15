from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class PhpHighlighter(QSyntaxHighlighter):
    HEREDOC_STATE = 1
    BLOCK_COMMENT_STATE = 2

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
            "class": "bold",
            "variable": "",
            "preprocessor": "bold",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, "#ffffff")
            self.styles[name] = self._format(color, flag)

        keywords = [
            "abstract", "and", "array", "as", "break", "callable", "case", "catch",
            "class", "clone", "const", "continue", "declare", "default", "die", "do",
            "echo", "else", "elseif", "enddeclare", "endfor", "endforeach", "endif",
            "endswitch", "endwhile", "eval", "exit", "extends", "final", "for",
            "foreach", "function", "global", "goto", "if", "implements", "include",
            "include_once", "instanceof", "insteadof", "interface", "isset", "list",
            "namespace", "new", "or", "print", "require", "require_once", "return",
            "static", "switch", "throw", "trait", "try", "unset", "use", "var",
            "while", "xor", "yield", "void", "int", "float", "string", "bool", "true", "false", "null"
        ]

        builtins = [
            "print", "echo", "array", "count", "isset", "empty", "in_array",
            "preg_match", "preg_replace", "substr", "str_replace", "strlen",
            "json_encode", "json_decode", "var_dump", "explode", "implode"
        ]

        self.rules = []

        self.rules += [(r"<\?(?:php|=)?\b", "preprocessor")]
        self.rules += [(r"\?>", "preprocessor")]

        self.rules += [(r"\bfunction\s+&?\s*([A-Za-z_]\w*)\b", "function")]
        self.rules += [(r"\b(class|interface|trait)\s+([A-Za-z_]\w*)\b", "class")]

        self.rules += [(r"\bnamespace\b", "keyword")]
        self.rules += [(r"\buse\b", "keyword")]

        self.rules += [(r"(\$[A-Za-z_\x80-\xff][\w\x80-\xff]*)", "variable")]
        self.rules += [(r"\b(?:self|static|parent)::[A-Za-z_]\w*\b", "variable")]

        self.rules += [(r"(?<=->)[A-Za-z_]\w*", "variable")]
        self.rules += [(r"(?<=::)[A-Za-z_]\w*", "variable")]

        self.rules += [(r"\b([A-Za-z_]\w*)\s*(?=\()", "function")]

        self.rules += [(fr"\b{kw}\b", "keyword") for kw in keywords]
        self.rules += [(fr"\b{bi}\b(?!\s*\()", "builtin") for bi in builtins]

        self.rules += [(r"\b0x[0-9A-Fa-f]+\b", "number")]
        self.rules += [(r"\b[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b", "number")]

        self.compiled_rules = []
        for pattern, style_name in self.rules:
            try:
                self.compiled_rules.append((QRegularExpression(pattern), style_name))
            except Exception:
                pass

        self.double_string_re = QRegularExpression(r'"(?:[^"\\\n]|\\.)*"')
        self.single_string_re = QRegularExpression(r"'(?:[^'\\\n]|\\.)*'")

        self.heredoc_start_re = QRegularExpression(r'<<\s*(?P<q>\'|")?(?P<id>[A-Za-z_]\w*)(?P=q)?')
        self.comment_start_re = QRegularExpression(r"/\*")
        self.comment_end_re = QRegularExpression(r"\*/")
        self.line_comment_re = QRegularExpression(r"(//|#).*")

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

    def highlightBlock(self, text):
        styles = self.styles

        if self.previousBlockState() == self.BLOCK_COMMENT_STATE:
            end_match = self.comment_end_re.match(text)
            if end_match.hasMatch():
                end_pos = end_match.capturedEnd()
                fmt = styles.get("comment")
                if fmt:
                    self.setFormat(0, end_pos, fmt)
                text = text[end_pos:]
                self.setCurrentBlockState(0)
            else:
                fmt = styles.get("comment")
                if fmt:
                    self.setFormat(0, len(text), fmt)
                self.setCurrentBlockState(self.BLOCK_COMMENT_STATE)
                return

        heredoc_spans = []
        it_heredoc = self.heredoc_start_re.globalMatch(text)
        while it_heredoc.hasNext():
            m = it_heredoc.next()
            s = m.capturedStart(0)
            l = m.capturedLength(0)
            if s >= 0 and l > 0:
                heredoc_spans.append((s, l))

        string_spans = []
        string_spans += self._find_spans(self.double_string_re, text)
        string_spans += self._find_spans(self.single_string_re, text)
        str_fmt = styles.get("string")
        if str_fmt:
            for s, l in heredoc_spans + string_spans:
                self.setFormat(s, l, str_fmt)

        comment_spans = []
        i = 0
        L = len(text)
        while i < L:
            if text.startswith("/*", i):
                end_idx = text.find("*/", i+2)
                if end_idx != -1:
                    span_len = end_idx + 2 - i
                    comment_spans.append((i, span_len))
                    i = end_idx + 2
                    continue
                else:
                    comment_spans.append((i, len(text) - i))
                    self.setCurrentBlockState(self.BLOCK_COMMENT_STATE)
                    break
            i += 1

        comment_spans += self._find_spans(self.line_comment_re, text)

        com_fmt = styles.get("comment")
        if com_fmt:
            for s, l in comment_spans:
                if not self._inside_any(s, string_spans):
                    self.setFormat(s, l, com_fmt)

        blocked_spans = list(string_spans) + list(comment_spans) + list(heredoc_spans)

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

        if self.currentBlockState() not in (self.BLOCK_COMMENT_STATE, self.HEREDOC_STATE):
            self.setCurrentBlockState(0)
