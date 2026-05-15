from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class CsHighlighter(QSyntaxHighlighter):
    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "keyword": "bold",
            "type": "bold",
            "builtin": "",
            "comment": "italic",
            "string": "",
            "char": "",
            "number": "",
            "function": "bold",
            "preprocessor": "bold",
            "class": "bold",
            "namespace": "bold",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, "#ffffff")
            self.styles[name] = self._format(color, flag)

        keywords = [
            "abstract", "as", "base", "break", "case", "catch", "checked", "class",
            "const", "continue", "default", "delegate", "do", "else", "enum",
            "event", "explicit", "extern", "false", "finally", "fixed", "for",
            "foreach", "goto", "if", "implicit", "in", "interface", "internal",
            "is", "lock", "new", "null", "operator", "out", "override", "params",
            "private", "protected", "public", "readonly", "ref", "return",
            "sealed", "sizeof", "stackalloc", "static", "struct", "switch",
            "this", "throw", "true", "try", "typeof", "unchecked", "unsafe",
            "using", "virtual", "volatile", "void", "while", "yield",
            "async", "await", "var", "dynamic", "get", "set", "add", "remove"
        ]

        types = [
            "int", "short", "long", "float", "double", "decimal", "char", "bool",
            "string", "object", "byte", "sbyte", "ushort", "uint", "ulong",
            "nint", "nuint", "void", "Int32", "Int64", "UInt32", "UInt64", "decimal"
        ]

        builtins = [
            "Console", "Math", "String", "Convert", "Environment", "GC", "DateTime",
            "List", "Dictionary", "Task", "Thread", "Console.WriteLine",
            "Console.ReadLine", "Console.Write", "Enumerable", "Regex"
        ]

        self.rules = []

        self.rules += [(r"\b([A-Za-z_]\w*)\s*(?=\()", "function")]

        self.rules += [(fr"\b{kw}\b", "keyword") for kw in keywords]
        self.rules += [(fr"\b{t}\b", "type") for t in types]

        self.rules += [(r"\b(class|interface|struct|enum)\s+([A-Za-z_]\w*)\b", "class")]
        self.rules += [(r"\b([A-Z][A-Za-z0-9_]+)\b", "class")]

        self.rules += [(r"\bnamespace\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\b", "namespace")]

        self.rules += [(fr"\b{bi}\b(?!\s*\()", "builtin") for bi in builtins]
        self.rules += [(r"\b(?:System|Microsoft|Console|DateTime|Task)\.[A-Za-z_]\w*\b(?!\s*\()", "builtin")]

        self.rules += [(r"^\s*#\s*\w+.*", "preprocessor")]

        self.rules += [(r"\[[A-Za-z_]\w*(?:\([^]]*\))?\]", "preprocessor")]

        self.rules += [(r'@"([^"]|"")*"', "string")]
        self.rules += [(r'\$@"([^"]|"")*"', "string")]
        self.rules += [(r'\$"([^"\\]|\\.)*"', "string")]
        self.rules += [(r'"([^"\\]|\\.)*"', "string")]
        self.rules += [(r"'([^'\\]|\\.)*'", "char")]

        self.rules += [(r"\b0[bB][01]+[uUlL]*\b", "number")]
        self.rules += [(r"\b0[xX][0-9A-Fa-f]+[uUlL]*\b", "number")]
        self.rules += [(r"\b[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?[mMfFdDuUlL]*\b", "number")]

        self.rules += [(r"///.*", "comment")]
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

    def highlightBlock(self, text):
        start_index = 0
        if self.previousBlockState() != 1:
            match = self.comment_start.match(text)
            start_index = match.capturedStart() if match.hasMatch() else -1
        else:
            start_index = 0

        comment_fmt = self.styles.get("comment")
        while start_index >= 0:
            end_match = self.comment_end.match(text, start_index)
            if end_match.hasMatch():
                end_index = end_match.capturedEnd()
                length = end_index - start_index
                if comment_fmt:
                    self.setFormat(start_index, length, comment_fmt)
                match = self.comment_start.match(text, end_index)
                start_index = match.capturedStart() if match.hasMatch() else -1
                self.setCurrentBlockState(0)
            else:
                if comment_fmt:
                    self.setFormat(start_index, len(text) - start_index, comment_fmt)
                self.setCurrentBlockState(1)
                break

        if self.currentBlockState() != 1:
            self.setCurrentBlockState(0)

        compiled = getattr(self, "compiled_rules", ())
        styles = self.styles

        for qre, style_name in compiled:
            it = qre.globalMatch(text)
            while it.hasNext():
                m = it.next()
                start = -1
                length = 0
                try:
                    if m.capturedStart(2) != -1:
                        start = m.capturedStart(2)
                        length = m.capturedLength(2)
                    elif m.capturedStart(1) != -1:
                        start = m.capturedStart(1)
                        length = m.capturedLength(1)
                    else:
                        start = m.capturedStart(0)
                        length = m.capturedLength(0)
                except Exception:
                    start = m.capturedStart()
                    length = m.capturedLength()

                if length > 0 and start >= 0:
                    fmt = styles.get(style_name)
                    if fmt:
                        self.setFormat(start, length, fmt)

        if self.currentBlockState() != 1:
            self.setCurrentBlockState(0)
