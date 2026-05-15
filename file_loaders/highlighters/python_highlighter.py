from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class PythonHighlighter(QSyntaxHighlighter):
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
        }

        q = getattr(self.controller, "qss_QPainter", {})
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, "#ffffff")
            self.styles[name] = self._format(color, flag)

        keywords = [
            "and", "as", "assert", "break", "class", "continue", "def", "del",
            "elif", "else", "except", "False", "finally", "for", "from", "global",
            "if", "import", "in", "is", "lambda", "None", "nonlocal", "not", "or",
            "pass", "raise", "return", "True", "try", "while", "with", "yield"
        ]
        builtins = [
            "abs", "all", "any", "ascii", "bin", "bool", "bytearray", "bytes",
            "callable", "chr", "classmethod", "compile", "complex", "delattr",
            "dict", "dir", "divmod", "enumerate", "eval", "exec", "filter", "float",
            "format", "frozenset", "getattr", "globals", "hasattr", "hash", "help",
            "hex", "id", "input", "int", "isinstance", "issubclass", "iter", "len",
            "list", "locals", "map", "max", "memoryview", "min", "next", "object",
            "oct", "open", "ord", "pow", "print", "property", "range", "repr",
            "reversed", "round", "set", "slice", "sorted", "staticmethod", "str",
            "sum", "super", "tuple", "type", "vars", "zip", "__import__"
        ]

        self.rules = []
        self.rules += [(fr"\b{kw}\b", "keyword") for kw in keywords]
        self.rules += [(fr"\b{bi}\b", "builtin") for bi in builtins]
        self.rules += [(r'"[^"\\]*(\\.[^"\\]*)*"', "string")]
        self.rules += [(r"'[^'\\]*(\\.[^'\\]*)*'", "string")]
        self.rules += [(r"\b[0-9]+(\.[0-9]+)?\b", "number")]
        self.rules += [(r"#.*", "comment")]
        self.rules += [(r"\bdef\b\s+(\w+)", "function")]

        self.compiled_rules = []
        for pattern, style_name in self.rules:
            self.compiled_rules.append((QRegularExpression(pattern), style_name))

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
        compiled = getattr(self, "compiled_rules", ())
        styles = self.styles

        for qre, style_name in compiled:
            it = qre.globalMatch(text)
            while it.hasNext():
                m = it.next()
                start = m.capturedStart()
                length = m.capturedLength()
                if length > 0:
                    fmt = styles.get(style_name)
                    if fmt:
                        self.setFormat(start, length, fmt)

        self.setCurrentBlockState(0)
