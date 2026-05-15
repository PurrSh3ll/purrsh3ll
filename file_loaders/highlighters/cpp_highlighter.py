from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class CppHighlighter(QSyntaxHighlighter):
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
            "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor",
            "bool", "break", "case", "catch", "char", "char16_t", "char32_t", "class",
            "compl", "const", "const_cast", "continue", "decltype", "default", "delete",
            "do", "double", "dynamic_cast", "else", "enum", "explicit", "export",
            "extern", "false", "float", "for", "friend", "goto", "if", "inline", "int",
            "long", "mutable", "namespace", "new", "noexcept", "not", "not_eq", "nullptr",
            "operator", "or", "or_eq", "private", "protected", "public", "register",
            "reinterpret_cast", "return", "short", "signed", "sizeof", "static",
            "static_assert", "static_cast", "struct", "switch", "template", "this",
            "thread_local", "throw", "true", "try", "typedef", "typeid", "typename",
            "union", "unsigned", "using", "virtual", "void", "volatile", "wchar_t",
            "while", "xor", "xor_eq", "constexpr", "override", "final"
        ]

        types = [
            "int", "short", "long", "float", "double", "char", "bool", "void",
            "signed", "unsigned", "size_t", "ptrdiff_t", "intptr_t", "uintptr_t",
            "std::string", "std::wstring", "std::u16string", "std::u32string"
        ]

        builtins = [
            "printf", "scanf", "sprintf", "snprintf", "fprintf",
            "std::printf", "std::scanf", "std::sprintf", "std::snprintf",
            "std::printf", "std::cout", "std::cin", "std::cerr",
            "std::move", "std::forward", "std::make_unique", "std::make_shared",
            "std::vector", "std::map", "std::unordered_map", "std::set",
            "std::unique_ptr", "std::shared_ptr", "std::string", "std::to_string"
        ]

        self.rules = []

        self.rules += [(r"\b([A-Za-z_]\w*)\s*(?=\()", "function")]

        self.rules += [(fr"\b{kw}\b", "keyword") for kw in keywords]
        self.rules += [(fr"\b{t}\b", "type") for t in types]

        self.rules += [(r"\bclass\s+([A-Za-z_]\w*)\b", "class")]
        self.rules += [(r"\bstruct\s+([A-Za-z_]\w*)\b", "class")]
        self.rules += [(r"\benum\s+([A-Za-z_]\w*)\b", "class")]
        self.rules += [(r"\b([A-Z][A-Za-z_0-9]+)\b", "class")]

        self.rules += [(r"\bnamespace\b", "namespace")]

        self.rules += [(fr"\b{bi}\b(?!\s*\()", "builtin") for bi in builtins]
        self.rules += [(r"\bstd::[A-Za-z_]\w*\b(?!\s*\()", "builtin")]

        self.rules += [(r"^\s*#\s*include\s*<[^>]+>", "preprocessor")]
        self.rules += [(r"^\s*#\s*include\s*\"[^\"]+\"", "preprocessor")]
        self.rules += [(r"^\s*#.*", "preprocessor")]

        self.rules += [(r'R"([^\s\\()]*)\((.*?)\)\1"', "string")]
        self.rules += [(r'"([^"\\]|\\.)*"', "string")]
        self.rules += [(r"'([^'\\]|\\.)*'", "char")]

        self.rules += [(r"\b0[bB][01]+[uUlL]*\b", "number")]
        self.rules += [(r"\b0[xX][0-9A-Fa-f]+[uUlL]*\b", "number")]
        self.rules += [(r"\b[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?[uUlLfF]*\b", "number")]

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
            end_match = self.comment_end.match(text, start_index + (0 if self.previousBlockState() == 1 else 0))
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
                    fmt = styles.get(style_name)
                    if fmt:
                        self.setFormat(start, length, fmt)

        if self.currentBlockState() != 1:
            self.setCurrentBlockState(0)
