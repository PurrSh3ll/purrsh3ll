from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class VbHighlighter(QSyntaxHighlighter):
    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "keyword": "bold",
            "type": "bold",
            "builtin": "",
            "comment": "italic",
            "xmlcomment": "italic",
            "string": "",
            "number": "",
            "function": "bold",
            "preprocessor": "bold",
            "class": "bold",
            "namespace": "bold",
            "attribute": "italic",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, "#ffffff")
            self.styles[name] = self._format(color, flag)

        keywords = [
            "AddHandler", "AddressOf", "Alias", "And", "AndAlso", "As", "Boolean",
            "ByRef", "ByVal", "Call", "Case", "Catch", "Const", "Continue", "Do",
            "Each", "Else", "ElseIf", "End", "Enum", "Exit", "Finally", "For",
            "Friend", "Function", "If", "Implements", "Imports", "In", "Inherits",
            "Interface", "Is", "Let", "Module", "New", "Next", "Not", "Nothing",
            "Option", "Or", "Private", "Property", "Protected", "Public", "Return",
            "Select", "Set", "Shared", "Static", "Sub", "Then", "Try", "While",
        ]
        types = [
            "Integer", "Long", "Short", "Single", "Double", "Decimal", "Boolean",
            "String", "Object", "Byte", "SByte", "UInteger", "ULong", "UShort",
            "Date", "Task", "List", "Dictionary"
        ]
        builtins = [
            "Console", "Math", "String", "DateTime", "TimeSpan", "Environment",
            "GC", "Task", "Enumerable", "Regex", "File", "Directory", "Debug",
        ]

        self.rules = []
        self.rules += [(r"\b(Sub|Function|Property)\s+([A-Za-z_]\w*)\b", "function")]
        self.rules += [(r"\b(Class|Module|Structure|Interface|Enum)\s+([A-Za-z_]\w*)\b", "class")]
        self.rules += [(r"\bNamespace\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\b", "namespace")]
        self.rules += [(r"\b([A-Za-z_]\w*)\s*(?=\()", "function")]
        self.rules += [(fr"\b{kw}\b", "keyword") for kw in keywords]
        self.rules += [(fr"\b{t}\b", "type") for t in types]

        attr_name = r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
        self.rules += [(fr"(?<=<)\s*({attr_name})\b(?=\s*(?:\(|,|>))", "attribute")]
        self.rules += [(fr"(?<=,)\s*({attr_name})\b(?=\s*(?:\(|,|>))", "attribute")]

        self.rules += [(r"^\s*Imports\s+[\w\.]+", "preprocessor")]
        self.rules += [(r"^\s*Global\s+Imports\s+[\w\.]+", "preprocessor")]
        self.rules += [(r"^\s*#\w+.*", "preprocessor")]

        self.rules += [(r"\b&[hH][0-9A-Fa-f]+\b", "number")]
        self.rules += [(r"\b&[bB][01]+\b", "number")]
        self.rules += [(r"\b[0-9]+(\.[0-9]+)?\b", "number")]

        self.rules += [(fr"\b{bi}\b(?!\s*\()", "builtin") for bi in builtins]
        self.rules += [(r"\b(?:System|Microsoft|Console|Environment)\.[A-Za-z_]\w*\b(?!\s*\()", "builtin")]

        self.compiled_rules = []
        for pattern, style_name in self.rules:
            try:
                self.compiled_rules.append((QRegularExpression(pattern), style_name))
            except Exception:
                pass

        self.string_regex = QRegularExpression(r'"(?:[^"\n]|"")*"')

        self.xmlcomment_re = QRegularExpression(r"^\s*'''[^\n]*")
        self.comment_re = QRegularExpression(r"^\s*'[^\n]*")

        self.xml_tag_re = QRegularExpression(r"<\s*/?\s*([A-Za-z_][A-Za-z0-9_-]*)")

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

    def _inside_any(self, pos: int, spans: list[tuple[int, int]]) -> bool:
        for s, l in spans:
            if pos >= s and pos < s + l:
                return True
        return False

    def highlightBlock(self, text):
        styles = self.styles

        string_spans = self._find_spans(self.string_regex, text)
        string_fmt = styles.get("string")
        if string_fmt:
            for s, l in string_spans:
                self.setFormat(s, l, string_fmt)

        xml_spans = self._find_spans(self.xmlcomment_re, text)
        xml_fmt = styles.get("xmlcomment") or styles.get("comment")
        if xml_fmt:
            for s, l in xml_spans:
                if not self._inside_any(s, string_spans):
                    self.setFormat(s, l, xml_fmt)
                    it_tags = self.xml_tag_re.globalMatch(text)
                    while it_tags.hasNext():
                        mtag = it_tags.next()
                        tag_start = mtag.capturedStart(1)
                        tag_len = mtag.capturedLength(1)
                        if tag_len > 0 and not self._inside_any(tag_start, string_spans):
                            if tag_start >= s and tag_start < s + l:
                                tag_fmt = styles.get("attribute")
                                if tag_fmt:
                                    self.setFormat(tag_start, tag_len, tag_fmt)

        comment_spans = []
        raw_comment_spans = self._find_spans(self.comment_re, text)
        for s, l in raw_comment_spans:
            is_xml = any(s >= xs and s < xs + xl for xs, xl in xml_spans)
            if not is_xml and not self._inside_any(s, string_spans):
                comment_spans.append((s, l))
                comment_fmt = styles.get("comment")
                if comment_fmt:
                    self.setFormat(s, l, comment_fmt)

        blocked_spans = list(string_spans) + list(xml_spans) + list(comment_spans)

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

        self.setCurrentBlockState(0)
