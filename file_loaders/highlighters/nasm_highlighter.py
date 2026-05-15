import re
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class NasmHighlighter(QSyntaxHighlighter):

    def __init__(self, document, controller):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "label": "bold",
            "directive": "bold",
            "instruction": "bold",
            "register": "",
            "number": "",
            "comment": "italic",
            "string": "",
            "symbol": "",
        }

        q = getattr(self.controller, "qss_QPainter", {})
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, "#ffffff")
            self.styles[name] = self._format(color, flag)

        directives = [
            "section", "global", "extern", "bits", "org", "equ", "times",
            "resb", "resw", "resd", "resq", "db", "dw", "dd", "dq",
            "align", "ptr", "struc", "endstruc", "istruc", "at", "incbin"
        ]

        mnemonics = [
            "mov", "movzx", "movsx", "lea", "push", "pop", "add", "sub",
            "imul", "mul", "div", "idiv", "inc", "dec", "and", "or", "xor",
            "not", "neg", "cmp", "test", "jmp", "je", "jne", "jg", "jl",
            "jge", "jle", "ja", "jb", "call", "ret", "syscall", "int", "nop",
            "loop", "loope", "loopne", "rep", "repe", "repne", "stosb",
            "movs", "movsb", "movsd", "movsq", "movsw", "scasb", "scasw",
            "in", "out", "pushf", "popf", "cbw", "cwde", "cdq", "cqo"
        ]

        registers = [
            "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
            "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
            "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8",
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
            "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
            "cr0", "cr2", "cr3", "cr4", "dr0", "dr1", "dr2", "dr3"
        ]

        def escaped_alt(words):
            esc = [re.escape(w) for w in words]
            esc.sort(key=len, reverse=True)
            return "|".join(esc)

        self.rules = []
        self.rules += [(r"^\s*([A-Za-z_][\w\.\$\@]*)\s*:", "label")]

        if directives:
            dirs_pat = rf"(?i)\b(?:{escaped_alt(directives)})\b"
            self.rules += [(dirs_pat, "directive")]

        if mnemonics:
            instr_pat = rf"(?i)\b(?:{escaped_alt(mnemonics)})\b"
            self.rules += [(instr_pat, "instruction")]

        if registers:
            regs_pat = rf"(?i)\b(?:{escaped_alt(registers)})\b"
            self.rules += [(regs_pat, "register")]

        self.rules += [(r"\b0b[01]+(?:'[bB])?\b", "number")]
        self.rules += [(r"\b0x[0-9A-Fa-f]+\b", "number")]
        self.rules += [(r"\b[0-9A-Fa-f]+h\b", "number")]
        self.rules += [(r"\b[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b", "number")]

        combined_known = []
        if directives:
            combined_known.append(escaped_alt(directives))
        if mnemonics:
            combined_known.append(escaped_alt(mnemonics))
        if registers:
            combined_known.append(escaped_alt(registers))
        if combined_known:
            joined_known = "|".join(combined_known)
            symbol_pat = rf"\b(?! (?i:(?:{joined_known}))\b)([A-Za-z_][\w\.\$\@]*)\b"
            symbol_pat = symbol_pat.replace(" ", "")
            self.rules += [(symbol_pat, "symbol")]
        else:
            self.rules += [(r"\b[A-Za-z_][\w\.\$\@]*\b", "symbol")]

        self.compiled_rules = []
        for pattern, style_name in self.rules:
            try:
                qre = QRegularExpression(pattern)
                if qre.isValid():
                    self.compiled_rules.append((qre, style_name))
            except Exception:
                pass

        self.string_re = QRegularExpression(r'"(?:[^"\\\n]|\\.)*"')
        self.string_single_re = QRegularExpression(r"'(?:[^'\\\n]|\\.)*'")
        self.comment_re = QRegularExpression(r";.*")

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

        blocked_spans = list(comment_spans) + list(string_spans)

        label_fmt = styles.get("label")
        label_spans = []
        if label_fmt:
            for qre, name in getattr(self, "compiled_rules", ()):
                if name == "label":
                    it = qre.globalMatch(text)
                    while it.hasNext():
                        m = it.next()
                        if m.capturedStart(1) != -1:
                            s = m.capturedStart(1); l = m.capturedLength(1)
                        else:
                            s = m.capturedStart(0); l = m.capturedLength(0)
                        if s >= 0 and l > 0:
                            if not self._inside_any(s, blocked_spans):
                                self.setFormat(s, l, label_fmt)
                                label_spans.append((s, l))
                    break
        blocked_spans += label_spans

        for qre, style_name in getattr(self, "compiled_rules", ()):
            if style_name == "label":
                continue
            it = qre.globalMatch(text)
            while it.hasNext():
                m = it.next()
                start = -1; length = 0
                try:
                    if m.capturedStart(1) != -1:
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
