from typing import Optional

from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class HtmlHighlighter(QSyntaxHighlighter):

    STATE_NORMAL = 0
    STATE_HTML_COMMENT = 1
    STATE_SCRIPT = 2
    STATE_STYLE = 3

    def __init__(self, document, controller=None):
        super().__init__(document)
        self.controller = controller

        self._style_flags = {
            "tag": "bold",
            "attribute": "",
            "attribute_value": "",
            "comment": "italic",
            "doctype": "bold",
            "entity": "",
            "script": "",
            "style": "",
        }

        q = getattr(self.controller, "qss_QPainter", {}) if self.controller else {}
        defaults = {
            "tag": "#cc99ff",
            "attribute": "#66d9ef",
            "attribute_value": "#a6e22e",
            "comment": "#7f8c8d",
            "doctype": "#ffd700",
            "entity": "#f92672",
            "script": "#f8f8f2",
            "style": "#f8f8f2",
        }
        self.styles = {}
        for name, flag in self._style_flags.items():
            color = q.get(name, defaults.get(name, "#ffffff"))
            self.styles[name] = self._format(color, flag)

        self.tag_re = QRegularExpression(r"</?\s*([A-Za-z0-9\-:]+)")
        self.attribute_re = QRegularExpression(r"\b([A-Za-z_:][-A-Za-z0-9_:.]*)\b")
        self.attribute_value_re = QRegularExpression(r'''(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')''')

        self.comment_start = QRegularExpression(r"<!--")
        self.comment_end = QRegularExpression(r"-->")
        self.doctype_re = QRegularExpression(r"<!DOCTYPE[^>]*>", QRegularExpression.PatternOption.CaseInsensitiveOption)
        self.entity_re = QRegularExpression(r"&[#A-Za-z0-9]+;")
        self.script_open_re = QRegularExpression(r"<script\b[^>]*>", QRegularExpression.PatternOption.CaseInsensitiveOption)
        self.script_close_re = QRegularExpression(r"</script\s*>", QRegularExpression.PatternOption.CaseInsensitiveOption)
        self.style_open_re = QRegularExpression(r"<style\b[^>]*>", QRegularExpression.PatternOption.CaseInsensitiveOption)
        self.style_close_re = QRegularExpression(r"</style\s*>", QRegularExpression.PatternOption.CaseInsensitiveOption)

        self.compiled_rules = [
            (self.doctype_re, "doctype"),
            (self.entity_re, "entity"),
        ]

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
                spans.append((s, l, m))
        return spans

    def _inside_any(self, pos: int, spans: list[tuple[int,int]]):
        for s, l in spans:
            if s <= pos < s + l:
                return True
        return False

    def update_colors(self, mapping: Optional[dict] = None):
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

    def highlightBlock(self, text: str):
        styles = self.styles

        prev = self.previousBlockState()
        start_index = 0

        if prev == self.STATE_HTML_COMMENT:
            end_it = self.comment_end.globalMatch(text)
            if end_it.hasNext():
                m = end_it.next()
                end = m.capturedStart(0) + m.capturedLength(0)
                if styles.get("comment"):
                    self.setFormat(0, end, styles.get("comment"))
                text_rest = text[end:]
                start_index = end
            else:
                if styles.get("comment"):
                    self.setFormat(0, len(text), styles.get("comment"))
                self.setCurrentBlockState(self.STATE_HTML_COMMENT)
                return

        if prev == self.STATE_SCRIPT:
            end_it = self.script_close_re.globalMatch(text)
            if end_it.hasNext():
                m = end_it.next()
                end = m.capturedStart(0) + m.capturedLength(0)
                if styles.get("script"):
                    self.setFormat(0, end, styles.get("script"))
                text = text[end:]
            else:
                if styles.get("script"):
                    self.setFormat(0, len(text), styles.get("script"))
                self.setCurrentBlockState(self.STATE_SCRIPT)
                return

        if prev == self.STATE_STYLE:
            end_it = self.style_close_re.globalMatch(text)
            if end_it.hasNext():
                m = end_it.next()
                end = m.capturedStart(0) + m.capturedLength(0)
                if styles.get("style"):
                    self.setFormat(0, end, styles.get("style"))
                text = text[end:]
            else:
                if styles.get("style"):
                    self.setFormat(0, len(text), styles.get("style"))
                self.setCurrentBlockState(self.STATE_STYLE)
                return

        self.setCurrentBlockState(self.STATE_NORMAL)

        comment_spans = []
        it_cstart = self.comment_start.globalMatch(text)
        while it_cstart.hasNext():
            m = it_cstart.next(); s = m.capturedStart(0)
            end_it = self.comment_end.globalMatch(text[s+4:])
            if end_it.hasNext():
                m2 = end_it.next(); l = m2.capturedStart(0) + m2.capturedLength(0) + 4
                comment_spans.append((s, l))
            else:
                if styles.get("comment"):
                    self.setFormat(s, len(text)-s, styles.get("comment"))
                self.setCurrentBlockState(self.STATE_HTML_COMMENT)
                return

        for s, l in comment_spans:
            if styles.get("comment"):
                self.setFormat(s, l, styles.get("comment"))

        script_spans = []
        it_script = self.script_open_re.globalMatch(text)
        while it_script.hasNext():
            m = it_script.next(); s = m.capturedStart(0); l = m.capturedLength(0)
            close_it = self.script_close_re.globalMatch(text[s+l:])
            if close_it.hasNext():
                m2 = close_it.next(); l2 = m2.capturedStart(0) + m2.capturedLength(0) + l
                script_spans.append((s, l2))
            else:
                if styles.get("script"):
                    self.setFormat(s, len(text)-s, styles.get("script"))
                self.setCurrentBlockState(self.STATE_SCRIPT)
                return

        style_spans = []
        it_style = self.style_open_re.globalMatch(text)
        while it_style.hasNext():
            m = it_style.next(); s = m.capturedStart(0); l = m.capturedLength(0)
            close_it = self.style_close_re.globalMatch(text[s+l:])
            if close_it.hasNext():
                m2 = close_it.next(); l2 = m2.capturedStart(0) + m2.capturedLength(0) + l
                style_spans.append((s, l2))
            else:
                if styles.get("style"):
                    self.setFormat(s, len(text)-s, styles.get("style"))
                self.setCurrentBlockState(self.STATE_STYLE)
                return

        for s, l in script_spans:
            if styles.get("script"):
                self.setFormat(s, l, styles.get("script"))
        for s, l in style_spans:
            if styles.get("style"):
                self.setFormat(s, l, styles.get("style"))

        tag_it = self.tag_re.globalMatch(text)
        used_spans = []
        while tag_it.hasNext():
            m = tag_it.next()
            tag_start = m.capturedStart(0)
            tag_name_len = m.capturedLength(1)
            if styles.get("tag"):
                name_start = m.capturedStart(1)
                self.setFormat(name_start, tag_name_len, styles.get("tag"))
                used_spans.append((name_start, tag_name_len))
            gt_pos = text.find('>', tag_start)
            if gt_pos == -1:
                gt_pos = len(text)
            inner = text[tag_start:gt_pos]
            attr_it = self.attribute_re.globalMatch(inner)
            while attr_it.hasNext():
                ma = attr_it.next()
                an_s = ma.capturedStart(1) + tag_start
                an_l = ma.capturedLength(1)
                if any(an_s >= us and an_s < us+ul for us, ul in used_spans):
                    continue
                if styles.get("attribute"):
                    self.setFormat(an_s, an_l, styles.get("attribute"))
                eq_pos = text.find('=', an_s + an_l)
                if eq_pos != -1 and eq_pos < gt_pos:
                    val_match = QRegularExpression(r'''\s*=\s*(?:"(?:[^"\\\\n]|\\\\.)*"|'(?:[^'\\\\n]|\\\\.)*')''')
                    vm = val_match.match(text, an_s+an_l)
                    if vm.hasMatch():
                        mstart = vm.capturedStart(0)
                        mlen = vm.capturedLength(0)
                        sub = text[mstart:mstart+mlen]
                        quote_idx = sub.find('"')
                        if quote_idx == -1:
                            quote_idx = sub.find("'")
                        if quote_idx != -1:
                            vs = mstart + quote_idx
                            vm2 = self.attribute_value_re.match(text, vs)
                            if vm2.hasMatch():
                                vs2 = vm2.capturedStart(0)
                                vl2 = vm2.capturedLength(0)
                                if styles.get("attribute_value"):
                                    self.setFormat(vs2, vl2, styles.get("attribute_value"))
                                used_spans.append((vs2, vl2))

        for qre, name in self.compiled_rules:
            it = qre.globalMatch(text)
            while it.hasNext():
                m = it.next()
                s = m.capturedStart(0); l = m.capturedLength(0)
                if styles.get(name):
                    self.setFormat(s, l, styles.get(name))

        self.setCurrentBlockState(self.STATE_NORMAL)
