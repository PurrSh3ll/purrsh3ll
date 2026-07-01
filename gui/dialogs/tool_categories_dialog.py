"""
tool_categories_dialog.py — Edit > Tool Categories

Lets the user view, add, edit and remove tool→category mappings stored in
appdata/tool_categories.json.  Not yet wired to the auto-tagger.
"""

import json
import logging
import os

logger = logging.getLogger(__name__)

from PyQt6.QtCore import Qt, QSortFilterProxyModel, QStringListModel
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QListWidget, QListWidgetItem, QLineEdit, QComboBox,
    QDialogButtonBox, QCheckBox, QScrollArea, QWidget,
    QFrame, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView,
)


class ToolCategoriesDialog(QDialog):
    """
    Two-panel dialog:
      Left  — category filter list
      Right — tools belonging to the selected category

    Bottom bar: Add Tool, Edit (selected), Remove (selected), Close.
    All changes are saved to tool_categories.json immediately on OK/close.
    """

    def __init__(self, base_path: str, parent=None):
        super().__init__(parent)
        self.base_path = base_path
        self._json_path = os.path.join(base_path, "appdata", "tool_categories.json")
        self._default_path = os.path.join(base_path, "appdata", "tool_categories_default.json")
        self._data = self._load()

        self.setWindowTitle("Tool Categories")
        self.setMinimumSize(780, 540)
        self.setModal(False)

        self._build_ui()
        self._populate_categories()
        self._cat_list.setCurrentRow(0)   # select "All"

    # ── persistence ────────────────────────────────────────────────────────

    def _load(self) -> dict:
        try:
            with open(self._json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"categories": {}, "tools": {}}

    def _save(self) -> None:
        try:
            with open(self._json_path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
        except Exception:
            logger.warning("failed to persist tool categories", exc_info=True)

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # ── search bar ────────────────────────────────────────────────────
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search:"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("filter tools…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._refresh_tools)
        search_row.addWidget(self._search)
        root.addLayout(search_row)

        # ── two-panel row: categories | tools ────────────────────────────
        panels = QHBoxLayout()
        panels.setSpacing(8)

        # left — categories
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)
        left_layout.addWidget(QLabel("Category"))
        self._cat_list = QListWidget()
        self._cat_list.setFixedWidth(190)
        self._cat_list.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._cat_list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._cat_list.currentRowChanged.connect(self._refresh_tools)
        left_layout.addWidget(self._cat_list)
        panels.addLayout(left_layout)

        # right — tools table
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(4)
        self._tools_header = QLabel("Tools")
        right_layout.addWidget(self._tools_header)

        self._tool_table = QTableWidget(0, 2)
        self._tool_table.setHorizontalHeaderLabels(["Tool", "Categories"])
        self._tool_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._tool_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._tool_table.verticalHeader().setVisible(False)
        self._tool_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._tool_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._tool_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tool_table.setShowGrid(False)
        self._tool_table.setAlternatingRowColors(True)
        self._tool_table.doubleClicked.connect(self._on_edit)
        right_layout.addWidget(self._tool_table)
        panels.addLayout(right_layout, stretch=1)

        root.addLayout(panels, stretch=1)

        # ── count label ───────────────────────────────────────────────────
        # ── action buttons ────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_add     = QPushButton("+ Add Tool")
        btn_edit    = QPushButton("Edit")
        btn_remove  = QPushButton("− Remove")
        btn_reset   = QPushButton("Reset to Defaults")
        btn_close   = QPushButton("Close")

        btn_add.clicked.connect(self._on_add)
        btn_edit.clicked.connect(self._on_edit)
        btn_remove.clicked.connect(self._on_remove)
        btn_reset.clicked.connect(self._on_reset)
        btn_close.clicked.connect(self.accept)

        btn_row.addWidget(btn_add)
        btn_row.addWidget(btn_edit)
        btn_row.addWidget(btn_remove)
        btn_row.addStretch()
        btn_row.addWidget(btn_reset)
        btn_row.addWidget(btn_close)
        root.addLayout(btn_row)

    # ── populate ───────────────────────────────────────────────────────────

    def _populate_categories(self):
        self._cat_list.clear()
        cats = self._data.get("categories", {})

        total = len(self._data.get("tools", {}))
        all_item = QListWidgetItem(f"All  ({total})")
        all_item.setData(Qt.ItemDataRole.UserRole, None)
        self._cat_list.addItem(all_item)

        for key, label in cats.items():
            count = sum(1 for tags in self._data["tools"].values() if key in tags)
            item = QListWidgetItem(f"{label}  ({count})")
            item.setData(Qt.ItemDataRole.UserRole, key)
            self._cat_list.addItem(item)

        self._fit_cat_list_height()

    def _fit_cat_list_height(self):
        n = self._cat_list.count()
        if n == 0:
            return
        row_h = self._cat_list.sizeHintForRow(0)
        frame = self._cat_list.frameWidth() * 2
        self._cat_list.setMinimumHeight(n * row_h + frame)

    def _refresh_tools(self):
        cat_item = self._cat_list.currentItem()
        selected_cat = cat_item.data(Qt.ItemDataRole.UserRole) if cat_item else None
        query = self._search.text().strip().lower()

        tools = self._data.get("tools", {})
        cats  = self._data.get("categories", {})

        self._tool_table.setRowCount(0)
        for tool_name in sorted(tools.keys()):
            tags = tools[tool_name]
            if selected_cat and selected_cat not in tags:
                continue
            if query and query not in tool_name.lower():
                continue
            labels = [cats.get(t, t) for t in tags]
            row = self._tool_table.rowCount()
            self._tool_table.insertRow(row)
            name_item = QTableWidgetItem(tool_name)
            name_item.setData(Qt.ItemDataRole.UserRole, tool_name)
            cats_item = QTableWidgetItem(", ".join(labels))
            cats_item.setData(Qt.ItemDataRole.UserRole, tool_name)
            self._tool_table.setItem(row, 0, name_item)
            self._tool_table.setItem(row, 1, cats_item)

        cat_label = cats.get(selected_cat, "All") if selected_cat else "All"
        self._tools_header.setText(f"Tools — {cat_label}")

    # ── actions ────────────────────────────────────────────────────────────

    def _on_reset(self):
        try:
            with open(self._default_path, "r", encoding="utf-8") as f:
                import json as _json
                default_data = _json.load(f)
        except Exception:
            QMessageBox.critical(self, "Reset Failed", "Default file not found or unreadable.")
            return
        msg = QMessageBox(self)
        msg.setWindowTitle("Reset to Defaults")
        msg.setText("This will restore all tool categories to the built-in defaults.\nAll custom changes will be lost. Continue?")
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        msg.setDefaultButton(QMessageBox.StandardButton.Cancel)
        try:
            msg.setStyleSheet(self.styleSheet())
        except Exception:
            pass
        if msg.exec() != QMessageBox.StandardButton.Yes:
            return
        self._data = default_data
        self._save()
        self._populate_categories()
        self._cat_list.setCurrentRow(0)
        self._refresh_tools()

    def _on_add(self):
        dlg = _ToolEditDialog(
            base_path=self.base_path,
            categories=self._data.get("categories", {}),
            tool_name="",
            current_tags=[],
            existing_tools=set(self._data.get("tools", {}).keys()),
            parent=self,
        )
        try:
            dlg.setStyleSheet(self.styleSheet())
        except Exception:
            pass
        if dlg.exec() == QDialog.DialogCode.Accepted:
            name, tags = dlg.result_name, dlg.result_tags
            if name:
                self._data["tools"][name] = tags
                self._save()
                self._populate_categories()
                self._refresh_tools()

    def _on_edit(self):
        tool_name = self._selected_tool()
        if not tool_name:
            return
        dlg = _ToolEditDialog(
            base_path=self.base_path,
            categories=self._data.get("categories", {}),
            tool_name=tool_name,
            current_tags=list(self._data["tools"].get(tool_name, [])),
            existing_tools=set(self._data.get("tools", {}).keys()),
            parent=self,
        )
        try:
            dlg.setStyleSheet(self.styleSheet())
        except Exception:
            pass
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._data["tools"][tool_name] = dlg.result_tags
            self._save()
            self._populate_categories()
            self._refresh_tools()

    def _on_remove(self):
        rows = self._tool_table.selectionModel().selectedRows()
        if not rows:
            return
        names = [self._tool_table.item(r.row(), 0).data(Qt.ItemDataRole.UserRole)
                 for r in rows]
        msg = QMessageBox(self)
        msg.setWindowTitle("Remove tools")
        msg.setText(f"Remove {len(names)} tool(s)?\n\n" + "\n".join(names))
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        msg.setDefaultButton(QMessageBox.StandardButton.Cancel)
        try:
            msg.setStyleSheet(self.styleSheet())
        except Exception:
            pass
        if msg.exec() != QMessageBox.StandardButton.Yes:
            return
        for name in names:
            self._data["tools"].pop(name, None)
        self._save()
        self._populate_categories()
        self._refresh_tools()

    def _selected_tool(self) -> str:
        row = self._tool_table.currentRow()
        if row < 0:
            return ""
        item = self._tool_table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else ""


# ---------------------------------------------------------------------------
# Sub-dialog: add / edit a single tool
# ---------------------------------------------------------------------------

class _ToolEditDialog(QDialog):
    """
    Compact dialog for adding or editing a tool entry.

    Fields:
      - Tool name (QLineEdit, read-only when editing)
      - Category checkboxes (one per category)
    """

    def __init__(self, base_path, categories: dict, tool_name: str,
                 current_tags: list, existing_tools: set, parent=None):
        super().__init__(parent)
        self._categories   = categories
        self._existing     = existing_tools
        self._editing      = bool(tool_name)
        self.result_name   = tool_name
        self.result_tags   = list(current_tags)

        self.setWindowTitle("Edit Tool" if self._editing else "Add Tool")
        self.setMinimumWidth(340)
        self.setModal(True)

        self._build_ui(tool_name, current_tags)

    def _build_ui(self, tool_name: str, current_tags: list):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # tool name
        layout.addWidget(QLabel("Tool name:"))
        self._name_edit = QLineEdit(tool_name)
        if self._editing:
            self._name_edit.setReadOnly(True)
            self._name_edit.setStyleSheet("color: #888;")
        self._name_edit.setPlaceholderText("e.g.  nmap")
        layout.addWidget(self._name_edit)

        # categories
        layout.addWidget(QLabel("Categories:"))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setMinimumHeight(220)
        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setSpacing(4)
        inner_layout.setContentsMargins(2, 2, 2, 2)

        self._checkboxes: dict[str, QCheckBox] = {}
        for key, label in self._categories.items():
            cb = QCheckBox(f"{label}  [{key}]")
            cb.setChecked(key in current_tags)
            self._checkboxes[key] = cb
            inner_layout.addWidget(cb)

        inner_layout.addStretch()
        scroll.setWidget(inner)
        layout.addWidget(scroll)

        # error label
        self._error = QLabel("")
        self._error.setStyleSheet("color: #cc4444; font-size: 11px;")
        layout.addWidget(self._error)

        # buttons
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._on_ok)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def _on_ok(self):
        name = self._name_edit.text().strip()
        if not name:
            self._error.setText("Tool name cannot be empty.")
            return
        if not self._editing and name in self._existing:
            self._error.setText(f"'{name}' already exists.")
            return
        tags = [k for k, cb in self._checkboxes.items() if cb.isChecked()]
        if not tags:
            self._error.setText("Select at least one category.")
            return
        self.result_name = name
        self.result_tags = tags
        self.accept()
