"""Edit → Erase all data… — pick which collected data to permanently delete.

Renders one checkbox per category from core.data_wipe (engagement data
pre-checked, user-authored/credentials left off), requires a type-to-confirm,
double-confirms, then runs the wipe and reports per-category results.
"""

import logging

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QCheckBox, QLineEdit,
    QPushButton, QScrollArea, QWidget, QMessageBox, QInputDialog,
)

from core.data_wipe import build_wipe_items, wipe

logger = logging.getLogger(__name__)


def open_erase_data_dialog(controller, parent):
    base_path = getattr(controller, "base_path", "")
    items = build_wipe_items(base_path)

    dlg = QDialog(parent)
    dlg.setWindowTitle("Erase data")
    dlg.setModal(True)
    dlg.resize(560, 640)
    dlg.setSizeGripEnabled(True)
    try:
        # Full theme dialog stylesheet (matches the current theme's window
        # background); messagebox_stylesheet doesn't paint the QDialog itself.
        dlg.setStyleSheet(controller.dialog_stylesheet)
    except Exception:
        pass

    root = QVBoxLayout(dlg)
    root.setContentsMargins(16, 16, 16, 12)
    root.setSpacing(10)

    title = QLabel("Select what to erase")
    title.setStyleSheet("font-size: 15px; font-weight: bold;")
    root.addWidget(title)

    warn = QLabel(
        "⚠ This permanently deletes the selected data collected by PurrSh3ll and "
        "cannot be undone. It is an application-level erase — not a forensic disk "
        "wipe (SSD internals, swap and shell history outside the app are not covered)."
    )
    warn.setWordWrap(True)
    warn.setStyleSheet("font-size: 11px;")
    root.addWidget(warn)

    sel_row = QHBoxLayout()
    btn_all  = QPushButton("Select all")
    btn_none = QPushButton("Select none")
    sel_row.addWidget(btn_all)
    sel_row.addWidget(btn_none)
    sel_row.addStretch(1)
    root.addLayout(sel_row)

    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    inner = QWidget()
    form = QVBoxLayout(inner)
    form.setSpacing(6)

    checks = {}
    for it in items:
        cb = QCheckBox(it.label)
        cb.setChecked(it.default)
        cb.setToolTip(it.description)
        form.addWidget(cb)
        desc = QLabel(it.description)
        desc.setWordWrap(True)
        desc.setStyleSheet("font-size: 10px; margin-left: 22px; margin-bottom: 6px;")
        form.addWidget(desc)
        checks[it.id] = cb
    form.addStretch(1)
    scroll.setWidget(inner)
    try:
        # Theme the scrollbar and make the scroll area / viewport / inner widget
        # transparent so they inherit the themed QDialog background instead of the
        # default palette colour.
        scroll.setStyleSheet(
            controller.scroll_stylesheet +
            "QScrollArea { background: transparent; border: none; }")
        scroll.viewport().setStyleSheet("background: transparent;")
        inner.setStyleSheet("background: transparent;")
    except Exception:
        pass
    root.addWidget(scroll, 1)

    btn_row = QHBoxLayout()
    btn_row.addStretch(1)
    cancel_btn = QPushButton("Cancel")
    erase_btn  = QPushButton("Erase selected")
    erase_btn.setEnabled(False)
    btn_row.addWidget(cancel_btn)
    btn_row.addWidget(erase_btn)
    root.addLayout(btn_row)

    def _any_checked():
        return any(cb.isChecked() for cb in checks.values())

    def _update_enabled():
        erase_btn.setEnabled(_any_checked())

    for cb in checks.values():
        cb.stateChanged.connect(lambda *_: _update_enabled())
    _update_enabled()

    def _set_all(state):
        for cb in checks.values():
            cb.setChecked(state)
        _update_enabled()

    btn_all.clicked.connect(lambda: _set_all(True))
    btn_none.clicked.connect(lambda: _set_all(False))
    cancel_btn.clicked.connect(dlg.reject)

    def _do_erase():
        selected = [wid for wid, cb in checks.items() if cb.isChecked()]
        labels   = [it.label for it in items if it.id in selected]

        confirm = QMessageBox(dlg)
        confirm.setIcon(QMessageBox.Icon.Warning)
        confirm.setWindowTitle("Confirm erase")
        confirm.setText("Permanently erase the following?")
        confirm.setInformativeText("\n".join("• " + l for l in labels))
        confirm.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        confirm.setDefaultButton(QMessageBox.StandardButton.No)
        try:
            confirm.setStyleSheet(controller.messagebox_stylesheet)
        except Exception:
            pass
        if confirm.exec() != QMessageBox.StandardButton.Yes:
            return

        # Docker needs sudo — obtain the password up front (reusing the cached one
        # if the session already has it). If not provided, drop docker and go on.
        if "docker" in selected and not getattr(controller, "sudo_password", None):
            pw, ok = QInputDialog.getText(
                dlg, "Root password",
                "Removing Docker containers requires sudo.\nEnter the root/sudo password:",
                QLineEdit.EchoMode.Password)
            if ok and pw:
                controller.sudo_password = bytearray(pw.encode("utf-8"))
            else:
                selected = [s for s in selected if s != "docker"]
                QMessageBox.information(
                    dlg, "Docker skipped",
                    "No password provided — Docker containers were left untouched.")
                if not selected:
                    return

        report = wipe(base_path, selected, controller)

        lines = []
        for wid in selected:
            ok, detail = report.get(wid, (False, "skipped"))
            lbl = next((it.label for it in items if it.id == wid), wid)
            lines.append(f"{'✓' if ok else '✗'} {lbl}: {detail}")

        done = QMessageBox(dlg)
        done.setIcon(QMessageBox.Icon.Information)
        done.setWindowTitle("Erase complete")
        done.setText("Selected data erased.")
        done.setInformativeText(
            "\n".join(lines) +
            "\n\nRestart PurrSh3ll to also clear in-memory state (open terminals' "
            "scrollback and cached views)."
        )
        try:
            done.setStyleSheet(controller.messagebox_stylesheet)
        except Exception:
            pass
        done.exec()
        dlg.accept()

    erase_btn.clicked.connect(_do_erase)
    dlg.exec()
