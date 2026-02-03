import csv
import time

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QFileDialog,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QPlainTextEdit,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from scanner import ScannerThread


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Port Scanner")
        self.resize(980, 700)

        self.thread = None
        self.scan_started_at = None
        self.scan_was_stopped = False
        self.open_ports_count = 0

        self.elapsed_timer = QTimer(self)
        self.elapsed_timer.setInterval(1000)
        self.elapsed_timer.timeout.connect(self.update_elapsed_time)

        self.status_anim_timer = QTimer(self)
        self.status_anim_timer.setInterval(450)
        self.status_anim_timer.timeout.connect(self.animate_scanning_status)
        self._scan_dots = 0
        self._status_mode = "Ready"

        self.build_ui()
        self.apply_hacker_theme()
        self.update_status("Ready")
        self.update_inline_status("Ready to scan")

    def build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 14)
        root.setSpacing(12)

        root.addWidget(self.build_header())
        root.addWidget(self.build_target_section())
        root.addWidget(self.build_ports_section())
        root.addWidget(self.build_progress_section())
        root.addWidget(self.build_results_section(), 1)
        root.addWidget(self.build_scan_log_section())

        self.footer = QLabel("Ethical use: scan only systems you own or have permission to test.")
        self.footer.setObjectName("footer")
        root.addWidget(self.footer)

    def build_header(self):
        header = QFrame()
        header.setObjectName("headerCard")

        layout = QVBoxLayout(header)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)

        title = QLabel("Port Scanner")
        title.setObjectName("appTitle")

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("statusReady")

        layout.addWidget(title)
        layout.addWidget(self.status_label)
        return header

    def build_target_section(self):
        card = QFrame()
        card.setObjectName("sectionCard")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        title = QLabel("Target")
        title.setObjectName("sectionTitle")

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(8)

        icon_label = QLabel("TARGET")
        icon_label.setObjectName("fieldTag")

        self.target = QLineEdit()
        self.target.setPlaceholderText("Enter IP or domain (e.g. 127.0.0.1, scanme.nmap.org)")
        self.target.textChanged.connect(self.on_target_changed)

        self.inline_status = QLabel("")
        self.inline_status.setObjectName("inlineNeutral")

        grid.addWidget(icon_label, 0, 0)
        grid.addWidget(self.target, 0, 1)
        grid.addWidget(self.inline_status, 1, 1)
        grid.setColumnStretch(1, 1)

        layout.addWidget(title)
        layout.addLayout(grid)
        return card

    def build_ports_section(self):
        card = QFrame()
        card.setObjectName("sectionCard")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        title = QLabel("Ports")
        title.setObjectName("sectionTitle")

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(8)

        self.start_port = QSpinBox()
        self.start_port.setRange(1, 65535)
        self.start_port.setValue(1)

        self.end_port = QSpinBox()
        self.end_port.setRange(1, 65535)
        self.end_port.setValue(1024)

        self.port_preset = QComboBox()
        self.port_preset.addItems(
            [
                "Custom",
                "Common (1-1024)",
                "Top 100 (1-100)",
                "Full (1-65535)",
            ]
        )
        self.port_preset.currentTextChanged.connect(self.apply_port_preset)

        grid.addWidget(QLabel("Start Port"), 0, 0)
        grid.addWidget(self.start_port, 0, 1)
        grid.addWidget(QLabel("End Port"), 0, 2)
        grid.addWidget(self.end_port, 0, 3)
        grid.addWidget(QLabel("Preset"), 1, 0)
        grid.addWidget(self.port_preset, 1, 1, 1, 3)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        buttons = QHBoxLayout()
        buttons.setSpacing(10)

        self.btn_scan = QPushButton("Scan")
        self.btn_scan.setObjectName("btnScan")

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setObjectName("btnStop")
        self.btn_stop.setEnabled(False)

        self.btn_clear = QPushButton("Clear")
        self.btn_clear.setObjectName("btnSecondary")

        self.btn_export = QPushButton("Export CSV")
        self.btn_export.setObjectName("btnSecondary")

        buttons.addWidget(self.btn_scan)
        buttons.addWidget(self.btn_stop)
        buttons.addStretch(1)
        buttons.addWidget(self.btn_clear)
        buttons.addWidget(self.btn_export)

        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_clear.clicked.connect(self.clear_table)
        self.btn_export.clicked.connect(self.export_csv)

        layout.addWidget(title)
        layout.addLayout(grid)
        layout.addLayout(buttons)
        return card

    def build_progress_section(self):
        card = QFrame()
        card.setObjectName("sectionCard")

        layout = QHBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(10)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)

        self.progress_percent = QLabel("0%")
        self.progress_percent.setObjectName("metricPill")

        self.elapsed_label = QLabel("Elapsed: 00:00")
        self.elapsed_label.setObjectName("metricPill")

        self.open_ports_label = QLabel("Open ports found: 0")
        self.open_ports_label.setObjectName("metricPill")

        layout.addWidget(self.progress, 1)
        layout.addWidget(self.progress_percent)
        layout.addWidget(self.elapsed_label)
        layout.addWidget(self.open_ports_label)
        return card

    def build_results_section(self):
        card = QFrame()
        card.setObjectName("sectionCard")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        top_row = QHBoxLayout()
        title = QLabel("Results")
        title.setObjectName("sectionTitle")

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Filter by port, service, or status...")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.textChanged.connect(self.filter_table)

        top_row.addWidget(title)
        top_row.addStretch(1)
        top_row.addWidget(self.search_box)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Port", "Status", "Service"])
        self.table.setEditTriggers(self.table.NoEditTriggers)
        self.table.setSelectionBehavior(self.table.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setMouseTracking(True)
        self.table.verticalHeader().setVisible(False)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

        layout.addLayout(top_row)
        layout.addWidget(self.table)
        return card

    def build_scan_log_section(self):
        card = QFrame()
        card.setObjectName("sectionCard")

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel("Scan Log")
        title.setObjectName("sectionTitle")

        self.log_toggle = QToolButton()
        self.log_toggle.setObjectName("logToggle")
        self.log_toggle.setText("Hide Log")
        self.log_toggle.setCheckable(True)
        self.log_toggle.setChecked(True)
        self.log_toggle.clicked.connect(self.toggle_scan_log)

        header.addWidget(title)
        header.addStretch(1)
        header.addWidget(self.log_toggle)

        self.scan_log = QPlainTextEdit()
        self.scan_log.setReadOnly(True)
        self.scan_log.setObjectName("scanLog")
        self.scan_log.setMinimumHeight(130)
        self.scan_log.setMaximumBlockCount(400)

        layout.addLayout(header)
        layout.addWidget(self.scan_log)
        return card

    def apply_hacker_theme(self):
        self.setStyleSheet(
            """
            QWidget {
                background-color: #0b0f0e;
                color: #c8d2cd;
                font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace;
                font-size: 13px;
            }
            #headerCard, #sectionCard {
                background-color: #111716;
                border: 1px solid #293330;
                border-radius: 10px;
            }
            #appTitle {
                color: #00ff88;
                font-size: 24px;
                font-weight: 700;
            }
            #appSubtitle {
                color: #7f8c87;
                font-size: 12px;
            }
            #statusReady {
                color: #00ff88;
                font-size: 12px;
                font-weight: 700;
            }
            #statusScanning {
                color: #00ff88;
                font-size: 12px;
                font-weight: 700;
            }
            #statusStopped {
                color: #8a9490;
                font-size: 12px;
                font-weight: 700;
            }
            #sectionTitle {
                color: #e5efe9;
                font-size: 14px;
                font-weight: 700;
            }
            #fieldTag {
                color: #00ff88;
                background-color: #0f1916;
                border: 1px solid #274138;
                border-radius: 8px;
                padding: 7px 10px;
                font-size: 11px;
                font-weight: 700;
            }
            QLabel {
                color: #a8b3ae;
            }
            #inlineNeutral {
                color: #7f8c87;
                font-size: 12px;
            }
            #inlineError {
                color: #ff5f5f;
                font-size: 12px;
                font-weight: 700;
            }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #0e1312;
                color: #d7e0db;
                border: 1px solid #2a3431;
                border-radius: 8px;
                min-height: 34px;
                padding: 0 10px;
                selection-background-color: #00cc6e;
            }
            QLineEdit::placeholder {
                color: #5f6b66;
            }
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                border: 1px solid #00ff88;
            }
            QComboBox::drop-down {
                border: 0;
                width: 20px;
            }
            QPushButton {
                min-height: 34px;
                border-radius: 8px;
                border: 1px solid #33403b;
                padding: 0 14px;
                font-weight: 700;
            }
            QPushButton#btnScan {
                background-color: #00d977;
                color: #04120b;
                border-color: #00ff88;
            }
            QPushButton#btnScan:hover {
                background-color: #00ff88;
                border-color: #67ffb7;
            }
            QPushButton#btnStop {
                background-color: #2a1417;
                color: #ff7676;
                border-color: #7f3434;
            }
            QPushButton#btnStop:hover {
                background-color: #3a191d;
                border-color: #c74b4b;
            }
            QPushButton#btnSecondary {
                background-color: #121a18;
                color: #9fd8bf;
                border-color: #2c5b48;
            }
            QPushButton#btnSecondary:hover {
                background-color: #16211e;
                border-color: #00ff88;
                color: #cbffe5;
            }
            QPushButton:disabled {
                background-color: #121716;
                color: #5e6964;
                border-color: #25302c;
            }
            QToolButton#logToggle {
                background-color: #121a18;
                color: #9fd8bf;
                border: 1px solid #2c5b48;
                border-radius: 8px;
                padding: 5px 12px;
                font-weight: 700;
            }
            QToolButton#logToggle:hover {
                border-color: #00ff88;
                color: #cbffe5;
            }
            QProgressBar {
                background-color: #0f1413;
                border: 1px solid #2a3431;
                border-radius: 8px;
                min-height: 18px;
            }
            QProgressBar::chunk {
                background-color: #00ff88;
                border-radius: 7px;
            }
            #metricPill {
                background-color: #0f1413;
                border: 1px solid #293330;
                border-radius: 8px;
                color: #b2c0ba;
                padding: 5px 9px;
                font-size: 12px;
            }
            QTableWidget {
                background-color: #0f1413;
                alternate-background-color: #121917;
                border: 1px solid #27312e;
                border-radius: 8px;
                gridline-color: transparent;
            }
            QHeaderView::section {
                background-color: #111a17;
                color: #d4e2dc;
                border: 0;
                border-bottom: 2px solid #00ff88;
                padding: 8px;
                font-weight: 700;
            }
            QTableWidget::item {
                color: #ccd5d1;
                padding: 6px;
                border-bottom: 1px solid #18201d;
            }
            QTableWidget::item:hover {
                background-color: #163126;
            }
            QTableWidget::item:selected {
                background-color: #1a3a2b;
                color: #ecfff6;
            }
            #scanLog {
                background-color: #090d0c;
                color: #00ff88;
                border: 1px solid #2a3431;
                border-radius: 8px;
                padding: 8px;
                font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace;
                selection-background-color: #1b3d2e;
            }
            #footer {
                color: #68736f;
                font-size: 12px;
            }
            """
        )

    def set_running_ui(self, running):
        self.btn_scan.setEnabled(not running)
        self.btn_stop.setEnabled(running)
        self.target.setEnabled(not running)
        self.start_port.setEnabled(not running)
        self.end_port.setEnabled(not running)
        self.port_preset.setEnabled(not running)

    def update_status(self, mode):
        self._status_mode = mode
        self.status_anim_timer.stop()

        if mode == "Scanning":
            self.status_label.setObjectName("statusScanning")
            self._scan_dots = 0
            self.animate_scanning_status()
            self.status_anim_timer.start()
        elif mode == "Stopped":
            self.status_label.setObjectName("statusStopped")
            self.status_label.setText("Stopped")
        else:
            self.status_label.setObjectName("statusReady")
            self.status_label.setText("Ready")

        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def animate_scanning_status(self):
        if self._status_mode != "Scanning":
            return
        self.status_label.setText("Scanning" + "." * self._scan_dots)
        self._scan_dots = (self._scan_dots + 1) % 4

    def update_inline_status(self, text, error=False):
        self.inline_status.setText(text)
        self.inline_status.setObjectName("inlineError" if error else "inlineNeutral")
        self.inline_status.style().unpolish(self.inline_status)
        self.inline_status.style().polish(self.inline_status)

    def on_target_changed(self):
        if self.target.text().strip():
            self.update_inline_status("Target looks valid.")
        else:
            self.update_inline_status("Ready to scan")

    def apply_port_preset(self, preset_text):
        if preset_text == "Common (1-1024)":
            self.start_port.setValue(1)
            self.end_port.setValue(1024)
        elif preset_text == "Top 100 (1-100)":
            self.start_port.setValue(1)
            self.end_port.setValue(100)
        elif preset_text == "Full (1-65535)":
            self.start_port.setValue(1)
            self.end_port.setValue(65535)

    def start_scan(self):
        target = self.target.text().strip()
        start_port = int(self.start_port.value())
        end_port = int(self.end_port.value())

        if not target:
            self.update_inline_status("Please enter a target.", error=True)
            QMessageBox.warning(self, "Validation Error", "Please enter a target (IP or domain).")
            return

        if start_port > end_port:
            self.update_inline_status("Start Port cannot be greater than End Port.", error=True)
            QMessageBox.warning(self, "Validation Error", "Start Port cannot be greater than End Port.")
            return

        self.set_running_ui(True)
        self.update_status("Scanning")
        self.update_inline_status("Scanning target...")

        self.progress.setValue(0)
        self.progress_percent.setText("0%")
        self.open_ports_count = 0
        self.open_ports_label.setText("Open ports found: 0")

        self.scan_was_stopped = False
        self.scan_started_at = time.time()
        self.elapsed_label.setText("Elapsed: 00:00")
        self.elapsed_timer.start()

        self.thread = ScannerThread(target, start_port, end_port, timeout=0.5)
        self.thread.found.connect(self.add_row)
        self.thread.scanning.connect(self.on_scanning_port)
        self.thread.progress.connect(self.on_progress_update)
        self.thread.error.connect(self.show_error)
        self.thread.finished.connect(self.scan_finished)
        self.thread.start()
        self.append_log("Scan started")

    def stop_scan(self):
        if self.thread:
            self.scan_was_stopped = True
            self.thread.stop()
            self.update_status("Stopped")
            self.update_inline_status("Stopping scan...")
            self.append_log("Stop requested")

    def on_progress_update(self, value):
        self.progress.setValue(value)
        self.progress_percent.setText(f"{value}%")

    def update_elapsed_time(self):
        if not self.scan_started_at:
            self.elapsed_label.setText("Elapsed: 00:00")
            return

        elapsed = int(max(0, time.time() - self.scan_started_at))
        minutes, seconds = divmod(elapsed, 60)
        self.elapsed_label.setText(f"Elapsed: {minutes:02d}:{seconds:02d}")

    def scan_finished(self):
        self.elapsed_timer.stop()
        self.update_elapsed_time()
        self.set_running_ui(False)
        self.thread = None

        if self.scan_was_stopped:
            self.update_status("Stopped")
            self.update_inline_status("Scan stopped by user.")
            self.append_log("Scan stopped")
        else:
            self.update_status("Ready")
            self.update_inline_status("Scan completed.")
            self.append_log("Scan completed")

    def show_error(self, message):
        self.update_inline_status("Scan failed. Check target and try again.", error=True)
        self.append_log(f"ERROR {message}")
        QMessageBox.critical(self, "Error", message)

    def on_scanning_port(self, port):
        self.append_log(f"Scanning port {port}")

    def add_row(self, port, status, service):
        row = self.table.rowCount()
        self.table.insertRow(row)

        port_item = QTableWidgetItem(str(port))
        status_item = QTableWidgetItem(status)
        service_item = QTableWidgetItem(service)

        for item in (port_item, status_item, service_item):
            item.setTextAlignment(Qt.AlignCenter)

        status_upper = status.upper().strip()
        if status_upper == "OPEN":
            status_item.setForeground(QColor("#00ff88"))
            self.open_ports_count += 1
            self.open_ports_label.setText(f"Open ports found: {self.open_ports_count}")
            service_display = f" ({service})" if service else ""
            self.append_log(f"OPEN {port}{service_display}")
        elif status_upper == "CLOSED":
            status_item.setForeground(QColor("#7a8681"))

        self.table.setItem(row, 0, port_item)
        self.table.setItem(row, 1, status_item)
        self.table.setItem(row, 2, service_item)

        self.filter_table(self.search_box.text())

    def filter_table(self, query):
        text = query.strip().lower()
        for row in range(self.table.rowCount()):
            row_text = " ".join(
                self.table.item(row, col).text().lower() if self.table.item(row, col) else ""
                for col in range(self.table.columnCount())
            )
            self.table.setRowHidden(row, text not in row_text)

    def clear_table(self):
        self.table.setRowCount(0)
        self.progress.setValue(0)
        self.progress_percent.setText("0%")
        self.open_ports_count = 0
        self.open_ports_label.setText("Open ports found: 0")
        self.search_box.clear()

    def toggle_scan_log(self):
        visible = self.log_toggle.isChecked()
        self.scan_log.setVisible(visible)
        self.log_toggle.setText("Hide Log" if visible else "Show Log")

    def append_log(self, message):
        stamp = time.strftime("%H:%M:%S")
        self.scan_log.appendPlainText(f"[{stamp}] {message}")

    def export_csv(self):
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "Info", "Table is empty. Run a scan first.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save CSV",
            "scan_results.csv",
            "CSV Files (*.csv)",
        )
        if not path:
            return

        with open(path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["Port", "Status", "Service"])
            for row in range(self.table.rowCount()):
                port_item = self.table.item(row, 0)
                status_item = self.table.item(row, 1)
                service_item = self.table.item(row, 2)
                if not port_item or not status_item or not service_item:
                    continue
                writer.writerow([port_item.text(), status_item.text(), service_item.text()])

        QMessageBox.information(self, "Success", "CSV exported successfully.")
