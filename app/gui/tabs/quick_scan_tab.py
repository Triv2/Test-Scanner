from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QSpinBox, QTableWidget, 
                            QTableWidgetItem, QProgressBar, QComboBox)
from PyQt6.QtCore import Qt, pyqtSignal, QThread

from ...core.scanner import PortScanner

class ScanWorker(QThread):
    result_ready = pyqtSignal(dict)
    scan_finished = pyqtSignal()
    
    def __init__(self, scanner, host, start_port, end_port):
        super().__init__()
        self.scanner = scanner
        self.host = host
        self.start_port = start_port
        self.end_port = end_port
        
    def run(self):
        def callback(result):
            self.result_ready.emit(result)
            
        self.scanner.scan_range(
            self.host, 
            self.start_port, 
            self.end_port, 
            callback=callback
        )
        self.scan_finished.emit()

class QuickScanTab(QWidget):
    def __init__(self):
        super().__init__()
        self.scanner = PortScanner()
        self.scan_thread = None
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Target input section
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target Host:"))
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Enter hostname or IP (e.g., 192.168.1.1)")
        target_layout.addWidget(self.host_input)
        layout.addLayout(target_layout)
        
        # Port range section
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port Range:"))
        self.start_port = QSpinBox()
        self.start_port.setRange(1, 65535)
        self.start_port.setValue(1)
        port_layout.addWidget(self.start_port)
        
        port_layout.addWidget(QLabel("to"))
        
        self.end_port = QSpinBox()
        self.end_port.setRange(1, 65535)
        self.end_port.setValue(1024)
        port_layout.addWidget(self.end_port)
        
        # Preset dropdown
        port_layout.addWidget(QLabel("Preset:"))
        self.preset_combo = QComboBox()
        self.preset_combo.addItems(["Custom", "Common Ports (1-1024)", "All Ports (1-65535)", "Web Servers (80, 443, 8080)"])
        self.preset_combo.currentIndexChanged.connect(self.preset_changed)
        port_layout.addWidget(self.preset_combo)
        
        layout.addLayout(port_layout)
        
        # Scan button
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        layout.addLayout(button_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # Results table
        self.results_table = QTableWidget(0, 3)
        self.results_table.setHorizontalHeaderLabels(["Port", "Status", "Service"])
        self.results_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.results_table)
        
    def preset_changed(self, index):
        if index == 1:  # Common Ports
            self.start_port.setValue(1)
            self.end_port.setValue(1024)
        elif index == 2:  # All Ports
            self.start_port.setValue(1)
            self.end_port.setValue(65535)
        elif index == 3:  # Web Servers
            self.start_port.setValue(80)
            self.end_port.setValue(8080)
            
    def start_scan(self):
        host = self.host_input.text().strip()
        if not host:
            return
            
        start_port = self.start_port.value()
        end_port = self.end_port.value()
        
        # Clear previous results
        self.results_table.setRowCount(0)
        
        # Update UI
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        
        # Calculate total ports for progress
        self.total_ports = end_port - start_port + 1
        self.scanned_ports = 0
        
        # Start scan in a separate thread
        self.scan_thread = ScanWorker(self.scanner, host, start_port, end_port)
        self.scan_thread.result_ready.connect(self.update_result)
        self.scan_thread.scan_finished.connect(self.scan_complete)
        self.scan_thread.start()
        
    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scanner.stop_scanning()
            self.scan_thread.wait()
            self.scan_complete()
            
    def update_result(self, result):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Add port
        port_item = QTableWidgetItem(str(result["port"]))
        self.results_table.setItem(row, 0, port_item)
        
        # Add status
        status_item = QTableWidgetItem(result["status"])
        if result["status"] == "Open":
            status_item.setForeground(Qt.GlobalColor.green)
        else:
            status_item.setForeground(Qt.GlobalColor.red)
        self.results_table.setItem(row, 1, status_item)
        
        # Add service (would need to be determined elsewhere)
        service_item = QTableWidgetItem("")
        self.results_table.setItem(row, 2, service_item)
        
        # Update progress
        self.scanned_ports += 1
        progress = int((self.scanned_ports / self.total_ports) * 100)
        self.progress_bar.setValue(progress)
        
    def scan_complete(self):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)