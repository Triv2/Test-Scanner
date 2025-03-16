from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QComboBox,
                            QCheckBox, QGroupBox, QFormLayout, QRadioButton)
from PyQt6.QtCore import Qt, pyqtSignal, QThread

from ...core.scanner import PortScanner

class AdvancedScanWorker(QThread):
    result_ready = pyqtSignal(dict)
    scan_finished = pyqtSignal()
    
    def __init__(self, scanner, host, ports, scan_type):
        super().__init__()
        self.scanner = scanner
        self.host = host
        self.ports = ports
        self.scan_type = scan_type
        
    def run(self):
        result = self.scanner.advanced_scan(self.host, self.ports, self.scan_type)
        self.result_ready.emit(result)
        self.scan_finished.emit()

class AdvancedScanTab(QWidget):
    def __init__(self):
        super().__init__()
        self.scanner = PortScanner()
        self.scan_thread = None
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Enter hostname, IP, or CIDR (e.g., 192.168.1.0/24)")
        target_layout.addWidget(self.host_input)
        layout.addLayout(target_layout)
        
        # Port specification
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Ports:"))
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Enter ports (e.g., 80,443,8000-8100)")
        port_layout.addWidget(self.port_input)
        layout.addLayout(port_layout)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout(options_group)
        
        # Scan type
        scan_type_group = QGroupBox("Scan Type")
        scan_type_layout = QVBoxLayout(scan_type_group)
        
        self.tcp_connect_radio = QRadioButton("TCP Connect Scan (-sT)")
        self.tcp_connect_radio.setChecked(True)
        scan_type_layout.addWidget(self.tcp_connect_radio)
        
        self.syn_scan_radio = QRadioButton("SYN Scan (-sS) - Requires root/admin")
        scan_type_layout.addWidget(self.syn_scan_radio)
        
        self.udp_scan_radio = QRadioButton("UDP Scan (-sU) - Requires root/admin")
        scan_type_layout.addWidget(self.udp_scan_radio)
        
        self.fin_scan_radio = QRadioButton("FIN Scan (-sF) - Requires root/admin")
        scan_type_layout.addWidget(self.fin_scan_radio)
        
        options_layout.addWidget(scan_type_group)
        
        # Additional options
        additional_options = QGroupBox("Additional Options")
        additional_layout = QFormLayout(additional_options)
        
        self.os_detection_check = QCheckBox("OS Detection (-O)")
        additional_layout.addRow(self.os_detection_check)
        
        self.version_detection_check = QCheckBox("Version Detection (-sV)")
        additional_layout.addRow(self.version_detection_check)
        
        self.aggressive_scan_check = QCheckBox("Aggressive Scan (-A)")
        additional_layout.addRow(self.aggressive_scan_check)
        
        self.timing_combo = QComboBox()
        self.timing_combo.addItems([
            "T0 - Paranoid", 
            "T1 - Sneaky", 
            "T2 - Polite", 
            "T3 - Normal", 
            "T4 - Aggressive", 
            "T5 - Insane"
        ])
        self.timing_combo.setCurrentIndex(3)  # Default to Normal
        additional_layout.addRow("Timing Template:", self.timing_combo)
        
        options_layout.addWidget(additional_options)
        
        layout.addWidget(options_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Advanced Scan")
        self.scan_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        layout.addLayout(button_layout)
        
        # Results area
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        layout.addWidget(self.results_text)
        
    def get_scan_type(self):
        if self.tcp_connect_radio.isChecked():
            return "-sT"
        elif self.syn_scan_radio.isChecked():
            return "-sS"
        elif self.udp_scan_radio.isChecked():
            return "-sU"
        elif self.fin_scan_radio.isChecked():
            return "-sF"
        return "-sT"  # Default
        
    def get_additional_options(self):
        options = []
        
        if self.os_detection_check.isChecked():
            options.append("-O")
            
        if self.version_detection_check.isChecked():
            options.append("-sV")
            
        if self.aggressive_scan_check.isChecked():
            options.append("-A")
            
        # Add timing template
        timing_index = self.timing_combo.currentIndex()
        options.append(f"-T{timing_index}")
        
        return " ".join(options)
        
    def start_scan(self):
        host = self.host_input.text().strip()
        ports = self.port_input.text().strip()
        
        if not host or not ports:
            self.results_text.setText("Please enter both target and ports.")
            return
            
        # Build scan arguments
        scan_type = self.get_scan_type()
        additional_options = self.get_additional_options()
        scan_args = f"{scan_type} {additional_options}"
        
        # Update UI
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.results_text.setText("Scanning in progress...\n")
        
        # Start scan in a separate thread
        self.scan_thread = AdvancedScanWorker(self.scanner, host, ports, scan_args)
        self.scan_thread.result_ready.connect(self.update_result)
        self.scan_thread.scan_finished.connect(self.scan_complete)
        self.scan_thread.start()
        
    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scanner.stop_scanning()
            self.scan_thread.wait()
            self.scan_complete()
            
    def update_result(self, result):
        if "error" in result:
            self.results_text.append(f"Error: {result['error']}")
            return
            
        self.results_text.clear()
        self.results_text.append("Scan Results:\n")
        
        try:
            # Format and display the nmap results
            for proto in result.all_protocols():
                self.results_text.append(f"\nProtocol: {proto}")
                
                ports = sorted(result[proto].keys())
                for port in ports:
                    service = result[proto][port]
                    state = service['state']
                    
                    service_info = []
                    if 'product' in service:
                        service_info.append(service['product'])
                    if 'version' in service:
                        service_info.append(service['version'])
                    if 'extrainfo' in service:
                        service_info.append(f"({service['extrainfo']})")
                        
                    service_str = " ".join(service_info) if service_info else ""
                    
                    self.results_text.append(f"Port {port}/{proto}: {state} {service['name']} {service_str}")
            
            # Add OS detection results if available
            if 'osmatch' in result:
                self.results_text.append("\nOS Detection:")
                for os in result['osmatch']:
                    self.results_text.append(f"  {os['name']} - Accuracy: {os['accuracy']}%")
                    
        except Exception as e:
            self.results_text.append(f"\nError parsing results: {str(e)}")
            self.results_text.append(f"\nRaw result: {str(result)}")
        
    def scan_complete(self):
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.results_text.append("\nScan completed.")