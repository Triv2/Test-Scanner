from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
                            QLabel, QLineEdit, QSpinBox, QCheckBox, 
                            QPushButton, QComboBox, QFileDialog, QGroupBox,
                            QFormLayout, QSlider)
from PyQt5.QtCore import Qt, QSettings

from app.utils.config import ConfigManager

class SettingsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.config = ConfigManager()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Create tabs for different settings categories
        tab_widget = QTabWidget()
        tab_widget.addTab(self.create_general_tab(), "General")
        tab_widget.addTab(self.create_scan_tab(), "Scan")
        tab_widget.addTab(self.create_appearance_tab(), "Appearance")
        tab_widget.addTab(self.create_network_tab(), "Network")
        tab_widget.addTab(self.create_advanced_tab(), "Advanced")
        
        layout.addWidget(tab_widget)
        
        # Buttons for saving/resetting settings
        button_layout = QHBoxLayout()
        
        save_button = QPushButton("Save Settings")
        save_button.clicked.connect(self.save_settings)
        
        reset_button = QPushButton("Reset to Defaults")
        reset_button.clicked.connect(self.reset_settings)
        
        button_layout.addStretch()
        button_layout.addWidget(save_button)
        button_layout.addWidget(reset_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def create_general_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Results group
        results_group = QGroupBox("Results")
        results_layout = QFormLayout()
        
        self.auto_save = QCheckBox()
        self.auto_save.setChecked(self.config.get("general", "save_results_automatically", False))
        results_layout.addRow("Auto-save results:", self.auto_save)
        
        self.results_dir = QLineEdit()
        self.results_dir.setText(self.config.get("general", "results_directory", ""))
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_results_dir)
        
        dir_layout = QHBoxLayout()
        dir_layout.addWidget(self.results_dir)
        dir_layout.addWidget(browse_button)
        results_layout.addRow("Results directory:", dir_layout)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Performance group
        perf_group = QGroupBox("Performance")
        perf_layout = QFormLayout()
        
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 30)
        self.timeout.setValue(self.config.get("general", "default_timeout", 5))
        perf_layout.addRow("Default timeout (seconds):", self.timeout)
        
        self.threads = QSpinBox()
        self.threads.setRange(1, 100)
        self.threads.setValue(self.config.get("general", "max_threads", 10))
        perf_layout.addRow("Maximum threads:", self.threads)
        
        perf_group.setLayout(perf_layout)
        layout.addWidget(perf_group)
        
        layout.addStretch()
        tab.setLayout(layout)
        return tab
    
    def create_scan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Scan defaults group
        scan_group = QGroupBox("Scan Defaults")
        scan_layout = QFormLayout()
        
        self.scan_type = QComboBox()
        self.scan_type.addItems(["TCP Connect", "SYN Scan", "UDP Scan", "FIN Scan", "XMAS Scan"])
        self.scan_type.setCurrentText(self.config.get("scan", "default_scan_type", "TCP Connect"))
        scan_layout.addRow("Default scan type:", self.scan_type)
        
        self.port_range = QLineEdit()
        self.port_range.setText(self.config.get("scan", "default_port_range", "1-1024"))
        scan_layout.addRow("Default port range:", self.port_range)
        
        self.common_ports = QCheckBox()
        self.common_ports.setChecked(self.config.get("scan", "common_ports_only", False))
        scan_layout.addRow("Scan common ports only:", self.common_ports)
        
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)
        
        # Detection group
        detect_group = QGroupBox("Detection")
        detect_layout = QFormLayout()
        
        self.service_detect = QCheckBox()
        self.service_detect.setChecked(self.config.get("scan", "service_detection", True))
        detect_layout.addRow("Service detection:", self.service_detect)
        
        self.os_detect = QCheckBox()
        self.os_detect.setChecked(self.config.get("scan", "os_detection", False))
        detect_layout.addRow("OS detection:", self.os_detect)
        
        detect_group.setLayout(detect_layout)
        layout.addWidget(detect_group)
        
        layout.addStretch()
        tab.setLayout(layout)
        return tab
    
    def create_appearance_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Theme group
        theme_group = QGroupBox("Theme")
        theme_layout = QFormLayout()
        
        self.theme = QComboBox()
        self.theme.addItems(["system", "light", "dark"])
        self.theme.setCurrentText(self.config.get("appearance", "theme", "system"))
        theme_layout.addRow("Application theme:", self.theme)
        
        self.font_size = QComboBox()
        self.font_size.addItems(["small", "medium", "large"])
        self.font_size.setCurrentText(self.config.get("appearance", "font_size", "medium"))
        theme_layout.addRow("Font size:", self.font_size)
        
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)
        
        # UI Options group
        ui_group = QGroupBox("UI Options")
        ui_layout = QFormLayout()
        
        self.show_toolbar = QCheckBox()
        self.show_toolbar.setChecked(self.config.get("appearance", "show_toolbar", True))
        ui_layout.addRow("Show toolbar:", self.show_toolbar)
        
        self.compact_view = QCheckBox()
        self.compact_view.setChecked(self.config.get("appearance", "compact_view", False))
        ui_layout.addRow("Compact view:", self.compact_view)
        
        ui_group.setLayout(ui_layout)
        layout.addWidget(ui_group)
        
        layout.addStretch()
        tab.setLayout(layout)
        return tab
    
    def create_network_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Connection settings group
        conn_group = QGroupBox("Connection Settings")
        conn_layout = QFormLayout()
        
        self.timeout_ms = QSpinBox()
        self.timeout_ms.setRange(100, 10000)
        self.timeout_ms.setSingleStep(100)
        self.timeout_ms.setValue(self.config.get("network", "timeout_ms", 2000))
        conn_layout.addRow("Timeout (ms):", self.timeout_ms)
        
        self.retries = QSpinBox()
        self.retries.setRange(0, 10)
        self.retries.setValue(self.config.get("network", "retries", 2))
        conn_layout.addRow("Retries:", self.retries)
        
        conn_group.setLayout(conn_layout)
        layout.addWidget(conn_group)
        
        # Source settings group
        source_group = QGroupBox("Source Settings")
        source_layout = QFormLayout()
        
        self.source_port = QSpinBox()
        self.source_port.setRange(0, 65535)
        self.source_port.setSpecialValueText("Random")
        self.source_port.setValue(self.config.get("network", "source_port", 0))
        source_layout.addRow("Source port:", self.source_port)
        
        self.source_address = QLineEdit()
        self.source_address.setText(self.config.get("network", "source_address", ""))
        self.source_address.setPlaceholderText("Default interface")
        source_layout.addRow("Source address:", self.source_address)
        
        self.ttl = QSpinBox()
        self.ttl.setRange(1, 255)
        self.ttl.setValue(self.config.get("network", "ttl", 64))
        source_layout.addRow("TTL:", self.ttl)
        
        source_group.setLayout(source_layout)
        layout.addWidget(source_group)
        
        layout.addStretch()
        tab.setLayout(layout)
        return tab
    
    def create_advanced_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        
        # Debug group
        debug_group = QGroupBox("Debug Options")
        debug_layout = QFormLayout()
        
        self.debug_mode = QCheckBox()
        self.debug_mode.setChecked(self.config.get("advanced", "debug_mode", False))
        debug_layout.addRow("Debug mode:", self.debug_mode)
        
        self.packet_trace = QCheckBox()
        self.packet_trace.setChecked(self.config.get("advanced", "packet_trace", False))
        debug_layout.addRow("Packet tracing:", self.packet_trace)
        
        debug_group.setLayout(debug_layout)
        layout.addWidget(debug_group)
        
        # Advanced options group
        adv_group = QGroupBox("Advanced Options")
        adv_layout = QFormLayout()
        
        self.fragment = QCheckBox()
        self.fragment.setChecked(self.config.get("advanced", "fragment_packets", False))
        adv_layout.addRow("Fragment packets:", self.fragment)
        
        self.spoof_mac = QLineEdit()
        self.spoof_mac.setText(self.config.get("advanced", "spoof_mac", ""))
        self.spoof_mac.setPlaceholderText("00:11:22:33:44:55")
        adv_layout.addRow("Spoof MAC address:", self.spoof_mac)
        
        self.custom_payload = QLineEdit()
        self.custom_payload.setText(self.config.get("advanced", "custom_payload", ""))
        self.custom_payload.setPlaceholderText("Hex format: 0A0B0C...")
        adv_layout.addRow("Custom payload:", self.custom_payload)
        
        adv_group.setLayout(adv_layout)
        layout.addWidget(adv_group)
        
        layout.addStretch()
        tab.setLayout(layout)
        return tab
    
    def browse_results_dir(self):
        """Open directory browser dialog"""
        current_dir = self.results_dir.text() or os.path.expanduser("~/Documents")
        directory = QFileDialog.getExistingDirectory(self, "Select Results Directory", current_dir)
        if directory:
            self.results_dir.setText(directory)
    
    def save_settings(self):
        """Save all settings to config"""
        # General settings
        self.config.set("general", "save_results_automatically", self.auto_save.isChecked())
        self.config.set("general", "results_directory", self.results_dir.text())
        self.config.set("general", "default_timeout", self.timeout.value())
        self.config.set("general", "max_threads", self.threads.value())
        
        # Scan settings
        self.config.set("scan", "default_scan_type", self.scan_type.currentText())
        self.config.set("scan", "default_port_range", self.port_range.text())
        self.config.set("scan", "common_ports_only", self.common_ports.isChecked())
        self.config.set("scan", "service_detection", self.service_detect.isChecked())
        self.config.set("scan", "os_detection", self.os_detect.isChecked())
        
        # Appearance settings
        self.config.set("appearance", "theme", self.theme.currentText())
        self.config.set("appearance", "font_size", self.font_size.currentText())
        self.config.set("appearance", "show_toolbar", self.show_toolbar.isChecked())
        self.config.set("appearance", "compact_view", self.compact_view.isChecked())
        
        # Network settings
        self.config.set("network", "timeout_ms", self.timeout_ms.value())
        self.config.set("network", "retries", self.retries.value())
        self.config.set("network", "source_port", self.source_port.value())
        self.config.set("network", "source_address", self.source_address.text())
        self.config.set("network", "ttl", self.ttl.value())
        
        # Advanced settings
        self.config.set("advanced", "debug_mode", self.debug_mode.isChecked())
        self.config.set("advanced", "packet_trace", self.packet_trace.isChecked())
        self.config.set("advanced", "fragment_packets", self.fragment.isChecked())
        self.config.set("advanced", "spoof_mac", self.spoof_mac.text())
        self.config.set("advanced", "custom_payload", self.custom_payload.text())
        
        # Save to file
        success = self.config.save_config()
        if success:
            QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully.")
        else:
            QMessageBox.warning(self, "Error", "Failed to save settings.")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        reply = QMessageBox.question(self, "Reset Settings", 
                                    "Are you sure you want to reset all settings to defaults?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.config.reset_to_defaults()
            # Reload the UI with default values
            self.__init__(self.parent())
            QMessageBox.information(self, "Settings Reset", "All settings have been reset to defaults.")