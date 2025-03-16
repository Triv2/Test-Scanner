from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QCheckBox, QComboBox, QSpinBox,
                            QFormLayout, QGroupBox, QLineEdit, QFileDialog)
from PyQt6.QtCore import Qt, pyqtSignal
import json
import os
import sys

class SettingsTab(QWidget):
    settings_changed = pyqtSignal()
    
    def __init__(self):
        super().__init__()
        
        # Default settings
        self.settings = {
            "general": {
                "save_results_automatically": False,
                "results_directory": os.path.expanduser("~/Documents"),
                "default_timeout": 5,
                "max_threads": 10
            },
            "scan": {
                "default_ports": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
                "default_scan_type": "TCP",
                "aggressive_scan": False,
                "resolve_hostnames": True
            },
            "appearance": {
                "theme": "System",
                "font_size": 10
            }
        }
        
        # Load settings if they exist
        self.settings_file = self.get_settings_file_path()
        self.load_settings()
        
        # Setup UI
        self.setup_ui()
        
    def get_settings_file_path(self):
        """Get the path to the settings file based on the platform"""
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            app_dir = os.path.dirname(sys.executable)
        else:
            # Running as script
            app_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            
        return os.path.join(app_dir, "config", "settings.json")
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # General Settings
        general_group = QGroupBox("General Settings")
        general_layout = QFormLayout()
        
        # Auto-save results
        self.auto_save_checkbox = QCheckBox()
        self.auto_save_checkbox.setChecked(self.settings["general"]["save_results_automatically"])
        general_layout.addRow("Auto-save results:", self.auto_save_checkbox)
        
        # Results directory
        results_dir_layout = QHBoxLayout()
        self.results_dir_edit = QLineEdit(self.settings["general"]["results_directory"])
        self.results_dir_edit.setReadOnly(True)
        results_dir_layout.addWidget(self.results_dir_edit)
        
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_results_directory)
        results_dir_layout.addWidget(browse_button)
        
        general_layout.addRow("Results directory:", results_dir_layout)
        
        # Timeout
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(1, 60)
        self.timeout_spinbox.setValue(self.settings["general"]["default_timeout"])
        self.timeout_spinbox.setSuffix(" seconds")
        general_layout.addRow("Default timeout:", self.timeout_spinbox)
        
        # Max threads
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setRange(1, 100)
        self.threads_spinbox.setValue(self.settings["general"]["max_threads"])
        self.threads_spinbox.setToolTip("Maximum number of concurrent threads for scanning")
        general_layout.addRow("Max threads:", self.threads_spinbox)
        
        general_group.setLayout(general_layout)
        layout.addWidget(general_group)
        
        # Scan Settings
        scan_group = QGroupBox("Scan Settings")
        scan_layout = QFormLayout()
        
        # Default ports
        self.default_ports_edit = QLineEdit(self.settings["scan"]["default_ports"])
        self.default_ports_edit.setToolTip("Comma-separated list of ports to scan by default")
        scan_layout.addRow("Default ports:", self.default_ports_edit)
        
        # Default scan type
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["TCP", "UDP", "SYN"])
        self.scan_type_combo.setCurrentText(self.settings["scan"]["default_scan_type"])
        scan_layout.addRow("Default scan type:", self.scan_type_combo)
        
        # Aggressive scan
        self.aggressive_checkbox = QCheckBox()
        self.aggressive_checkbox.setChecked(self.settings["scan"]["aggressive_scan"])
        self.aggressive_checkbox.setToolTip("Enable more aggressive scanning techniques (may be detected by IDS/IPS)")
        scan_layout.addRow("Aggressive scan:", self.aggressive_checkbox)
        
        # Resolve hostnames
        self.resolve_checkbox = QCheckBox()
        self.resolve_checkbox.setChecked(self.settings["scan"]["resolve_hostnames"])
        scan_layout.addRow("Resolve hostnames:", self.resolve_checkbox)
        
        scan_group.setLayout(scan_layout)
        layout.addWidget(scan_group)
        
        # Appearance Settings
        appearance_group = QGroupBox("Appearance")
        appearance_layout = QFormLayout()
        
        # Theme
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["System", "Light", "Dark"])
        self.theme_combo.setCurrentText(self.settings["appearance"]["theme"])
        appearance_layout.addRow("Theme:", self.theme_combo)
        
        # Font size
        self.font_size_spinbox = QSpinBox()
        self.font_size_spinbox.setRange(8, 16)
        self.font_size_spinbox.setValue(self.settings["appearance"]["font_size"])
        appearance_layout.addRow("Font size:", self.font_size_spinbox)
        
        appearance_group.setLayout(appearance_layout)
        layout.addWidget(appearance_group)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        
        save_button = QPushButton("Save Settings")
        save_button.clicked.connect(self.save_settings)
        buttons_layout.addWidget(save_button)
        
        reset_button = QPushButton("Reset to Defaults")
        reset_button.clicked.connect(self.reset_settings)
        buttons_layout.addWidget(reset_button)
        
        layout.addLayout(buttons_layout)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
    def browse_results_directory(self):
        directory = QFileDialog.getExistingDirectory(
            self, 
            "Select Results Directory",
            self.results_dir_edit.text()
        )
        
        if directory:
            self.results_dir_edit.setText(directory)
            
    def load_settings(self):
        """Load settings from file if it exists"""
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    loaded_settings = json.load(f)
                    
                    # Update settings with loaded values, keeping defaults for any missing keys
                    for category in self.settings:
                        if category in loaded_settings:
                            for key in self.settings[category]:
                                if key in loaded_settings[category]:
                                    self.settings[category][key] = loaded_settings[category][key]
        except Exception as e:
            print(f"Error loading settings: {e}")
            
    def save_settings(self):
        """Save current settings to file"""
        # Update settings from UI
        self.settings["general"]["save_results_automatically"] = self.auto_save_checkbox.isChecked()
        self.settings["general"]["results_directory"] = self.results_dir_edit.text()
        self.settings["general"]["default_timeout"] = self.timeout_spinbox.value()
        self.settings["general"]["max_threads"] = self.threads_spinbox.value()
        
        self.settings["scan"]["default_ports"] = self.default_ports_edit.text()
        self.settings["scan"]["default_scan_type"] = self.scan_type_combo.currentText()
        self.settings["scan"]["aggressive_scan"] = self.aggressive_checkbox.isChecked()
        self.settings["scan"]["resolve_hostnames"] = self.resolve_checkbox.isChecked()
        
        self.settings["appearance"]["theme"] = self.theme_combo.currentText()
        self.settings["appearance"]["font_size"] = self.font_size_spinbox.value()
        
        # Ensure config directory exists
        os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
        
        # Save to file
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=4)
                
            # Emit signal that settings have changed
            self.settings_changed.emit()
            
            # Show success message
            QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save settings: {str(e)}")
            
    def reset_settings(self):
        """Reset settings to default values"""
        if QMessageBox.question(
            self,
            "Reset Settings",
            "Are you sure you want to reset all settings to default values?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) == QMessageBox.StandardButton.Yes:
            # Reset to default values
            self.settings = {
                "general": {
                    "save_results_automatically": False,
                    "results_directory": os.path.expanduser("~/Documents"),
                    "default_timeout": 5,
                    "max_threads": 10
                },
                "scan": {
                    "default_ports": "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
                    "default_scan_type": "TCP",
                    "aggressive_scan": False,
                    "resolve_hostnames": True
                },
                "appearance": {
                    "theme": "System",
                    "font_size": 10
                }
            }
            
            # Update UI
            self.auto_save_checkbox.setChecked(self.settings["general"]["save_results_automatically"])
            self.results_dir_edit.setText(self.settings["general"]["results_directory"])
            self.timeout_spinbox.setValue(self.settings["general"]["default_timeout"])
            self.threads_spinbox.setValue(self.settings["general"]["max_threads"])
            
            self.default_ports_edit.setText(self.settings["scan"]["default_ports"])
            self.scan_type_combo.setCurrentText(self.settings["scan"]["default_scan_type"])
            self.aggressive_checkbox.setChecked(self.settings["scan"]["aggressive_scan"])
            self.resolve_checkbox.setChecked(self.settings["scan"]["resolve_hostnames"])
            
            self.theme_combo.setCurrentText(self.settings["appearance"]["theme"])
            self.font_size_spinbox.setValue(self.settings["appearance"]["font_size"])
            
            # Save to file
            self.save_settings()
            
    def get_settings(self):
        """Return the current settings"""
        return self.settings