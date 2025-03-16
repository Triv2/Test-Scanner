from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QVBoxLayout, 
                            QWidget, QStatusBar, QMenuBar, QMenu, QMessageBox)
from PyQt6.QtCore import Qt

from .tabs.quick_scan_tab import QuickScanTab
from .tabs.advanced_scan_tab import AdvancedScanTab
from .tabs.network_info_tab import NetworkInfoTab
from .tabs.settings_tab import SettingsTab

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Port Scanner")
        self.resize(800, 600)
        
        # Create central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.quick_scan_tab = QuickScanTab()
        self.advanced_scan_tab = AdvancedScanTab()
        self.network_info_tab = NetworkInfoTab()
        self.settings_tab = SettingsTab()
        
        # Add tabs
        self.tabs.addTab(self.quick_scan_tab, "Quick Scan")
        self.tabs.addTab(self.advanced_scan_tab, "Advanced Scan")
        self.tabs.addTab(self.network_info_tab, "Network Info")
        self.tabs.addTab(self.settings_tab, "Settings")
        
        self.layout.addWidget(self.tabs)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Create menu bar
        self.setup_menu()
        
    def setup_menu(self):
        menu_bar = QMenuBar()
        self.setMenuBar(menu_bar)
        
        # File menu
        file_menu = QMenu("&File", self)
        menu_bar.addMenu(file_menu)
        
        file_menu.addAction("Save Results", self.save_results)
        file_menu.addAction("Export Report", self.export_report)
        file_menu.addSeparator()
        file_menu.addAction("Exit", self.close, shortcut="Ctrl+Q")
        
        # Help menu
        help_menu = QMenu("&Help", self)
        menu_bar.addMenu(help_menu)
        
        help_menu.addAction("About", self.show_about)
        
    def save_results(self):
        # Implement save functionality
        pass
        
    def export_report(self):
        # Implement export functionality
        pass
        
    def show_about(self):
        QMessageBox.about(
            self,
            "About Port Scanner",
            "Port Scanner v1.0\n\nA desktop application for scanning ports on local and remote hosts."
        )