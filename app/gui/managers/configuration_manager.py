import json
import os
import sys
from typing import Dict, Any

class ConfigManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        # Default configuration
        self.config = {
            "general": {
                "save_results_automatically": False,
                "results_directory": os.path.expanduser("~/Documents/PortScanner"),
                "default_timeout": 5,
                "max_threads": 10
            },
            "scan": {
                "default_scan_type": "TCP Connect",
                "default_port_range": "1-1024",
                "common_ports_only": False,
                "service_detection": True,
                "os_detection": False
            },
            "appearance": {
                "theme": "system",  # system, light, dark
                "font_size": "medium",
                "show_toolbar": True,
                "compact_view": False
            },
            "network": {
                "timeout_ms": 2000,
                "retries": 2,
                "source_port": 0,  # 0 means random
                "source_address": "",  # empty means default
                "ttl": 64
            },
            "advanced": {
                "debug_mode": False,
                "packet_trace": False,
                "fragment_packets": False,
                "spoof_mac": "",
                "custom_payload": ""
            }
        }
        
        # Determine config directory
        if getattr(sys, 'frozen', False):
            app_dir = os.path.dirname(sys.executable)
        else:
            app_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        self.config_dir = os.path.join(app_dir, 'config')
        self.config_file = os.path.join(self.config_dir, 'settings.json')
        
        # Create config directory if it doesn't exist
        os.makedirs(self.config_dir, exist_ok=True)
        
        # Load existing config if available
        self.load_config()
    
    def load_config(self) -> bool:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                    
                    # Update default config with user settings
                    for section, settings in user_config.items():
                        if section in self.config:
                            self.config[section].update(settings)
                        else:
                            self.config[section] = settings
                return True
        except Exception as e:
            print(f"Error loading configuration: {e}")
        return False
    
    def save_config(self) -> bool:
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
        return False
    
    def get(self, section: str, key: str, default=None) -> Any:
        """Get a configuration value"""
        try:
            return self.config[section][key]
        except KeyError:
            return default
    
    def set(self, section: str, key: str, value: Any) -> bool:
        """Set a configuration value"""
        try:
            if section not in self.config:
                self.config[section] = {}
            self.config[section][key] = value
            return True
        except Exception:
            return False
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get an entire configuration section"""
        return self.config.get(section, {})
    
    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults"""
        self._initialize()
        return self.save_config()