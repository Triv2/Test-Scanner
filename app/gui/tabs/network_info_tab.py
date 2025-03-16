from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTextEdit, QTableWidget, 
                            QTableWidgetItem, QGroupBox, QTabWidget)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
import socket
import netifaces
import subprocess
import platform
import re

class NetworkInfoWorker(QThread):
    info_ready = pyqtSignal(dict)
    
    def __init__(self, info_type):
        super().__init__()
        self.info_type = info_type
        
    def run(self):
        if self.info_type == "interfaces":
            result = self.get_network_interfaces()
        elif self.info_type == "arp":
            result = self.get_arp_table()
        elif self.info_type == "route":
            result = self.get_routing_table()
        else:
            result = {"error": "Unknown info type"}
            
        self.info_ready.emit(result)
        
    def get_network_interfaces(self):
        interfaces = {}
        
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                
                # Get IPv4 info if available
                ipv4_info = {}
                if netifaces.AF_INET in addrs:
                    ipv4_info = addrs[netifaces.AF_INET][0]
                    
                # Get IPv6 info if available
                ipv6_info = {}
                if netifaces.AF_INET6 in addrs:
                    ipv6_info = addrs[netifaces.AF_INET6][0]
                    
                # Get MAC address if available
                mac_info = {}
                if netifaces.AF_LINK in addrs:
                    mac_info = addrs[netifaces.AF_LINK][0]
                    
                interfaces[iface] = {
                    "ipv4": ipv4_info.get("addr", "") if ipv4_info else "",
                    "netmask": ipv4_info.get("netmask", "") if ipv4_info else "",
                    "ipv6": ipv6_info.get("addr", "") if ipv6_info else "",
                    "mac": mac_info.get("addr", "") if mac_info else ""
                }
                
            return {"interfaces": interfaces}
        except Exception as e:
            return {"error": str(e)}
            
    def get_arp_table(self):
        arp_entries = []
        
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("arp -a", shell=True).decode("utf-8")
                for line in output.splitlines():
                    if "dynamic" in line.lower() or "static" in line.lower():
                        parts = re.split(r'\s+', line.strip())
                        if len(parts) >= 3:
                            ip = parts[0]
                            mac = parts[1]
                            type_entry = parts[2]
                            arp_entries.append({"ip": ip, "mac": mac, "type": type_entry})
            else:  # Linux/Mac
                output = subprocess.check_output(["arp", "-a"]).decode("utf-8")
                for line in output.splitlines():
                    if "(" in line and ")" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            hostname = parts[0]
                            ip = parts[1].strip("()")
                            mac = parts[3]
                            arp_entries.append({"hostname": hostname, "ip": ip, "mac": mac})
                            
            return {"arp_entries": arp_entries}
        except Exception as e:
            return {"error": str(e)}
            
    def get_routing_table(self):
        routes = []
        
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("route print", shell=True).decode("utf-8")
                ipv4_section = False
                for line in output.splitlines():
                    if "IPv4 Route Table" in line:
                        ipv4_section = True
                        continue
                    if ipv4_section and "==" in line:
                        continue
                    if ipv4_section and "Persistent Routes" in line:
                        break
                    if ipv4_section and line.strip() and not "Interface List" in line:
                        parts = re.split(r'\s+', line.strip())
                        if len(parts) >= 4 and parts[0].count('.') == 3:
                            network = parts[0]
                            netmask = parts[1]
                            gateway = parts[2]
                            interface = parts[3]
                            routes.append({
                                "network": network,
                                "netmask": netmask,
                                "gateway": gateway,
                                "interface": interface
                            })
            else:  # Linux/Mac
                output = subprocess.check_output(["netstat", "-rn"]).decode("utf-8")
                for line in output.splitlines():
                    if line.startswith("0.0.0.0") or line.startswith("default") or "UG" in line:
                        parts = re.split(r'\s+', line.strip())
                        if len(parts) >= 4:
                            destination = parts[0]
                            gateway = parts[1]
                            flags = parts[2]
                            interface = parts[-1]
                            routes.append({
                                "destination": destination,
                                "gateway": gateway,
                                "flags": flags,
                                "interface": interface
                            })
                            
            return {"routes": routes}
        except Exception as e:
            return {"error": str(e)}

class NetworkInfoTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Create tabs for different network information
        self.tabs = QTabWidget()
        
        # Interface information tab
        self.interface_tab = QWidget()
        interface_layout = QVBoxLayout(self.interface_tab)
        
        # Interface table
        self.interface_table = QTableWidget()
        self.interface_table.setColumnCount(5)
        self.interface_table.setHorizontalHeaderLabels(["Interface", "IPv4", "Netmask", "IPv6", "MAC Address"])
        self.interface_table.horizontalHeader().setStretchLastSection(True)
        interface_layout.addWidget(self.interface_table)
        
        # Refresh button for interfaces
        refresh_interfaces_btn = QPushButton("Refresh Interface Information")
        refresh_interfaces_btn.clicked.connect(self.refresh_interfaces)
        interface_layout.addWidget(refresh_interfaces_btn)
        
        self.tabs.addTab(self.interface_tab, "Network Interfaces")
        
        # ARP table tab
        self.arp_tab = QWidget()
        arp_layout = QVBoxLayout(self.arp_tab)
        
        # ARP table
        self.arp_table = QTableWidget()
        self.arp_table.setColumnCount(3)
        self.arp_table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Type"])
        self.arp_table.horizontalHeader().setStretchLastSection(True)
        arp_layout.addWidget(self.arp_table)
        
        # Refresh button for ARP
        refresh_arp_btn = QPushButton("Refresh ARP Table")
        refresh_arp_btn.clicked.connect(self.refresh_arp)
        arp_layout.addWidget(refresh_arp_btn)
        
        self.tabs.addTab(self.arp_tab, "ARP Table")
        
        # Routing table tab
        self.route_tab = QWidget()
        route_layout = QVBoxLayout(self.route_tab)
        
        # Routing table
        self.route_table = QTableWidget()
        if platform.system() == "Windows":
            self.route_table.setColumnCount(4)
            self.route_table.setHorizontalHeaderLabels(["Network", "Netmask", "Gateway", "Interface"])
        else:
            self.route_table.setColumnCount(4)
            self.route_table.setHorizontalHeaderLabels(["Destination", "Gateway", "Flags", "Interface"])
        self.route_table.horizontalHeader().setStretchLastSection(True)
        route_layout.addWidget(self.route_table)
        
        # Refresh button for routes
        refresh_route_btn = QPushButton("Refresh Routing Table")
        refresh_route_btn.clicked.connect(self.refresh_routes)
        route_layout.addWidget(refresh_route_btn)
        
        self.tabs.addTab(self.route_tab, "Routing Table")
        
        # System information tab
        self.system_tab = QWidget()
        system_layout = QVBoxLayout(self.system_tab)
        
        # System info text area
        self.system_info_text = QTextEdit()
        self.system_info_text.setReadOnly(True)
        system_layout.addWidget(self.system_info_text)
        
        # Refresh button for system info
        refresh_system_btn = QPushButton("Refresh System Information")
        refresh_system_btn.clicked.connect(self.refresh_system_info)
        system_layout.addWidget(refresh_system_btn)
        
        self.tabs.addTab(self.system_tab, "System Information")
        
        layout.addWidget(self.tabs)
        
        # Initial data load
        self.refresh_interfaces()
        self.refresh_arp()
        self.refresh_routes()
        self.refresh_system_info()
        
    def refresh_interfaces(self):
        self.interface_worker = NetworkInfoWorker("interfaces")
        self.interface_worker.info_ready.connect(self.update_interfaces)
        self.interface_worker.start()
        
    def refresh_arp(self):
        self.arp_worker = NetworkInfoWorker("arp")
        self.arp_worker.info_ready.connect(self.update_arp)
        self.arp_worker.start()
        
    def refresh_routes(self):
        self.route_worker = NetworkInfoWorker("route")
        self.route_worker.info_ready.connect(self.update_routes)
        self.route_worker.start()
        
    def refresh_system_info(self):
        self.system_info_text.clear()
        
        # Get hostname
        hostname = socket.gethostname()
        self.system_info_text.append(f"Hostname: {hostname}")
        
        # Get IP addresses
        try:
            ip = socket.gethostbyname(hostname)
            self.system_info_text.append(f"IP Address: {ip}")
        except:
            self.system_info_text.append("IP Address: Unable to determine")
        
        # Get OS information
        self.system_info_text.append(f"\nOperating System: {platform.system()} {platform.release()}")
        self.system_info_text.append(f"OS Version: {platform.version()}")
        self.system_info_text.append(f"Architecture: {platform.machine()}")
        
        # Get Python version
        self.system_info_text.append(f"\nPython Version: {platform.python_version()}")
        
        # Get network hostname resolution
        try:
            fqdn = socket.getfqdn()
            self.system_info_text.append(f"\nFully Qualified Domain Name: {fqdn}")
        except:
                      self.system_info_text.append("\nFully Qualified Domain Name: Unable to determine")
        
        # Get default gateway
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("ipconfig", shell=True).decode("utf-8")
                for line in output.splitlines():
                    if "Default Gateway" in line and not ":" in line.split(":")[-1].strip():
                        continue
                    if "Default Gateway" in line:
                        gateway = line.split(":")[-1].strip()
                        self.system_info_text.append(f"\nDefault Gateway: {gateway}")
                        break
            else:  # Linux/Mac
                output = subprocess.check_output(["netstat", "-rn"]).decode("utf-8")
                for line in output.splitlines():
                    if line.startswith("0.0.0.0") or line.startswith("default"):
                        gateway = line.split()[1]
                        self.system_info_text.append(f"\nDefault Gateway: {gateway}")
                        break
        except:
            self.system_info_text.append("\nDefault Gateway: Unable to determine")
        
        # Get DNS servers
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("ipconfig /all", shell=True).decode("utf-8")
                dns_servers = []
                for line in output.splitlines():
                    if "DNS Servers" in line:
                        dns = line.split(":")[-1].strip()
                        if dns:
                            dns_servers.append(dns)
                    elif line.strip().startswith("1") and "." in line and len(dns_servers) > 0:
                        # This is likely a continuation of DNS servers
                        dns = line.strip()
                        dns_servers.append(dns)
                
                if dns_servers:
                    self.system_info_text.append("\nDNS Servers:")
                    for dns in dns_servers:
                        self.system_info_text.append(f"  {dns}")
            else:  # Linux/Mac
                try:
                    with open("/etc/resolv.conf", "r") as f:
                        self.system_info_text.append("\nDNS Servers:")
                        for line in f:
                            if line.startswith("nameserver"):
                                dns = line.split()[1]
                                self.system_info_text.append(f"  {dns}")
                except:
                    self.system_info_text.append("\nDNS Servers: Unable to determine")
        except:
            self.system_info_text.append("\nDNS Servers: Unable to determine")
    
    def update_interfaces(self, data):
        if "error" in data:
            self.interface_table.setRowCount(1)
            self.interface_table.setItem(0, 0, QTableWidgetItem("Error"))
            self.interface_table.setItem(0, 1, QTableWidgetItem(data["error"]))
            return
            
        interfaces = data.get("interfaces", {})
        self.interface_table.setRowCount(len(interfaces))
        
        row = 0
        for iface, info in interfaces.items():
            self.interface_table.setItem(row, 0, QTableWidgetItem(iface))
            self.interface_table.setItem(row, 1, QTableWidgetItem(info.get("ipv4", "")))
            self.interface_table.setItem(row, 2, QTableWidgetItem(info.get("netmask", "")))
            self.interface_table.setItem(row, 3, QTableWidgetItem(info.get("ipv6", "")))
            self.interface_table.setItem(row, 4, QTableWidgetItem(info.get("mac", "")))
            row += 1
            
        self.interface_table.resizeColumnsToContents()
        
    def update_arp(self, data):
        if "error" in data:
            self.arp_table.setRowCount(1)
            self.arp_table.setItem(0, 0, QTableWidgetItem("Error"))
            self.arp_table.setItem(0, 1, QTableWidgetItem(data["error"]))
            return
            
        arp_entries = data.get("arp_entries", [])
        self.arp_table.setRowCount(len(arp_entries))
        
        for row, entry in enumerate(arp_entries):
            self.arp_table.setItem(row, 0, QTableWidgetItem(entry.get("ip", "")))
            self.arp_table.setItem(row, 1, QTableWidgetItem(entry.get("mac", "")))
            self.arp_table.setItem(row, 2, QTableWidgetItem(entry.get("type", "")))
            
        self.arp_table.resizeColumnsToContents()
        
    def update_routes(self, data):
        if "error" in data:
            self.route_table.setRowCount(1)
            self.route_table.setItem(0, 0, QTableWidgetItem("Error"))
            self.route_table.setItem(0, 1, QTableWidgetItem(data["error"]))
            return
            
        routes = data.get("routes", [])
        self.route_table.setRowCount(len(routes))
        
        for row, route in enumerate(routes):
            if platform.system() == "Windows":
                self.route_table.setItem(row, 0, QTableWidgetItem(route.get("network", "")))
                self.route_table.setItem(row, 1, QTableWidgetItem(route.get("netmask", "")))
                self.route_table.setItem(row, 2, QTableWidgetItem(route.get("gateway", "")))
                self.route_table.setItem(row, 3, QTableWidgetItem(route.get("interface", "")))
            else:
                self.route_table.setItem(row, 0, QTableWidgetItem(route.get("destination", "")))
                self.route_table.setItem(row, 1, QTableWidgetItem(route.get("gateway", "")))
                self.route_table.setItem(row, 2, QTableWidgetItem(route.get("flags", "")))
                self.route_table.setItem(row, 3, QTableWidgetItem(route.get("interface", "")))
                
        self.route_table.resizeColumnsToContents()