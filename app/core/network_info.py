# app/core/network_info.py
import socket
import netifaces
import subprocess
import platform
import re
from typing import Dict, List, Any

def get_network_interfaces() -> Dict[str, Dict[str, str]]:
    """Get information about network interfaces"""
    interfaces = {}
    
    for iface in netifaces.interfaces():
        info = {"ipv4": "", "ipv6": "", "mac": "", "netmask": ""}
        
        # Get addresses for this interface
        addrs = netifaces.ifaddresses(iface)
        
        # Get IPv4 address
        if netifaces.AF_INET in addrs:
            info["ipv4"] = addrs[netifaces.AF_INET][0].get("addr", "")
            info["netmask"] = addrs[netifaces.AF_INET][0].get("netmask", "")
            
        # Get IPv6 address
        if netifaces.AF_INET6 in addrs:
            info["ipv6"] = addrs[netifaces.AF_INET6][0].get("addr", "").split("%")[0]
            
        # Get MAC address
        if netifaces.AF_LINK in addrs:
            info["mac"] = addrs[netifaces.AF_LINK][0].get("addr", "")
            
        interfaces[iface] = info
        
    return interfaces

def get_arp_table() -> List[Dict[str, str]]:
    """Get ARP table entries"""
    entries = []
    
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("arp -a", shell=True).decode("utf-8")
            for line in output.splitlines():
                if "dynamic" in line.lower() or "static" in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        entries.append({
                            "ip": parts[0],
                            "mac": parts[1],
                            "type": parts[2]
                        })
        else:  # Linux/Mac
            output = subprocess.check_output(["arp", "-a"]).decode("utf-8")
            for line in output.splitlines():
                if "(" in line and ")" in line:
                    ip = line.split("(")[1].split(")")[0]
                    parts = line.split()
                    if len(parts) >= 4:
                        entries.append({
                            "ip": ip,
                            "mac": parts[3],
                            "type": parts[4] if len(parts) > 4 else ""
                        })
    except Exception as e:
        print(f"Error getting ARP table: {e}")
        
    return entries
def get_routing_table() -> List[Dict[str, str]]:
    """Get routing table entries"""
    routes = []
    
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("route print", shell=True, stderr=subprocess.STDOUT).decode("utf-8", errors="replace")
            ipv4_section = False
            
            for line in output.splitlines():
                if "IPv4 Route Table" in line:
                    ipv4_section = True
                    continue
                elif "IPv6 Route Table" in line or "Persistent Routes" in line:
                    # Stop processing when we reach IPv6 section or persistent routes
                    ipv4_section = False
                    continue
                    
                if ipv4_section and "==" in line:
                    continue
                    
                if ipv4_section and line.strip() and "IPv6" not in line:
                    parts = line.split()
                    if len(parts) >= 4 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                        try:
                            route_entry = {
                                "network": parts[0],
                                "netmask": parts[1],
                                "gateway": parts[2],
                                "interface": parts[3]
                            }
                            
                            # Add metric if available
                            if len(parts) >= 5:
                                route_entry["metric"] = parts[4]
                                
                            routes.append(route_entry)
                        except IndexError:
                            # Skip malformed lines
                            continue
        else:  # Linux/Mac
            try:
                # Try netstat first
                output = subprocess.check_output(["netstat", "-rn"], stderr=subprocess.STDOUT).decode("utf-8", errors="replace")
            except (subprocess.CalledProcessError, FileNotFoundError):
                try:
                    # Fall back to ip route if netstat is not available (newer Linux distros)
                    output = subprocess.check_output(["ip", "route"], stderr=subprocess.STDOUT).decode("utf-8", errors="replace")
                    # Parse ip route output differently
                    for line in output.splitlines():
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 3:
                                route_entry = {
                                    "destination": parts[0],
                                    "gateway": "via" in parts and parts[parts.index("via") + 1] or "*",
                                    "interface": parts[-1] if "dev" in parts else ""
                                }
                                routes.append(route_entry)
                    return routes
                except (subprocess.CalledProcessError, FileNotFoundError):
                    # If both commands fail, return empty list
                    return routes
            
            # Parse netstat output
            for line in output.splitlines():
                if line.startswith("Destination") or line.strip() == "":
                    continue
                    
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        route_entry = {
                            "destination": parts[0],
                            "gateway": parts[1],
                            "flags": parts[2],
                            "interface": parts[-1]
                        }
                        
                        # Add metric if available (position varies by OS)
                        for i, part in enumerate(parts):
                            if part.isdigit() and i > 2 and i < len(parts) - 1:
                                route_entry["metric"] = part
                                break
                                
                        routes.append(route_entry)
                    except IndexError:
                        # Skip malformed lines
                        continue
    except subprocess.CalledProcessError as e:
        print(f"Command execution failed when getting routing table: {e}")
        print(f"Command output: {e.output.decode('utf-8', errors='replace') if hasattr(e, 'output') else 'No output'}")
    except Exception as e:
        print(f"Error getting routing table: {e}")
        import traceback
        print(traceback.format_exc())
        
    return routes