import json
import csv
import os
import datetime
from typing import List, Dict, Any

class ScanResult:
    def __init__(self, target: str, scan_type: str, start_time: datetime.datetime):
        self.target = target
        self.scan_type = scan_type
        self.start_time = start_time
        self.end_time = None
        self.ports = []
        self.metadata = {}
    
    def add_port_result(self, port_data: Dict[str, Any]):
        self.ports.append(port_data)
    
    def set_end_time(self, end_time: datetime.datetime):
        self.end_time = end_time
    
    def get_duration(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.get_duration(),
            "ports": self.ports,
            "metadata": self.metadata
        }

class ResultsManager:
    def __init__(self, base_dir: str = None):
        if base_dir is None:
            # Default to user's documents folder
            base_dir = os.path.join(os.path.expanduser("~"), "Documents", "PortScanner")
        
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)
    
    def save_result(self, result: ScanResult, format: str = "json") -> str:
        """Save scan result to a file in the specified format"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        target_name = result.target.replace(".", "_").replace(":", "_")
        filename = f"scan_{target_name}_{timestamp}"
        
        if format == "json":
            return self._save_as_json(result, filename)
        elif format == "csv":
            return self._save_as_csv(result, filename)
        elif format == "txt":
            return self._save_as_txt(result, filename)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _save_as_json(self, result: ScanResult, filename: str) -> str:
        """Save result as JSON file"""
        filepath = os.path.join(self.base_dir, f"{filename}.json")
        with open(filepath, 'w') as f:
            json.dump(result.to_dict(), f, indent=4)
        return filepath
    
    def _save_as_csv(self, result: ScanResult, filename: str) -> str:
        """Save result as CSV file"""
        filepath = os.path.join(self.base_dir, f"{filename}.csv")
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Port", "State", "Service", "Protocol"])
            for port in result.ports:
                writer.writerow([
                    port.get("port", ""),
                    port.get("state", ""),
                    port.get("service", ""),
                    port.get("protocol", "TCP")
                ])
        return filepath
    
    def _save_as_txt(self, result: ScanResult, filename: str) -> str:
        """Save result as text file"""
        filepath = os.path.join(self.base_dir, f"{filename}.txt")
        with open(filepath, 'w') as f:
            f.write(f"Port Scan Results for {result.target}\n")
            f.write(f"Scan Type: {result.scan_type}\n")
            f.write(f"Start Time: {result.start_time}\n")
            f.write(f"End Time: {result.end_time}\n")
            f.write(f"Duration: {result.get_duration()} seconds\n\n")
            
            f.write("PORT\tSTATE\tSERVICE\tPROTOCOL\n")
            f.write("-" * 40 + "\n")
            for port in result.ports:
                f.write(f"{port.get('port', '')}\t{port.get('state', '')}\t{port.get('service', '')}\t{port.get('protocol', 'TCP')}\n")
        return filepath