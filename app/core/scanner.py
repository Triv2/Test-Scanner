import socket
import threading
import queue
import nmap
from typing import List, Dict, Any, Callable

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.stop_scan = False
        
    def scan_port(self, host: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
        """Scan a single port on a host."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            status = "Open" if result == 0 else "Closed"
            return {"host": host, "port": port, "status": status}
        except socket.gaierror:
            return {"host": host, "port": port, "status": "Error: Host not found"}
        except socket.error:
            return {"host": host, "port": port, "status": "Error: Socket error"}
            
    def scan_range(self, host: str, start_port: int, end_port: int, 
                  callback: Callable = None, threads: int = 100) -> List[Dict[str, Any]]:
        """Scan a range of ports using multiple threads."""
        port_queue = queue.Queue()
        results = []
        result_lock = threading.Lock()
        self.stop_scan = False
        
        # Fill queue with ports
        for port in range(start_port, end_port + 1):
            port_queue.put(port)
            
        def worker():
            while not port_queue.empty() and not self.stop_scan:
                try:
                    port = port_queue.get(block=False)
                    result = self.scan_port(host, port)
                    
                    with result_lock:
                        results.append(result)
                        
                    if callback:
                        callback(result)
                        
                    port_queue.task_done()
                except queue.Empty:
                    break
        
        # Start worker threads
        thread_list = []
        for _ in range(min(threads, end_port - start_port + 1)):
            t = threading.Thread(target=worker)
            t.daemon = True
            t.start()
            thread_list.append(t)
            
        # Wait for all threads to complete
        for t in thread_list:
            t.join()
            
        return results
    
    def advanced_scan(self, host: str, ports: str, scan_type: str = "-sS") -> Dict[str, Any]:
        """Perform advanced scan using nmap."""
        try:
            self.nm.scan(hosts=host, ports=ports, arguments=scan_type)
            return self.nm[host]
        except Exception as e:
            return {"error": str(e)}
            
    def stop_scanning(self):
        """Stop any ongoing scan."""
        self.stop_scan = True