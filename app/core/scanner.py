# app/core/scanner.py
import socket
import threading
import queue
from typing import List, Dict, Any

class PortScanner:
    def __init__(self, timeout=5, max_threads=10):
        self.timeout = timeout
        self.max_threads = max_threads
        self.stop_flag = threading.Event()
        
    def scan_port(self, host: str, port: int) -> Dict[str, Any]:
        """Scan a single port on the specified host"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                # Try to get service name
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                    
                return {
                    "port": port,
                    "state": "open",
                    "service": service
                }
            else:
                return {
                    "port": port,
                    "state": "closed",
                    "service": ""
                }
        except Exception as e:
            return {
                "port": port,
                "state": "error",
                "service": "",
                "error": str(e)
            }
            
    def scan_host(self, host: str, ports: List[int], callback=None) -> List[Dict[str, Any]]:
        """Scan multiple ports on a host using multiple threads"""
        results = []
        port_queue = queue.Queue()
        result_lock = threading.Lock()
        self.stop_flag.clear()
        
        # Fill the queue with ports to scan
        for port in ports:
            port_queue.put(port)
            
        def worker():
            while not port_queue.empty() and not self.stop_flag.is_set():
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
        threads = []
        for _ in range(min(self.max_threads, len(ports))):
            thread = threading.Thread(target=worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
            
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
            
        return results
        
    def stop_scan(self):
        """Stop an ongoing scan"""
        self.stop_flag.set()