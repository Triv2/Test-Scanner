import socket
import re
import ssl
from typing import Dict, Optional, Tuple
import time

from app.core.logger import Logger

class ServiceDetector:
    """Detects services running on open ports"""
    
    # Common service signatures
    SERVICE_SIGNATURES = {
        'http': [b'HTTP', b'<html', b'<!DOCTYPE'],
        'https': [b'HTTP', b'<html', b'<!DOCTYPE'],
        'ssh': [b'SSH', b'OpenSSH'],
        'ftp': [b'220', b'FTP', b'FileZilla'],
        'smtp': [b'220', b'SMTP', b'ESMTP'],
        'pop3': [b'+OK', b'POP3'],
        'imap': [b'* OK', b'IMAP'],
        'telnet': [b'Telnet', b'login:', b'Username:'],
        'mysql': [b'mysql_native_password', b'MariaDB'],
        'rdp': [b'RDP', b'RFB'],
        'vnc': [b'RFB', b'VNC'],
        'dns': [b'DNS'],
        'smb': [b'SMB', b'Samba'],
        'ldap': [b'LDAP'],
        'ntp': [b'NTP'],
        'snmp': [b'SNMP'],
        'redis': [b'REDIS'],
        'mongodb': [b'MongoDB'],
        'postgresql': [b'PostgreSQL']
    }
    
    # Common service probes
    SERVICE_PROBES = {
        'http': b'GET / HTTP/1.0\r\n\r\n',
        'https': b'GET / HTTP/1.0\r\n\r\n',
        'ssh': b'SSH-2.0-OpenSSH_Client\r\n',
        'ftp': b'',  # Just connect
        'smtp': b'EHLO test.com\r\n',
        'pop3': b'',  # Just connect
        'imap': b'A001 CAPABILITY\r\n',
        'telnet': b'',  # Just connect
        'mysql': b'\x03\x00\x00\x00\x0b\x00\x00\x00\x00\x01\x00\x00\x00',  # MySQL handshake
        'redis': b'PING\r\n',
        'mongodb': b'\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x61\x64\x6d\x69\x6e\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x1b\x00\x00\x00\x01\x70\x69\x6e\x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
        'postgresql': b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
    }
    
    def __init__(self):
        self.logger = Logger()
        self.timeout = 3  # Default timeout in seconds
    
    def set_timeout(self, timeout: int):
        """Set the timeout for service detection"""
        self.timeout = timeout
    
    def detect_service(self, ip: str, port: int) -> Dict[str, str]:
        """
        Detect the service running on the specified port
        
        Args:
            ip: Target IP address
            port: Target port number
            
        Returns:
            Dictionary with service information
        """
        result = {
            'service': 'unknown',
            'version': '',
            'banner': '',
            'protocol': 'tcp'
        }
        
        # Try common service detection based on port number first
        common_service = self._detect_by_port(port)
        if common_service:
            result['service'] = common_service
        
        # Try to get banner by connecting to the port
        banner = self._get_banner(ip, port)
        if banner:
            result['banner'] = banner.decode('utf-8', errors='replace').strip()
            
            # Try to identify service from banner
            service = self._identify_from_banner(banner)
            if service:
                result['service'] = service
            
            # Try to extract version information
            version = self._extract_version(banner)
            if version:
                result['version'] = version
        
        # Try specific service probes for better identification
        identified_service = self._probe_service(ip, port)
        if identified_service:
            result['service'] = identified_service
        
        # Special case for SSL/TLS services
        if port in [443, 8443] or result['service'] == 'https':
            ssl_info = self._get_ssl_info(ip, port)
            if ssl_info:
                result['service'] = 'https'
                result['ssl_version'] = ssl_info.get('version', '')
                result['ssl_issuer'] = ssl_info.get('issuer', '')
                result['ssl_subject'] = ssl_info.get('subject', '')
        
        return result
    
    def _detect_by_port(self, port: int) -> str:
        """Detect service based on common port numbers"""
        common_ports = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            445: 'smb',
            1433: 'mssql',
            1521: 'oracle',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            6379: 'redis',
            8080: 'http-proxy',
            8443: 'https-alt',
            27017: 'mongodb'
        }
        return common_ports.get(port, '')
    
    def _get_banner(self, ip: str, port: int) -> Optional[bytes]:
        """Get service banner by connecting to the port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                
                # Some services need a prompt
                if port in [80, 443, 8080, 8443]:
                    s.send(b'GET / HTTP/1.0\r\n\r\n')
                elif port == 25 or port == 587:
                    s.send(b'EHLO test.com\r\n')
                elif port == 110:
                    s.send(b'USER test\r\n')
                
                # Wait a moment for response
                time.sleep(0.5)
                
                # Try to receive data
                banner = b''
                s.settimeout(1)
                try:
                    while True:
                        data = s.recv(1024)
                        if not data:
                            break
                        banner += data
                        if len(banner) > 4096:  # Limit banner size
                            break
                except socket.timeout:
                    pass
                
                return banner
        except Exception as e:
            self.logger.debug(f"Error getting banner for {ip}:{port}: {str(e)}")
            return None
    
    def _identify_from_banner(self, banner: bytes) -> str:
        """Identify service from banner"""
        banner_lower = banner.lower()
        
        for service, signatures in self.SERVICE_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in banner_lower:
                    return service
        
        return ''
    
    def _extract_version(self, banner: bytes) -> str:
        """Extract version information from banner"""
        try:
            # Convert to string for regex
            banner_str = banner.decode('utf-8', errors='replace')
            
            # Common version patterns
            patterns = [
                r'(?i)Server: ([^\r\n]+)',
                r'(?i)Version: ([^\r\n]+)',
                r'(?i)OpenSSH_([^\s]+)',
                r'(?i)Apache/([^\s]+)',
                r'(?i)nginx/([^\s]+)',
                r'(?i)Microsoft-IIS/([^\s]+)',
                r'(?i)MySQL ([^\s]+)',
                r'(?i)PostgreSQL ([^\s]+)',
                r'(?i)SSH-2.0-([^\r\n]+)',
                r'(?i)220 ([^\r\n]+) FTP'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, banner_str)
                if match:
                    return match.group(1).strip()
        except Exception as e:
            self.logger.debug(f"Error extracting version: {str(e)}")
        
        return ''
    
    def _probe_service(self, ip: str, port: int) -> str:
        """Send specific probes to identify services"""
        for service, probe in self.SERVICE_PROBES.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    s.connect((ip, port))
                    
                    if probe:  # Send probe if not empty
                        s.send(probe)
                    
                    # Wait for response
                    time.sleep(0.5)
                    
                    try:
                        s.settimeout(1)
                        response = s.recv(1024)
                        
                        # Check if response matches service signatures
                        if service in self.SERVICE_SIGNATURES:
                            for signature in self.SERVICE_SIGNATURES[service]:
                                if signature.lower() in response.lower():
                                    return service
                    except socket.timeout:
                        pass
            except Exception:
                pass
        
        return ''
    
    def _get_ssl_info(self, ip: str, port: int) -> Dict[str, str]:
        """Get SSL/TLS certificate information"""
        result = {}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    if not cert:
                        return {}
                    
                    x509 = ssl.DER_cert_to_PEM_cert(cert)
                    result['version'] = ssock.version()
                    
                    # Extract certificate information
                    if hasattr(ssock, 'getpeercert') and callable(getattr(ssock, 'getpeercert')):
                        cert_dict = ssock.getpeercert()
                        if cert_dict:
                            # Extract subject
                            if 'subject' in cert_dict:
                                subject_parts = []
                                for part in cert_dict['subject']:
                                    for key, value in part:
                                        if key == 'commonName':
                                            subject_parts.append(f"CN={value}")
                                result['subject'] = ', '.join(subject_parts)
                            
                            # Extract issuer
                            if 'issuer' in cert_dict:
                                issuer_parts = []
                                for part in cert_dict['issuer']:
                                    for key, value in part:
                                        if key == 'commonName':
                                            issuer_parts.append(f"CN={value}")
                                        elif key == 'organizationName':
                                            issuer_parts.append(f"O={value}")
                                result['issuer'] = ', '.join(issuer_parts)
                            
                            # Extract validity dates
                            if 'notBefore' in cert_dict:
                                result['valid_from'] = cert_dict['notBefore']
                            if 'notAfter' in cert_dict:
                                result['valid_until'] = cert_dict['notAfter']
        except Exception as e:
            self.logger.debug(f"Error getting SSL info for {ip}:{port}: {str(e)}")
        
        return result

    def get_http_headers(self, ip: str, port: int, use_ssl: bool = False) -> Dict[str, str]:
        """Get HTTP headers from a web server"""
        headers = {}
        try:
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        ssock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
                        response = b""
                        
                        while True:
                            chunk = ssock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    s.connect((ip, port))
                    s.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
                    
                    response = b""
                    s.settimeout(2)
                    try:
                        while True:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                    except socket.timeout:
                        pass
            
            # Parse headers
            if response:
                header_text = response.split(b'\r\n\r\n')[0].decode('utf-8', errors='replace')
                header_lines = header_text.split('\r\n')
                
                # Skip the first line (HTTP status line)
                for line in header_lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key.strip()] = value.strip()
        
        except Exception as e:
            self.logger.debug(f"Error getting HTTP headers for {ip}:{port}: {str(e)}")
        
        return headers
    
    def detect_web_technology(self, ip: str, port: int) -> Dict[str, str]:
        """Detect web technologies used by a web server"""
        result = {}
        
        # Determine if we should use SSL
        use_ssl = port in [443, 8443] or self._detect_by_port(port) == 'https'
        
        # Get HTTP headers
        headers = self.get_http_headers(ip, port, use_ssl)
        
        # Check for server header
        if 'Server' in headers:
            result['server'] = headers['Server']
        
        # Check for common web frameworks and technologies
        if 'X-Powered-By' in headers:
            result['powered_by'] = headers['X-Powered-By']
        
        # Get content to analyze
        content = self._get_web_content(ip, port, use_ssl)
        if content:
            # Check for common web technologies
            technologies = self._identify_web_technologies(content)
            if technologies:
                result['technologies'] = technologies
        
        return result
    
    def _get_web_content(self, ip: str, port: int, use_ssl: bool = False) -> str:
        """Get web content from a server"""
        try:
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        ssock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
                        response = b""
                        
                        while True:
                            chunk = ssock.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                            if len(response) > 100000:  # Limit response size
                                break
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    s.connect((ip, port))
                    s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
                    
                    response = b""
                    s.settimeout(2)
                    try:
                        while True:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            response += chunk
                            if len(response) > 100000:  # Limit response size
                                break
                    except socket.timeout:
                        pass
            
            # Extract body content
            if b'\r\n\r\n' in response:
                body = response.split(b'\r\n\r\n', 1)[1]
                return body.decode('utf-8', errors='replace')
            
            return ""
        
        except Exception as e:
            self.logger.debug(f"Error getting web content for {ip}:{port}: {str(e)}")
            return ""
    
    def _identify_web_technologies(self, content: str) -> Dict[str, str]:
        """Identify web technologies from content"""
        technologies = {}
        
        # Check for common web technologies
        tech_signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'WordPress'],
            'Joomla': ['joomla', 'Joomla'],
            'Drupal': ['Drupal.settings', 'drupal'],
            'Bootstrap': ['bootstrap.css', 'bootstrap.min.css', 'bootstrap.js'],
            'jQuery': ['jquery.js', 'jquery.min.js', 'jQuery'],
            'React': ['react.js', 'react-dom.js', 'react.production.min.js'],
            'Angular': ['angular.js', 'ng-app', 'ng-controller'],
            'Vue.js': ['vue.js', 'vue.min.js'],
            'Laravel': ['laravel', 'Laravel'],
            'Django': ['django', 'csrftoken'],
            'ASP.NET': ['__VIEWSTATE', 'ASP.NET'],
            'PHP': ['php', 'PHP'],
            'Node.js': ['node_modules', 'Express'],
            'Apache': ['apache', 'Apache'],
            'Nginx': ['nginx', 'Nginx'],
            'IIS': ['IIS', 'Microsoft-IIS']
        }
        
        for tech, signatures in tech_signatures.items():
            for signature in signatures:
                if signature.lower() in content.lower():
                    technologies[tech] = True
                    break
        
        return technologies