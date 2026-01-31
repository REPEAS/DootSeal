# ==============================================================================
# PROJECT  : DOOTSEAL (Quantum Omega - v8.1)  
# AUTHOR   : Dootmas
# VERSION  : 8.0
# ==============================================================================
# [!] DOOTMAS INTEGRITY SHIELD ACTIVE
# [!] LEGAL: Authorized Auditing Only. Don't be a "Bad Boy". :3
# ==============================================================================
#!/usr/bin/env python3
"""
DOOTSEAL v8.1 - COMPLETE OPERATIONAL FRAMEWORK
WITH MAC VENDOR DB & SERVICE PROBING DATABASE
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import threading
import os
import sys
import subprocess
import socket
import json
import time
import hashlib
import base64
import random
import string
import re
import csv
import ipaddress
import ssl
import urllib.request
import urllib.parse
import http.client
from datetime import datetime, timedelta
import zipfile
import tempfile
import shutil
import struct
import binascii
import select
import ssl
import concurrent.futures
import queue
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any
import http.client

# Try to import optional libraries
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

# ============================================================================
# ADVANCED MAC ADDRESS VENDOR LOOKUP
# ============================================================================
class AdvancedMACVendorLookup:
    """Advanced MAC address vendor lookup using multiple databases"""
    
    def __init__(self, manuf_file="manuf.json", 
                 mac_prefixes_file="mac-prefixes.json",
                 auto_update=True):
        self.vendor_db = {}
        self.alias_db = {}
        self.stats = {'total_entries': 0, 'manuf_entries': 0, 'prefix_entries': 0}
        
        # Load all databases
        self._load_manuf_database(manuf_file)
        self._load_mac_prefixes_file(mac_prefixes_file)
        self._build_alias_database()
        
        print(f"[+] MAC Vendor DB: {self.stats['total_entries']:,} total entries")
        print(f"    - manuf.json: {self.stats['manuf_entries']:,} entries")
        print(f"    - mac-prefixes.json: {self.stats['prefix_entries']:,} entries")
    
    def _load_manuf_database(self, manuf_file):
        """Load MAC vendor database from manuf.json format"""
        try:
            if os.path.exists(manuf_file):
                with open(manuf_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines_loaded = 0
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        
                        # Skip comments and empty lines
                        if not line or line.startswith('#'):
                            continue
                        
                        # Parse the manuf format: MAC_PREFIX<TAB>SHORT_NAME<TAB>FULL_NAME
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            mac_prefix = parts[0].strip().upper()
                            short_name = parts[1].strip()
                            full_name = parts[2].strip() if len(parts) > 2 else short_name
                            
                            # Clean MAC prefix (remove :, -, etc)
                            clean_prefix = self._normalize_mac_prefix(mac_prefix)
                            
                            # Handle prefixes with netmasks (e.g., 00:00:00/24)
                            if '/' in clean_prefix:
                                base_prefix, mask = clean_prefix.split('/')
                                clean_prefix = base_prefix[:int(mask)//4]
                            else:
                                clean_prefix = clean_prefix[:6]
                            
                            if clean_prefix:
                                self.vendor_db[clean_prefix] = {
                                    'short': short_name[:30],
                                    'full': full_name[:100],
                                    'notes': parts[3] if len(parts) > 3 else '',
                                    'source': 'manuf.json',
                                    'line': line_num
                                }
                                lines_loaded += 1
                    
                    self.stats['manuf_entries'] = lines_loaded
                    self.stats['total_entries'] += lines_loaded
                    
            else:
                print(f"[!] manuf.json not found at {manuf_file}")
                
        except Exception as e:
            print(f"[!] Error loading manuf.json: {e}")
    
    def _load_mac_prefixes_file(self, mac_prefixes_file):
        """Load MAC vendor database from mac-prefixes.json format (nmap style)"""
        try:
            if os.path.exists(mac_prefixes_file):
                entries_loaded = 0
                with open(mac_prefixes_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        
                        # Skip comments and empty lines
                        if not line or line.startswith('#'):
                            continue
                        
                        # Parse nmap format: PREFIX VENDOR_NAME
                        parts = line.split(maxsplit=1)
                        if len(parts) >= 2:
                            prefix = parts[0].strip().upper()
                            vendor_name = parts[1].strip()
                            
                            # Clean prefix (6 hex chars)
                            clean_prefix = self._normalize_mac_prefix(prefix)
                            if len(clean_prefix) < 6:
                                clean_prefix = clean_prefix.ljust(6, '0')[:6]
                            else:
                                clean_prefix = clean_prefix[:6]
                            
                            # Only add if not already in database
                            if clean_prefix and clean_prefix not in self.vendor_db:
                                self.vendor_db[clean_prefix] = {
                                    'short': vendor_name[:30],
                                    'full': vendor_name[:100],
                                    'notes': '',
                                    'source': 'mac-prefixes.json'
                                }
                                entries_loaded += 1
                
                self.stats['prefix_entries'] = entries_loaded
                self.stats['total_entries'] += entries_loaded
                
            else:
                print(f"[!] mac-prefixes.json not found at {mac_prefixes_file}")
                
        except Exception as e:
            print(f"[!] Error loading mac-prefixes.json: {e}")
    
    def _build_alias_database(self):
        """Build alias database for common vendor name variations"""
        common_aliases = {
            'Cisco Systems': ['Cisco', 'Cisco Sys', 'Cisco Systems Inc'],
            'Intel': ['Intel Corp', 'Intel Corporation'],
            'Apple': ['Apple Inc', 'Apple Computer'],
            'Samsung': ['Samsung Electronics', 'Samsung Elec'],
            'Hewlett Packard': ['HP', 'Hewlett-Packard', 'HP Inc'],
            'Microsoft': ['Microsoft Corp', 'MSFT'],
            'Dell': ['Dell Inc', 'Dell Computer'],
            'ASUS': ['ASUSTeK', 'ASUSTEK COMPUTER INC'],
            'TP-Link': ['TP-LINK', 'TPLink', 'TP LINK'],
        }
        
        for main_name, aliases in common_aliases.items():
            for alias in aliases:
                self.alias_db[alias.upper()] = main_name
    
    def _normalize_mac_prefix(self, mac_prefix: str) -> str:
        """Normalize MAC prefix by removing separators and converting to uppercase"""
        return re.sub(r'[^a-fA-F0-9]', '', mac_prefix).upper()
    
    def normalize_mac(self, mac_address: str) -> str:
        """Normalize MAC address to standard format"""
        mac = re.sub(r'[^a-fA-F0-9]', '', mac_address).upper()
        
        # Add colons for display (XX:XX:XX:XX:XX:XX)
        if len(mac) == 12:
            return ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        return mac
    
    def get_vendor(self, mac_address: str) -> Dict[str, Any]:
        """Get complete vendor information from MAC address"""
        mac = self._normalize_mac_prefix(mac_address)
        original_mac = mac_address
        
        if len(mac) < 6:
            return {
                'vendor': 'Invalid MAC',
                'short': 'Invalid',
                'full': 'Invalid MAC Address',
                'confidence': 0,
                'mac': self.normalize_mac(original_mac),
                'original': original_mac,
                'source': 'none'
            }
        
        # Try different prefix lengths in order of specificity
        test_prefixes = [
            mac[:9],  # OUI-36 (most specific)
            mac[:7],  # CID
            mac[:6],  # Standard OUI (most common)
            mac[:5],  # Sometimes used
        ]
        
        for prefix in test_prefixes:
            if prefix in self.vendor_db:
                vendor_info = self.vendor_db[prefix].copy()
                
                # Calculate confidence based on prefix length
                confidence = min(100, len(prefix) * 15)
                
                # Check for aliases
                full_name = vendor_info['full'].upper()
                if full_name in self.alias_db:
                    vendor_info['full'] = self.alias_db[full_name]
                
                return {
                    'vendor': vendor_info['short'],
                    'short': vendor_info['short'],
                    'full': vendor_info['full'],
                    'notes': vendor_info.get('notes', ''),
                    'confidence': confidence,
                    'mac': self.normalize_mac(original_mac),
                    'original': original_mac,
                    'source': vendor_info.get('source', 'unknown'),
                    'prefix_length': len(prefix)
                }
        
        # Check for special MAC addresses
        special_macs = {
            '000000': 'Xerox',
            'FFFFFF': 'Broadcast',
            '01005E': 'IPv4 Multicast',
            '333300': 'IPv6 Multicast',
            '555555': 'Invalid/Test',
        }
        
        for prefix, vendor in special_macs.items():
            if mac.startswith(prefix):
                return {
                    'vendor': vendor,
                    'short': vendor,
                    'full': f'{vendor} (Special Address)',
                    'confidence': 100,
                    'mac': self.normalize_mac(original_mac),
                    'original': original_mac,
                    'source': 'special',
                    'prefix_length': len(prefix)
                }
        
        # Check for locally administered MAC
        second_byte = mac[1:2] if len(mac) > 1 else ''
        if second_byte in ['2', '3', '6', '7', 'A', 'B', 'E', 'F']:
            return {
                'vendor': 'Locally Administered',
                'short': 'Local',
                'full': 'Locally Administered MAC Address',
                'confidence': 100,
                'mac': self.normalize_mac(original_mac),
                'original': original_mac,
                'source': 'local',
                'prefix_length': 0
            }
        
        # Check for multicast MAC
        if mac[1:2] in ['1', '3', '5', '7', '9', 'B', 'D', 'F']:
            return {
                'vendor': 'Multicast',
                'short': 'Multicast',
                'full': 'Multicast MAC Address',
                'confidence': 100,
                'mac': self.normalize_mac(original_mac),
                'original': original_mac,
                'source': 'multicast',
                'prefix_length': 0
            }
        
        # Unknown vendor
        return {
            'vendor': 'Unknown',
            'short': 'Unknown',
            'full': 'Unknown Vendor',
            'confidence': 0,
            'mac': self.normalize_mac(original_mac),
            'original': original_mac,
            'source': 'none',
            'prefix_length': 0
        }
    
    def lookup(self, mac_address: str, detailed=False) -> Any:
        """Simple or detailed lookup"""
        if detailed:
            return self.get_vendor(mac_address)
        else:
            result = self.get_vendor(mac_address)
            return result['full']
    
    def batch_lookup(self, mac_list: List[str]) -> Dict[str, Dict[str, Any]]:
        """Lookup multiple MAC addresses efficiently"""
        results = {}
        for mac in mac_list:
            results[mac] = self.get_vendor(mac)
        return results
    
    def search_vendor(self, search_term: str) -> List[Dict[str, Any]]:
        """Search for vendors by name"""
        search_term = search_term.upper()
        results = []
        
        for prefix, vendor_info in self.vendor_db.items():
            if (search_term in vendor_info['short'].upper() or 
                search_term in vendor_info['full'].upper() or
                search_term in vendor_info.get('notes', '').upper()):
                
                results.append({
                    'prefix': ':'.join(prefix[i:i+2] for i in range(0, len(prefix), 2)) if len(prefix) >= 6 else prefix,
                    'short': vendor_info['short'],
                    'full': vendor_info['full'],
                    'source': vendor_info.get('source', 'unknown')
                })
        
        return sorted(results, key=lambda x: x['short'])[:50]

# ============================================================================
# ADVANCED SERVICE PROBING DATABASE
# ============================================================================
class AdvancedServiceProber:
    """Advanced service version detection and probing"""
    
    def __init__(self, probes_file="service-probes.json"):
        self.probes = {}
        self.port_map = defaultdict(list)
        self.default_timeout = 3
        
        # First try to load from file, if not found or invalid, create default
        if os.path.exists(probes_file):
            try:
                with open(probes_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if content:
                        custom_probes = json.loads(content)
                        self._initialize_probes(custom_probes)
                        print(f"[+] Service Prober: Loaded from {probes_file}")
                    else:
                        print(f"[!] {probes_file} is empty, using built-in probes")
                        self._initialize_probes({})
            except json.JSONDecodeError as e:
                print(f"[!] Error parsing {probes_file}: {e}")
                print(f"[+] Creating default service-probes.json file")
                self._create_default_probes_file(probes_file)
                self._initialize_probes({})
            except Exception as e:
                print(f"[!] Error loading {probes_file}: {e}")
                self._initialize_probes({})
        else:
            print(f"[!] {probes_file} not found, creating default")
            self._create_default_probes_file(probes_file)
            self._initialize_probes({})
        
        print(f"[+] Service Prober: {len(self.probes)} probes loaded")
    
    def _create_default_probes_file(self, probes_file):
        """Create default service-probes.json file"""
        default_probes = {
            "http": {
                "ports": [80, 8080, 8000, 8888],
                "ssl_ports": [443, 8443],
                "probe": "GET / HTTP/1.1\\r\\nHost: localhost\\r\\nUser-Agent: DOOTSEAL/8.1\\r\\nAccept: */*\\r\\n\\r\\n",
                "patterns": {
                    "Apache": ["Apache", "apache", "Server: Apache"],
                    "Nginx": ["nginx", "NGINX", "Server: nginx"],
                    "IIS": ["Microsoft-IIS", "IIS", "Server: Microsoft-IIS"],
                    "Lighttpd": ["lighttpd", "Server: lighttpd"],
                    "Tomcat": ["Apache-Coyote", "Tomcat", "Server: Apache Tomcat"]
                },
                "default_ssl": False
            },
            "ssh": {
                "ports": [22],
                "probe": "SSH-2.0-DOOTSEAL_Client\\r\\n",
                "patterns": {
                    "OpenSSH": ["OpenSSH", "SSH-2.0-OpenSSH"],
                    "Dropbear": ["dropbear", "SSH-2.0-dropbear"]
                }
            },
            "ftp": {
                "ports": [21, 2121],
                "probe": "",
                "patterns": {
                    "vsFTPd": ["vsFTPd", "220 vsFTPd"],
                    "ProFTPD": ["ProFTPD", "220 ProFTPD"]
                },
                "banner_grab": True
            },
            "smtp": {
                "ports": [25, 587, 465],
                "probe": "EHLO localhost\\r\\n",
                "patterns": {
                    "Postfix": ["Postfix", "220 .* ESMTP Postfix"],
                    "Exim": ["Exim", "220 .* ESMTP Exim"]
                }
            },
            "mysql": {
                "ports": [3306],
                "probe": "\\x0a\\x00\\x00\\x01\\x85\\xa6\\x03\\x00\\x00\\x00\\x00\\x01\\x21\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00",
                "patterns": {
                    "MySQL": ["mysql", "MySQL"],
                    "MariaDB": ["mariadb", "MariaDB"]
                }
            }
        }
        
        try:
            with open(probes_file, 'w') as f:
                json.dump(default_probes, f, indent=2, sort_keys=True)
            print(f"[+] Created default {probes_file}")
        except Exception as e:
            print(f"[!] Error creating {probes_file}: {e}")
    
    def _initialize_probes(self, custom_probes):
        """Initialize probes with defaults and custom ones"""
        # Default probes
        default_probes = {
            "http": {
                "ports": [80, 8080, 8000, 8888],
                "ssl_ports": [443, 8443],
                "probe": b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: DOOTSEAL/8.1\r\nAccept: */*\r\n\r\n",
                "patterns": {
                    "Apache": [b"Apache", b"apache", b"Server: Apache"],
                    "Nginx": [b"nginx", b"NGINX", b"Server: nginx"],
                    "IIS": [b"Microsoft-IIS", b"IIS", b"Server: Microsoft-IIS"],
                    "Lighttpd": [b"lighttpd", b"Server: lighttpd"],
                    "Tomcat": [b"Apache-Coyote", b"Tomcat", b"Server: Apache Tomcat"],
                    "Node.js": [b"X-Powered-By: Express", b"Server: Node.js"],
                    "WordPress": [b"wp-", b"wordpress", b"WordPress"],
                    "Joomla": [b"joomla", b"Joomla"],
                    "Drupal": [b"Drupal", b"drupal"]
                },
                "default_ssl": False
            },
            "ssh": {
                "ports": [22],
                "probe": b"SSH-2.0-DOOTSEAL_Client\r\n",
                "patterns": {
                    "OpenSSH": [b"OpenSSH", b"SSH-2.0-OpenSSH"],
                    "Dropbear": [b"dropbear", b"SSH-2.0-dropbear"],
                    "Cisco SSH": [b"cisco", b"Cisco"],
                    "PuTTY": [b"PuTTY", b"SSH-2.0-PuTTY"]
                }
            },
            "ftp": {
                "ports": [21, 2121],
                "probe": b"",
                "patterns": {
                    "vsFTPd": [b"vsFTPd", b"220 vsFTPd"],
                    "ProFTPD": [b"ProFTPD", b"220 ProFTPD"],
                    "Pure-FTPd": [b"Pure-FTPd", b"220----------"],
                    "FileZilla": [b"FileZilla", b"220 FileZilla"]
                },
                "banner_grab": True
            },
            "smtp": {
                "ports": [25, 587, 465],
                "probe": b"EHLO localhost\r\n",
                "patterns": {
                    "Postfix": [b"Postfix", b"220 .* ESMTP Postfix"],
                    "Exim": [b"Exim", b"220 .* ESMTP Exim"],
                    "Microsoft Exchange": [b"Microsoft ESMTP", b"220 .* Microsoft ESMTP"],
                    "Sendmail": [b"Sendmail", b"220 .* ESMTP Sendmail"]
                }
            },
            "mysql": {
                "ports": [3306],
                "probe": b"\x0a\x00\x00\x01\x85\xa6\x03\x00\x00\x00\x00\x01\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "patterns": {
                    "MySQL": [b"mysql", b"MySQL"],
                    "MariaDB": [b"mariadb", b"MariaDB"]
                }
            }
        }
        
        # Merge custom probes with defaults
        for service, config in custom_probes.items():
            if service in default_probes:
                # Convert string probes to bytes
                if 'probe' in config and isinstance(config['probe'], str):
                    config['probe'] = config['probe'].encode('utf-8')
                
                # Convert string patterns to bytes
                if 'patterns' in config:
                    for pattern_name, pattern_list in config['patterns'].items():
                        if isinstance(pattern_list, list):
                            config['patterns'][pattern_name] = [p.encode('utf-8') if isinstance(p, str) else p for p in pattern_list]
                
                default_probes[service].update(config)
            else:
                default_probes[service] = config
        
        # Store probes and build port mapping
        self.probes = default_probes
        for service, config in self.probes.items():
            for port in config.get('ports', []):
                self.port_map[port].append(service)
            for port in config.get('ssl_ports', []):
                self.port_map[port].append(f"{service}_ssl")
    
    def guess_service_by_port(self, port: int) -> List[str]:
        """Guess possible services by port number"""
        return self.port_map.get(port, [f"unknown_port_{port}"])
    
    def probe_service(self, host: str, port: int, service_type: str = None) -> Dict[str, Any]:
        """Probe a service for detailed information"""
        result = {
            'host': host,
            'port': port,
            'service': 'unknown',
            'version': 'unknown',
            'banner': '',
            'ssl': False,
            'detected': [],
            'probe_time': datetime.now().isoformat(),
            'success': False
        }
        
        # Determine service type if not specified
        if not service_type:
            possible_services = self.guess_service_by_port(port)
            service_type = possible_services[0].replace('_ssl', '') if possible_services else 'http'
        
        # Check if service is in our database
        if service_type not in self.probes:
            return self._generic_banner_grab(host, port)
        
        probe_config = self.probes[service_type]
        
        # Check if this is an SSL port
        ssl_ports = probe_config.get('ssl_ports', [])
        use_ssl = port in ssl_ports or probe_config.get('default_ssl', False)
        
        try:
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=self.default_timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        response = self._send_probe(ssock, probe_config)
                        result['ssl'] = True
            else:
                with socket.create_connection((host, port), timeout=self.default_timeout) as sock:
                    response = self._send_probe(sock, probe_config)
            
            if response:
                result['banner'] = response.decode('utf-8', errors='ignore').strip()
                result['success'] = True
                result['service'] = service_type
                
                # Check for patterns
                for version_name, patterns in probe_config.get('patterns', {}).items():
                    for pattern in patterns:
                        if pattern in response:
                            if version_name not in result['detected']:
                                result['detected'].append(version_name)
                
                # Set version based on detections
                if result['detected']:
                    result['version'] = result['detected'][0]
                
                # Additional processing for specific services
                if service_type == 'http':
                    result = self._parse_http_response(result, response)
                elif service_type == 'ssh':
                    result = self._parse_ssh_response(result, response)
                
        except socket.timeout:
            result['error'] = "Connection timeout"
        except ConnectionRefusedError:
            result['error'] = "Connection refused"
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _send_probe(self, sock: socket.socket, probe_config: Dict) -> Optional[bytes]:
        """Send probe and receive response"""
        try:
            probe_data = probe_config.get('probe', b'')
            if probe_data:
                sock.sendall(probe_data)
            
            sock.settimeout(2)
            
            response = b''
            try:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 8192:
                        break
            except socket.timeout:
                pass
            
            if not probe_data and probe_config.get('banner_grab', False):
                time.sleep(0.5)
                try:
                    banner = sock.recv(1024)
                    if banner:
                        response = banner
                except:
                    pass
            
            return response if response else None
            
        except Exception:
            return None
    
    def _generic_banner_grab(self, host: str, port: int) -> Dict[str, Any]:
        """Generic banner grab for unknown services"""
        result = {
            'host': host,
            'port': port,
            'service': 'unknown',
            'version': 'unknown',
            'banner': '',
            'success': False,
            'method': 'generic_banner_grab'
        }
        
        try:
            with socket.create_connection((host, port), timeout=self.default_timeout) as sock:
                sock.settimeout(2)
                
                try:
                    banner = sock.recv(1024)
                    if banner:
                        result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                        result['success'] = True
                        
                        banner_lower = result['banner'].lower()
                        if 'ssh' in banner_lower:
                            result['service'] = 'ssh'
                        elif 'http' in banner_lower:
                            result['service'] = 'http'
                        elif 'smtp' in banner_lower:
                            result['service'] = 'smtp'
                        elif 'ftp' in banner_lower:
                            result['service'] = 'ftp'
                        elif 'mysql' in banner_lower:
                            result['service'] = 'mysql'
                except socket.timeout:
                    result['error'] = "No banner received"
                    
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _parse_http_response(self, result: Dict, response: bytes) -> Dict:
        """Parse HTTP response for additional info"""
        try:
            headers_text = response.decode('utf-8', errors='ignore')
            headers = {}
            
            lines = headers_text.split('\r\n')
            if lines:
                result['status_line'] = lines[0]
                
                for line in lines[1:]:
                    if ': ' in line:
                        key, value = line.split(': ', 1)
                        headers[key.lower()] = value
            
            result['headers'] = headers
            
            if 'server' in headers:
                result['server_header'] = headers['server']
            
            if 'x-powered-by' in headers:
                result['powered_by'] = headers['x-powered-by']
            
            body_start = headers_text.find('\r\n\r\n')
            if body_start != -1:
                body = headers_text[body_start + 4:]
                title_match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE)
                if title_match:
                    result['title'] = title_match.group(1)[:200]
                
        except Exception:
            pass
        
        return result
    
    def _parse_ssh_response(self, result: Dict, response: bytes) -> Dict:
        """Parse SSH response for additional info"""
        try:
            banner = response.decode('utf-8', errors='ignore')
            
            ssh_match = re.search(r'SSH-(\d+\.\d+)-(.+)', banner)
            if ssh_match:
                result['ssh_version'] = ssh_match.group(1)
                result['ssh_software'] = ssh_match.group(2)
                
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', result['ssh_software'])
                if version_match:
                    result['version'] = version_match.group(1)
                    
        except Exception:
            pass
        
        return result
    
    def comprehensive_scan(self, host: str, ports: List[int] = None) -> Dict[str, Any]:
        """Comprehensive service scan on multiple ports"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080]
        
        results = {
            'host': host,
            'scan_start': datetime.now().isoformat(),
            'ports_scanned': len(ports),
            'services': []
        }
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_port = {executor.submit(self.probe_service, host, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    service_result = future.result()
                    results['services'].append(service_result)
                except Exception as e:
                    results['services'].append({
                        'host': host,
                        'port': port,
                        'error': str(e),
                        'success': False
                    })
        
        results['scan_end'] = datetime.now().isoformat()
        results['successful'] = sum(1 for s in results['services'] if s.get('success', False))
        
        return results

# ============================================================================
# ENHANCED CORE SCANNER WITH MAC & SERVICE DATABASES
# ============================================================================
class EnhancedCoreScanner:
    """Enhanced core scanner with MAC vendor and service probing"""
    
    def __init__(self):
        self.mac_lookup = AdvancedMACVendorLookup()
        self.service_prober = AdvancedServiceProber()
        print("[+] Enhanced Core Scanner initialized")
    
    def get_mac_vendor(self, mac_address: str) -> Dict[str, Any]:
        """Get MAC vendor information"""
        return self.mac_lookup.get_vendor(mac_address)
    
    def probe_service(self, host: str, port: int) -> Dict[str, Any]:
        """Probe service with enhanced detection"""
        return self.service_prober.probe_service(host, port)
    
    def comprehensive_service_scan(self, host: str) -> Dict[str, Any]:
        """Comprehensive service scan with enhanced detection"""
        return self.service_prober.comprehensive_scan(host)
    
    def arp_scan_with_vendors(self, network: str) -> List[Dict[str, Any]]:
        """ARP scan with MAC vendor identification"""
        results = []
        
        try:
            if sys.platform == "win32":
                output = subprocess.check_output(["arp", "-a"], text=True)
                for line in output.split('\n'):
                    if network.replace('/24', '') in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            ip = parts[0]
                            mac = parts[1].replace('-', ':')
                            if mac.count(':') == 5:
                                vendor_info = self.get_mac_vendor(mac)
                                results.append({
                                    'ip': ip,
                                    'mac': mac,
                                    'vendor': vendor_info['vendor'],
                                    'vendor_full': vendor_info['full'],
                                    'confidence': vendor_info['confidence']
                                })
            else:
                output = subprocess.check_output(["arp", "-an"], text=True)
                for line in output.split('\n'):
                    if network.replace('/24', '') in line:
                        match = re.search(r'\(([\d\.]+)\) at ([0-9a-f:]+)', line, re.IGNORECASE)
                        if match:
                            ip = match.group(1)
                            mac = match.group(2)
                            vendor_info = self.get_mac_vendor(mac)
                            results.append({
                                'ip': ip,
                                'mac': mac,
                                'vendor': vendor_info['vendor'],
                                'vendor_full': vendor_info['full'],
                                'confidence': vendor_info['confidence']
                            })
            
        except Exception as e:
            print(f"[!] ARP scan error: {e}")
            results = self._ping_sweep_with_vendors(network)
        
        return results
    
    def _ping_sweep_with_vendors(self, network: str) -> List[Dict[str, Any]]:
        """Ping sweep with placeholder for MAC (simulated)"""
        results = []
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = list(net.hosts())[:50]
            
            def check_host(ip):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((str(ip), 80))
                    sock.close()
                    
                    if result == 0:
                        ip_parts = str(ip).split('.')
                        simulated_mac = f"00:16:3e:{ip_parts[1]}:{ip_parts[2]}:{ip_parts[3]}"
                        vendor_info = self.get_mac_vendor(simulated_mac)
                        
                        return {
                            'ip': str(ip),
                            'mac': simulated_mac,
                            'vendor': vendor_info['vendor'],
                            'vendor_full': vendor_info['full'],
                            'confidence': vendor_info['confidence'],
                            'simulated_mac': True
                        }
                except:
                    pass
                return None
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(check_host, ip) for ip in hosts]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                        
        except Exception as e:
            print(f"[!] Ping sweep error: {e}")
        
        return results
    
    def network_device_discovery(self, network: str) -> Dict[str, Any]:
        """Complete network device discovery with vendors and services"""
        result = {
            'network': network,
            'scan_time': datetime.now().isoformat(),
            'devices': [],
            'statistics': {
                'total_devices': 0,
                'by_vendor': defaultdict(int),
                'open_ports': 0,
                'unique_services': set()
            }
        }
        
        devices = self.arp_scan_with_vendors(network)
        
        for device in devices:
            if not device.get('simulated_mac', False):
                services = self.service_prober.comprehensive_scan(device['ip'], [22, 80, 443, 3389])
                device['services'] = services.get('services', [])
                
                for service in device['services']:
                    if service.get('success', False):
                        result['statistics']['open_ports'] += 1
                        result['statistics']['unique_services'].add(service.get('service', 'unknown'))
            
            device['discovery_time'] = datetime.now().isoformat()
            result['devices'].append(device)
            
            vendor = device.get('vendor', 'Unknown')
            result['statistics']['by_vendor'][vendor] += 1
        
        result['statistics']['total_devices'] = len(result['devices'])
        result['statistics']['unique_services'] = list(result['statistics']['unique_services'])
        
        return result

# ============================================================================
# NETWORK SCANNER COMPLETE - UPDATED WITH NEW FEATURES
# ============================================================================
class NetworkScannerComplete:
    """Complete network scanner with enhanced features"""
    
    def __init__(self):
        self.enhanced_core = EnhancedCoreScanner()
        self.nmap_available = NMAP_AVAILABLE
        if self.nmap_available:
            self.nm = nmap.PortScanner()
    
    def comprehensive_scan(self, target: str) -> Dict[str, Any]:
        """Complete network assessment with enhanced features"""
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'phases': {},
            'warnings': []
        }
        
        results['phases']['host_discovery'] = self.enhanced_host_discovery(target)
        
        live_hosts = results['phases']['host_discovery'].get('live_hosts', [])
        if live_hosts:
            host = live_hosts[0]
            results['phases']['port_scanning'] = self.enhanced_port_scanning(host)
        
        if 'port_scanning' in results['phases']:
            results['phases']['service_detection'] = self.enhanced_service_detection(
                target,
                results['phases']['port_scanning'].get('open_ports', [])
            )
        
        if self._is_private_ip(target):
            network = target.rsplit('.', 1)[0] + '.0/24'
            results['phases']['device_discovery'] = self.enhanced_core.network_device_discovery(network)
        
        results['phases']['vulnerability_assessment'] = self.vulnerability_assessment(results)
        
        return results
    
    def enhanced_host_discovery(self, target: str) -> Dict[str, Any]:
        """Host discovery with MAC vendor information"""
        discovery = {
            'techniques': [],
            'live_hosts': [],
            'devices': [],
            'mac_vendors': set(),
            'scan_time': datetime.now().isoformat()
        }
        
        try:
            discovery['techniques'].append('ICMP Ping')
            if self._ping_host(target):
                discovery['live_hosts'].append(target)
            
            discovery['techniques'].append('TCP Port Check')
            ports = [80, 443, 22, 21]
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if sock.connect_ex((target, port)) == 0:
                        if target not in discovery['live_hosts']:
                            discovery['live_hosts'].append(target)
                        sock.close()
                        break
                    sock.close()
                except:
                    pass
            
            if self._is_private_ip(target):
                discovery['techniques'].append('ARP Scan with MAC Vendors')
                network = target.rsplit('.', 1)[0] + '.0/24'
                devices = self.enhanced_core.arp_scan_with_vendors(network)
                discovery['devices'] = devices
                
                for device in devices:
                    vendor = device.get('vendor_full', 'Unknown')
                    if vendor:
                        discovery['mac_vendors'].add(vendor)
                
                discovery['mac_vendors'] = list(discovery['mac_vendors'])
        
        except Exception as e:
            discovery['error'] = str(e)
        
        return discovery
    
    def enhanced_port_scanning(self, host: str) -> Dict[str, Any]:
        """Port scanning with service guessing"""
        port_scan = {
            'host': host,
            'scan_time': datetime.now().isoformat(),
            'method': 'Enhanced TCP Scan with Service Guessing'
        }
        
        common_ports = [
            (21, 'FTP'), (22, 'SSH'), (23, 'Telnet'), (25, 'SMTP'),
            (53, 'DNS'), (80, 'HTTP'), (110, 'POP3'), (143, 'IMAP'),
            (443, 'HTTPS'), (445, 'SMB'), (3306, 'MySQL'),
            (3389, 'RDP'), (5900, 'VNC'), (8080, 'HTTP Proxy'),
            (8443, 'HTTPS Alt'), (27017, 'MongoDB'), (6379, 'Redis')
        ]
        
        ports_only = [port for port, _ in common_ports]
        
        try:
            scan_results = self.enhanced_core.comprehensive_service_scan(host)
            
            open_ports = []
            service_summary = defaultdict(int)
            
            for service in scan_results.get('services', []):
                if service.get('success', False):
                    port = service['port']
                    service_name = service.get('service', 'unknown')
                    version = service.get('version', 'unknown')
                    
                    open_ports.append({
                        'port': port,
                        'service': service_name,
                        'version': version,
                        'banner': service.get('banner', '')[:100],
                        'ssl': service.get('ssl', False),
                        'detected': service.get('detected', [])
                    })
                    
                    service_summary[service_name] += 1
            
            port_scan['open_ports'] = open_ports
            port_scan['total_scanned'] = len(ports_only)
            port_scan['open_count'] = len(open_ports)
            port_scan['service_summary'] = dict(service_summary)
            
        except Exception as e:
            port_scan['error'] = str(e)
        
        return port_scan
    
    def enhanced_service_detection(self, host: str, ports: List[Dict]) -> Dict[str, Any]:
        """Enhanced service detection with database lookup"""
        services = {
            'host': host,
            'services': [],
            'detection_time': datetime.now().isoformat(),
            'detailed_probes': []
        }
        
        for port_info in ports:
            port = port_info['port']
            
            detailed_result = self.enhanced_core.probe_service(host, port)
            services['detailed_probes'].append(detailed_result)
            
            services['services'].append({
                'port': port,
                'service': detailed_result.get('service', 'unknown'),
                'version': detailed_result.get('version', 'unknown'),
                'banner': detailed_result.get('banner', '')[:200],
                'ssl': detailed_result.get('ssl', False),
                'detected_software': detailed_result.get('detected', []),
                'success': detailed_result.get('success', False)
            })
        
        return services
    
    def vulnerability_assessment(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced vulnerability assessment with service-specific checks"""
        assessment = {
            'vulnerabilities': [],
            'risk_score': 0,
            'recommendations': [],
            'service_specific_checks': []
        }
        
        try:
            if 'service_detection' in scan_data['phases']:
                services = scan_data['phases']['service_detection'].get('services', [])
                
                for service in services:
                    if not service.get('success', False):
                        continue
                    
                    port = service['port']
                    service_name = service['service']
                    version = service['version']
                    banner = service.get('banner', '').lower()
                    
                    # SSH checks
                    if port == 22:
                        if 'openssh' in banner:
                            version_match = re.search(r'openssh[_\s]*(\d+\.\d+)', banner, re.IGNORECASE)
                            if version_match:
                                version_num = float(version_match.group(1))
                                if version_num < 7.0:
                                    assessment['vulnerabilities'].append({
                                        'service': 'SSH',
                                        'port': port,
                                        'issue': f'Outdated OpenSSH Version {version_num}',
                                        'severity': 'HIGH',
                                        'cve': 'Multiple CVEs possible',
                                        'details': 'Consider upgrading to OpenSSH 8.0 or later'
                                    })
                                    assessment['risk_score'] += 30
                    
                    # FTP checks
                    if port == 21:
                        if 'anonymous' in banner or '220' in banner:
                            assessment['vulnerabilities'].append({
                                'service': 'FTP',
                                'port': port,
                                'issue': 'FTP Service Exposed',
                                'severity': 'MEDIUM',
                                'details': 'FTP transmits credentials in clear text'
                            })
                            assessment['risk_score'] += 15
                    
                    # HTTP checks
                    if port in [80, 443, 8080, 8443]:
                        if 'apache' in banner and '2.2' in banner:
                            assessment['vulnerabilities'].append({
                                'service': 'HTTP',
                                'port': port,
                                'issue': 'Outdated Apache Version 2.2',
                                'severity': 'HIGH',
                                'cve': 'CVE-2017-3167, CVE-2017-3169, etc.',
                                'details': 'Apache 2.2 is EOL, upgrade to 2.4+'
                            })
                            assessment['risk_score'] += 25
                        
                        if port == 80 and 'http' in service_name.lower():
                            assessment['vulnerabilities'].append({
                                'service': 'HTTP',
                                'port': port,
                                'issue': 'HTTP without SSL',
                                'severity': 'MEDIUM',
                                'details': 'Consider redirecting to HTTPS'
                            })
                            assessment['risk_score'] += 10
                    
                    # Database checks
                    if port in [3306, 5432, 27017]:
                        assessment['vulnerabilities'].append({
                            'service': 'Database',
                            'port': port,
                            'issue': 'Database Exposed to Network',
                            'severity': 'HIGH',
                            'details': 'Database should not be directly accessible from network'
                        })
                        assessment['risk_score'] += 20
            
            if 'service_detection' in scan_data['phases']:
                detailed_probes = scan_data['phases']['service_detection'].get('detailed_probes', [])
                for probe in detailed_probes:
                    if probe.get('success', False):
                        service_check = {
                            'port': probe['port'],
                            'service': probe.get('service', 'unknown'),
                            'ssl': probe.get('ssl', False),
                            'headers': probe.get('headers', {}),
                            'issues_found': []
                        }
                        
                        if 'headers' in probe:
                            headers = probe['headers']
                            if 'server' in headers:
                                service_check['server'] = headers['server']
                            
                            security_headers = ['x-frame-options', 'x-content-type-options', 
                                              'x-xss-protection', 'content-security-policy']
                            missing = [h for h in security_headers if h not in headers]
                            if missing:
                                service_check['issues_found'].append(f'Missing security headers: {", ".join(missing)}')
                        
                        assessment['service_specific_checks'].append(service_check)
            
            if assessment['risk_score'] >= 50:
                assessment['recommendations'] = [
                    'CRITICAL: Immediate action required',
                    'Update all outdated services immediately',
                    'Disable or firewall high-risk services',
                    'Implement network segmentation',
                    'Enable logging and monitoring'
                ]
            elif assessment['risk_score'] >= 25:
                assessment['recommendations'] = [
                    'Update services to latest versions',
                    'Disable unnecessary network services',
                    'Implement proper authentication',
                    'Review firewall rules',
                    'Regular security assessments'
                ]
            elif assessment['risk_score'] > 0:
                assessment['recommendations'] = [
                    'Apply security patches',
                    'Harden service configurations',
                    'Review exposure of services',
                    'Consider security best practices'
                ]
            else:
                assessment['recommendations'] = ['No critical issues found. Maintain good security practices.']
        
        except Exception as e:
            assessment['error'] = str(e)
        
        return assessment
    
    def _ping_host(self, host: str) -> bool:
        """Simple ping check"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, 80))
            sock.close()
            return result == 0
        except:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False

# ============================================================================
# WEB SCANNER COMPLETE - UPDATED
# ============================================================================
class WebScannerComplete:
    """Web scanner with enhanced features"""
    
    def __init__(self):
        self.core = EnhancedCoreScanner()
    
    def comprehensive_web_scan(self, url: str) -> Dict[str, Any]:
        """Complete web assessment with enhanced features"""
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'phases': {}
        }
        
        results['phases']['server_detection'] = self.core.service_prober.probe_service(
            self._extract_hostname(url), 
            self._extract_port(url)
        )
        
        results['phases']['directory_enumeration'] = self.directory_enum(url)
        
        results['phases']['technology_detection'] = self.tech_detection(url)
        
        results['phases']['security_headers'] = self.check_security_headers(url)
        
        return results
    
    def _extract_hostname(self, url: str) -> str:
        """Extract hostname from URL"""
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.split(':')[0]
    
    def _extract_port(self, url: str) -> int:
        """Extract port from URL"""
        parsed = urllib.parse.urlparse(url)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == 'https' else 80
    
    def directory_enum(self, url: str) -> Dict[str, Any]:
        """Directory enumeration"""
        enumeration = {
            'directories': [],
            'files': [],
            'scanned': datetime.now().isoformat()
        }
        
        try:
            common_paths = [
                '/admin', '/login', '/wp-admin', '/administrator',
                '/backup', '/config', '/api', '/test',
                '/robots.txt', '/sitemap.xml', '/.env', '/.git/config'
            ]
            
            parsed = urllib.parse.urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for path in common_paths:
                full_url = base_url + path
                try:
                    if full_url.startswith('https'):
                        conn = http.client.HTTPSConnection(parsed.netloc, timeout=3)
                    else:
                        conn = http.client.HTTPConnection(parsed.netloc, timeout=3)
                    
                    conn.request("GET", path, headers={'User-Agent': 'DOOTSEAL/8.1'})
                    response = conn.getresponse()
                    status = f"{response.status} {response.reason}"
                    conn.close()
                    
                    if str(response.status)[0] in ['2', '3', '4']:
                        if '.' in path:
                            enumeration['files'].append({
                                'path': path,
                                'url': full_url,
                                'status': status
                            })
                        else:
                            enumeration['directories'].append({
                                'path': path,
                                'url': full_url,
                                'status': status
                            })
                except:
                    continue
        
        except Exception as e:
            enumeration['error'] = str(e)
        
        return enumeration
    
    def tech_detection(self, url: str) -> Dict[str, Any]:
        """Technology detection"""
        tech = {
            'server': 'unknown',
            'framework': 'unknown',
            'cms': 'unknown',
            'languages': [],
            'detected': []
        }
        
        try:
            host = self._extract_hostname(url)
            port = self._extract_port(url)
            
            result = self.core.probe_service(host, port)
            
            if 'server_header' in result:
                tech['server'] = result['server_header']
            
            if 'title' in result:
                tech['title'] = result['title']
            
            detected = result.get('detected', [])
            tech['detected'] = detected
            
            if any('wordpress' in d.lower() for d in detected):
                tech['cms'] = 'WordPress'
            elif any('joomla' in d.lower() for d in detected):
                tech['cms'] = 'Joomla'
            elif any('drupal' in d.lower() for d in detected):
                tech['cms'] = 'Drupal'
            
            banner = result.get('banner', '').lower()
            if 'php' in banner or '.php' in url:
                tech['languages'].append('PHP')
            if 'asp.net' in banner or '.aspx' in url:
                tech['languages'].append('ASP.NET')
                tech['framework'] = 'ASP.NET'
            
            if any('express' in d.lower() for d in detected) or 'node.js' in banner:
                tech['languages'].append('JavaScript')
                tech['framework'] = 'Node.js'
            
        except Exception as e:
            tech['error'] = str(e)
        
        return tech
    
    def check_security_headers(self, url: str) -> Dict[str, Any]:
        """Check security headers"""
        headers_check = {
            'url': url,
            'headers': {},
            'missing': [],
            'score': 0
        }
        
        try:
            host = self._extract_hostname(url)
            port = self._extract_port(url)
            
            result = self.core.probe_service(host, port)
            headers = result.get('headers', {})
            
            security_headers = {
                'X-Frame-Options': 'Prevents clickjacking',
                'X-Content-Type-Options': 'Prevents MIME sniffing',
                'X-XSS-Protection': 'XSS protection',
                'Content-Security-Policy': 'Content security policy',
                'Strict-Transport-Security': 'Enforces HTTPS',
                'Referrer-Policy': 'Controls referrer information'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    headers_check['headers'][header] = {
                        'value': headers[header],
                        'description': description,
                        'present': True
                    }
                    headers_check['score'] += 10
                else:
                    headers_check['headers'][header] = {
                        'value': 'MISSING',
                        'description': description,
                        'present': False
                    }
                    headers_check['missing'].append(header)
        
        except Exception as e:
            headers_check['error'] = str(e)
        
        return headers_check

# ============================================================================
# PASSWORD AUDITOR - KEEP EXISTING
# ============================================================================
class PasswordAuditorComplete:
    """Password auditor"""
    
    def __init__(self):
        self.paramiko_available = PARAMIKO_AVAILABLE
    
    def ssh_bruteforce(self, target: str, username: str, password_list: List[str]) -> Dict[str, Any]:
        """SSH brute force"""
        results = {
            'target': target,
            'service': 'ssh',
            'timestamp': datetime.now().isoformat(),
            'attempts': 0,
            'successful': [],
            'tested': []
        }
        
        if not self.paramiko_available:
            results['error'] = 'Paramiko not installed. Install with: pip install paramiko'
            return results
        
        for password in password_list[:50]:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                client.connect(
                    target,
                    username=username,
                    password=password,
                    timeout=5,
                    banner_timeout=5,
                    auth_timeout=5
                )
                
                results['successful'].append({
                    'username': username,
                    'password': password,
                    'timestamp': datetime.now().isoformat()
                })
                
                client.close()
                break
                
            except (paramiko.AuthenticationException, paramiko.SSHException):
                results['tested'].append(password)
                results['attempts'] += 1
                continue
            except Exception as e:
                results['error'] = f'Connection error: {str(e)}'
                break
        
        return results
    
    def http_basic_auth_bruteforce(self, url: str, username: str, password_list: List[str]) -> Dict[str, Any]:
        """HTTP Basic Auth brute force"""
        results = {
            'url': url,
            'service': 'http_basic_auth',
            'timestamp': datetime.now().isoformat(),
            'attempts': 0,
            'successful': []
        }
        
        for password in password_list[:30]:
            try:
                auth_string = f"{username}:{password}"
                encoded_auth = base64.b64encode(auth_string.encode()).decode()
                
                parsed = urllib.parse.urlparse(url)
                host = parsed.netloc
                path = parsed.path if parsed.path else '/'
                
                if url.startswith('https'):
                    conn = http.client.HTTPSConnection(host, timeout=5)
                else:
                    conn = http.client.HTTPConnection(host, timeout=5)
                
                conn.request("GET", path, headers={
                    'Authorization': f'Basic {encoded_auth}',
                    'User-Agent': 'DOOTSEAL/8.1'
                })
                
                response = conn.getresponse()
                
                if response.status not in [401, 403]:
                    results['successful'].append({
                        'username': username,
                        'password': password,
                        'status': f"{response.status} {response.reason}"
                    })
                    break
                
                conn.close()
                results['attempts'] += 1
                
            except Exception as e:
                results['error'] = str(e)
                break
        
        return results

# ============================================================================
# MAIN DOOTSEAL CLASS - UPDATED WITH NEW FEATURES
# ============================================================================
class DootsealComplete:
    """Complete DOOTSEAL with enhanced features"""
    
    def __init__(self):
        self.version = "8.1"
        
        print("[+] Initializing DOOTSEAL v8.1 with enhanced features...")
        self.network_scanner = NetworkScannerComplete()
        self.web_scanner = WebScannerComplete()
        self.password_auditor = PasswordAuditorComplete()
        
        self.enhanced_core = EnhancedCoreScanner()
        
        self.scan_history = []
        
        print("[+] DOOTSEAL v8.1 initialized successfully!")
        print("[+] Features:")
        print("    • Advanced MAC Vendor Database")
        print("    • Service Probing Database")
        print("    • Enhanced Network Discovery")
        print("    • Comprehensive Service Detection")
    
    def mac_lookup_tool(self, mac_address: str) -> Dict[str, Any]:
        """Tool for MAC address vendor lookup"""
        return self.enhanced_core.get_mac_vendor(mac_address)
    
    def service_probe_tool(self, host: str, port: int) -> Dict[str, Any]:
        """Tool for service probing"""
        return self.enhanced_core.probe_service(host, port)
    
    def network_discovery_tool(self, network: str) -> Dict[str, Any]:
        """Tool for network device discovery"""
        return self.enhanced_core.network_device_discovery(network)
    
    def generate_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive report with enhanced features"""
        report = {
            'report_id': f"DOOTSEAL-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'generated': datetime.now().isoformat(),
            'version': self.version,
            'author': 'Dootmas',
            'enhanced_features': True,
            'results': results,
            'summary': self._generate_enhanced_summary(results)
        }
        
        self.scan_history.append(report)
        
        return report
    
    def _generate_enhanced_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary with enhanced features"""
        summary = {
            'risk_level': 'UNKNOWN',
            'findings_count': 0,
            'critical_issues': 0,
            'mac_vendors_found': 0,
            'services_detected': 0,
            'recommendations': []
        }
        
        try:
            if 'phases' in results and 'vulnerability_assessment' in results['phases']:
                vulns = results['phases']['vulnerability_assessment'].get('vulnerabilities', [])
                summary['findings_count'] = len(vulns)
                summary['critical_issues'] = len([v for v in vulns if v.get('severity') in ['HIGH', 'CRITICAL']])
            
            if 'phases' in results and 'host_discovery' in results['phases']:
                vendors = results['phases']['host_discovery'].get('mac_vendors', [])
                summary['mac_vendors_found'] = len(vendors)
            
            if 'phases' in results and 'service_detection' in results['phases']:
                services = results['phases']['service_detection'].get('services', [])
                summary['services_detected'] = len([s for s in services if s.get('success', False)])
            
            if summary['critical_issues'] > 3:
                summary['risk_level'] = 'CRITICAL'
            elif summary['critical_issues'] > 0:
                summary['risk_level'] = 'HIGH'
            elif summary['findings_count'] > 5:
                summary['risk_level'] = 'MEDIUM'
            elif summary['findings_count'] > 0:
                summary['risk_level'] = 'LOW'
            else:
                summary['risk_level'] = 'VERY LOW'
            
            if summary['risk_level'] in ['CRITICAL', 'HIGH']:
                summary['recommendations'] = [
                    '🔴 IMMEDIATE ACTION REQUIRED',
                    'Apply all security patches immediately',
                    'Isolate affected systems from network',
                    'Review and update all firewall rules',
                    'Enable comprehensive logging and monitoring',
                    'Consider professional security assessment'
                ]
            elif summary['risk_level'] == 'MEDIUM':
                summary['recommendations'] = [
                    '🟠 Address security issues promptly',
                    'Update all services to latest versions',
                    'Harden service configurations',
                    'Implement proper network segmentation',
                    'Regular security assessments recommended'
                ]
            elif summary['risk_level'] == 'LOW':
                summary['recommendations'] = [
                    '🟢 Maintain security vigilance',
                    'Keep systems updated',
                    'Follow security best practices',
                    'Regular vulnerability scanning'
                ]
            else:
                summary['recommendations'] = ['🟢 Systems appear secure. Maintain current practices.']
        
        except Exception as e:
            summary['error'] = str(e)
        
        return summary

# ============================================================================
# COMPLETE GUI - FULL IMPLEMENTATION
# ============================================================================
class DootsealCompleteGUI:
    """Complete GUI with enhanced features"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("DOOTSEAL v8.1 - ADVANCED OPERATIONS CENTER")
        self.root.geometry("1400x900")
        
        # Initialize core
        self.dootseal = DootsealComplete()
        
        # Dootmas colors
        self.colors = {
            'bg_dark': '#0a0a0a',
            'bg_panel': '#1a1a1a',
            'fg_green': '#00ff88',
            'fg_blue': '#00ccff',
            'fg_purple': '#ff00ff',
            'fg_orange': '#ff9900',
            'fg_text': '#ffffff',
            'danger': '#ff3333',
            'warning': '#ff9900',
            'success': '#00cc66',
            'primary': '#ff5e5e',
            'cyber_blue': '#0066ff',
            'cyber_green': '#00ffaa',
            'cyber_purple': '#aa00ff'
        }
        
        # Configure theme
        self.root.configure(bg=self.colors['bg_dark'])
        
        # Build interface
        self.setup_styles()
        self.build_header()
        self.build_main_interface()
        self.build_status_bar()
        
        # Center window
        self.center_window()
        
        # Show welcome
        self.show_welcome()
    
    def setup_styles(self):
        """Configure styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('.', 
                       background=self.colors['bg_dark'],
                       foreground=self.colors['fg_text'],
                       fieldbackground=self.colors['bg_panel'])
        
        style.configure('TFrame', background=self.colors['bg_dark'])
        style.configure('TLabel', background=self.colors['bg_dark'], 
                       foreground=self.colors['fg_text'])
        style.configure('TButton', background=self.colors['bg_panel'],
                       foreground=self.colors['fg_text'])
        style.configure('TEntry', fieldbackground=self.colors['bg_panel'],
                       foreground=self.colors['fg_text'])
        style.configure('TCombobox', fieldbackground=self.colors['bg_panel'],
                       foreground=self.colors['fg_text'])
    
    def build_header(self):
        """Build header"""
        header = tk.Frame(self.root, bg=self.colors['bg_dark'], height=100)
        header.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(header,
                text="DOOTSEAL v8.1 - ADVANCED OPERATIONS CENTER",
                font=('Arial', 24, 'bold'),
                fg=self.colors['cyber_blue'],
                bg=self.colors['bg_dark']).pack(anchor='w')
        
        tk.Label(header,
                text="by Dootmas | Enhanced with MAC Vendor DB & Service Probing | Don't be a 'Bad Boy'. :3",
                font=('Arial', 11),
                fg=self.colors['cyber_purple'],
                bg=self.colors['bg_dark']).pack(anchor='w')
        
        stats_text = f"Status: READY | MAC DB: {self.dootseal.enhanced_core.mac_lookup.stats['total_entries']:,} entries | Service DB: {len(self.dootseal.enhanced_core.service_prober.probes)} probes"
        tk.Label(header,
                text=stats_text,
                font=('Arial', 10),
                fg=self.colors['cyber_green'],
                bg=self.colors['bg_dark']).pack(anchor='w', pady=(5,0))
    
    def build_main_interface(self):
        """Build main interface"""
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=self.colors['bg_dark'])
        main_pane.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0,20))
        
        # Left panel - Controls
        left_panel = ttk.LabelFrame(main_pane, text=" Advanced Operations ", padding=15)
        main_pane.add(left_panel, width=450)
        self.build_control_panel(left_panel)
        
        # Right panel - Results
        right_panel = ttk.Frame(main_pane)
        main_pane.add(right_panel)
        self.build_results_panel(right_panel)
    
    def build_control_panel(self, parent):
        """Build control panel"""
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Network tab
        network_frame = ttk.Frame(notebook)
        notebook.add(network_frame, text="🌐 Network v8")
        self.build_network_tab(network_frame)
        
        # MAC Tools tab
        mac_frame = ttk.Frame(notebook)
        notebook.add(mac_frame, text="📟 MAC Tools")
        self.build_mac_tools_tab(mac_frame)
        
        # Service Tools tab
        service_frame = ttk.Frame(notebook)
        notebook.add(service_frame, text="🔧 Service Tools")
        self.build_service_tools_tab(service_frame)
        
        # Web tab
        web_frame = ttk.Frame(notebook)
        notebook.add(web_frame, text="🕸️ Web")
        self.build_web_tab(web_frame)
        
        # Password tab
        pass_frame = ttk.Frame(notebook)
        notebook.add(pass_frame, text="🔐 Password")
        self.build_password_tab(pass_frame)
        
        # Tools tab
        tools_frame = ttk.Frame(notebook)
        notebook.add(tools_frame, text="🛠️ Tools")
        self.build_tools_tab(tools_frame)
    
    def build_network_tab(self, parent):
        """Build network scanning tab"""
        ttk.Label(parent, text="Target IP/Hostname:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_var = tk.StringVar(value="scanme.nmap.org")
        ttk.Entry(parent, textvariable=self.target_var, width=30).grid(row=1, column=0, columnspan=2, pady=(0,15))
        
        buttons = [
            ("🚀 Enhanced Network Scan", self.enhanced_network_scan),
            ("🔍 Quick Port Scan", self.quick_port_scan),
            ("🎯 Service Detection", self.service_detection),
            ("📡 Network Device Discovery", self.network_device_discovery),
            ("🌐 Subnet Discovery", self.subnet_discovery),
            ("🔗 DNS Lookup", self.dns_lookup)
        ]
        
        for i, (text, command) in enumerate(buttons):
            ttk.Button(parent, text=text, command=command).grid(
                row=2+i, column=0, columnspan=2, pady=3, sticky=tk.W+tk.E)
    
    def build_mac_tools_tab(self, parent):
        """Build MAC tools tab"""
        ttk.Label(parent, text="MAC Address:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.mac_var = tk.StringVar(value="00:11:22:33:44:55")
        ttk.Entry(parent, textvariable=self.mac_var, width=25).grid(row=1, column=0, pady=(0,15))
        
        ttk.Button(parent, text="🔍 Lookup MAC Vendor", 
                  command=self.mac_vendor_lookup).grid(row=1, column=1, padx=5, pady=(0,15))
        
        ttk.Label(parent, text="Search Vendor:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.vendor_search_var = tk.StringVar(value="Cisco")
        ttk.Entry(parent, textvariable=self.vendor_search_var, width=25).grid(row=3, column=0, pady=(0,15))
        
        ttk.Button(parent, text="🔎 Search Vendor Database", 
                  command=self.search_vendor_database).grid(row=3, column=1, padx=5, pady=(0,15))
        
        ttk.Button(parent, text="📊 Batch MAC Lookup", 
                  command=self.batch_mac_lookup).grid(row=4, column=0, columnspan=2, pady=5, sticky=tk.W+tk.E)
        
        ttk.Button(parent, text="🔄 ARP Scan with Vendors", 
                  command=self.arp_scan_with_vendors).grid(row=5, column=0, columnspan=2, pady=5, sticky=tk.W+tk.E)
    
    def build_service_tools_tab(self, parent):
        """Build service tools tab"""
        ttk.Label(parent, text="Host:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.service_host_var = tk.StringVar(value="scanme.nmap.org")
        ttk.Entry(parent, textvariable=self.service_host_var, width=20).grid(row=1, column=0, pady=(0,5))
        
        ttk.Label(parent, text="Port:").grid(row=1, column=1, sticky=tk.W, padx=5)
        self.service_port_var = tk.StringVar(value="80")
        ttk.Entry(parent, textvariable=self.service_port_var, width=10).grid(row=1, column=2, pady=(0,5))
        
        ttk.Button(parent, text="🔧 Probe Service", 
                  command=self.service_probe).grid(row=2, column=0, columnspan=3, pady=5, sticky=tk.W+tk.E)
        
        ttk.Button(parent, text="🎯 Comprehensive Service Scan", 
                  command=self.comprehensive_service_scan).grid(row=3, column=0, columnspan=3, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(parent, text="Quick Ports:").grid(row=4, column=0, sticky=tk.W, pady=10)
        
        port_buttons_frame = ttk.Frame(parent)
        port_buttons_frame.grid(row=5, column=0, columnspan=3, pady=5)
        
        common_ports = [("21 FTP", 21), ("22 SSH", 22), ("80 HTTP", 80), 
                       ("443 HTTPS", 443), ("3389 RDP", 3389), ("8080 HTTP", 8080)]
        
        for i, (text, port) in enumerate(common_ports):
            btn = ttk.Button(port_buttons_frame, text=text, width=8,
                           command=lambda p=port: self.quick_service_probe(p))
            btn.grid(row=i//3, column=i%3, padx=2, pady=2)
    
    def build_web_tab(self, parent):
        """Build web scanning tab"""
        ttk.Label(parent, text="Website URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.web_url_var = tk.StringVar(value="http://scanme.nmap.org")
        ttk.Entry(parent, textvariable=self.web_url_var, width=30).grid(row=1, column=0, columnspan=2, pady=(0,15))
        
        buttons = [
            ("🌐 Full Web Scan", self.full_web_scan),
            ("🔍 Check Server", self.check_web_server),
            ("📁 Directory Enum", self.directory_enum),
            ("🔬 Tech Detection", self.tech_detection),
            ("🛡️ Security Headers", self.security_headers)
        ]
        
        for i, (text, command) in enumerate(buttons):
            ttk.Button(parent, text=text, command=command).grid(
                row=2+i, column=0, columnspan=2, pady=3, sticky=tk.W+tk.E)
    
    def build_password_tab(self, parent):
        """Build password tab"""
        ttk.Label(parent, text="Target:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.pass_target_var = tk.StringVar(value="")
        ttk.Entry(parent, textvariable=self.pass_target_var, width=20).grid(row=1, column=0, pady=(0,5))
        
        ttk.Label(parent, text="Username:").grid(row=1, column=1, sticky=tk.W, padx=5)
        self.pass_user_var = tk.StringVar(value="admin")
        ttk.Entry(parent, textvariable=self.pass_user_var, width=10).grid(row=1, column=2, pady=(0,5))
        
        buttons = [
            ("🔑 SSH Brute Force", self.ssh_bruteforce),
            ("🌐 HTTP Auth Crack", self.http_auth_crack),
            ("🧪 Test Credentials", self.test_credentials)
        ]
        
        for i, (text, command) in enumerate(buttons):
            ttk.Button(parent, text=text, command=command).grid(
                row=2+i, column=0, columnspan=3, pady=5, sticky=tk.W+tk.E)
    
    def build_tools_tab(self, parent):
        """Build tools tab"""
        tools = [
            ("📊 Generate Report", self.generate_report),
            ("💾 Export Results", self.export_results),
            ("🗑️ Clear Output", self.clear_output),
            ("ℹ️ About DOOTSEAL", self.show_about)
        ]
        
        for i, (text, command) in enumerate(tools):
            ttk.Button(parent, text=text, command=command).grid(
                row=i, column=0, pady=5, sticky=tk.W+tk.E)
    
    def build_results_panel(self, parent):
        """Build results panel"""
        self.output_text = scrolledtext.ScrolledText(parent, 
                                                    bg=self.colors['bg_panel'], 
                                                    fg=self.colors['fg_text'], 
                                                    font=('Consolas', 10),
                                                    insertbackground=self.colors['fg_text'],
                                                    height=30)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.output_text.config(state=tk.NORMAL)
        
        # Configure tags for colored output
        self.output_text.tag_config("success", foreground=self.colors['success'])
        self.output_text.tag_config("error", foreground=self.colors['danger'])
        self.output_text.tag_config("warning", foreground=self.colors['warning'])
        self.output_text.tag_config("info", foreground=self.colors['fg_blue'])
        self.output_text.tag_config("header", foreground=self.colors['cyber_blue'], font=('Consolas', 11, 'bold'))
        self.output_text.tag_config("cyber_green", foreground=self.colors['cyber_green'])
        self.output_text.tag_config("cyber_purple", foreground=self.colors['cyber_purple'])
    
    def build_status_bar(self):
        """Build status bar"""
        self.status_frame = tk.Frame(self.root, bg='#2a2a2a', height=30)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=20, pady=(0,10))
        
        self.status_var = tk.StringVar(value="DOOTSEAL v8.1 Ready")
        tk.Label(self.status_frame, textvariable=self.status_var,
                bg='#2a2a2a', fg=self.colors['cyber_green']).pack(side=tk.LEFT, padx=10)
        
        self.progress = ttk.Progressbar(self.status_frame, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10)
    
    def center_window(self):
        """Center window"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def show_welcome(self):
        """Show welcome message"""
        welcome = f"""
╔═══════════════════════════════════════════════════════════════════╗
║                    DOOTSEAL v8.1 - ADVANCED OPERATIONS           ║
║                            by Dootmas                            ║
╚═══════════════════════════════════════════════════════════════════╝

[!] DOOTMAS INTEGRITY SHIELD ACTIVE v8.1
[!] LEGAL: Authorized Auditing Only. Don't be a "Bad Boy". :3

DATABASES LOADED:
• MAC Vendor Database: {self.dootseal.enhanced_core.mac_lookup.stats['total_entries']:,} entries
• Service Probes: {len(self.dootseal.enhanced_core.service_prober.probes)} probes

ENHANCED FEATURES:
• Advanced MAC Vendor Lookup
• Service Probing Database
• Network Device Discovery with MAC Vendors
• Enhanced Service Detection
• Comprehensive Security Assessment

Ready for advanced operations. Select a tool to begin.
"""
        self.update_output(welcome, "header")
    
    def update_output(self, text, tag="normal"):
        """Update output with colored text"""
        self.output_text.config(state=tk.NORMAL)
        
        if tag != "normal":
            self.output_text.insert(tk.END, text + "\n", tag)
        else:
            self.output_text.insert(tk.END, text + "\n")
        
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def update_status(self, status):
        """Update status bar"""
        self.status_var.set(status)
    
    def start_progress(self):
        """Start progress bar"""
        self.progress.start(10)
    
    def stop_progress(self):
        """Stop progress bar"""
        self.progress.stop()
    
    def clear_output(self):
        """Clear output window"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.show_welcome()
    
    # ============================================================================
    # NETWORK SCANNING OPERATIONS
    # ============================================================================
    
    def enhanced_network_scan(self):
        """Execute enhanced network scan"""
        target = self.target_var.get().strip()
        if not target:
            self.update_output("[✗] Please enter a target", "error")
            return
        
        self.update_output(f"\n[🚀] Starting ENHANCED NETWORK SCAN on {target}", "header")
        self.update_status(f"Enhanced Scanning: {target}")
        self.start_progress()
        
        def run():
            try:
                results = self.dootseal.network_scanner.comprehensive_scan(target)
                
                self.update_output(f"[✓] Enhanced scan completed", "success")
                self.update_output("\n" + "═" * 70, "header")
                self.update_output("ENHANCED SCAN RESULTS:", "header")
                self.update_output("═" * 70, "header")
                
                # Display results
                if 'host_discovery' in results['phases']:
                    hd = results['phases']['host_discovery']
                    self.update_output(f"\n[📡] HOST DISCOVERY:")
                    self.update_output(f"    Techniques: {', '.join(hd.get('techniques', []))}")
                    
                    vendors = hd.get('mac_vendors', [])
                    if vendors:
                        self.update_output(f"    MAC Vendors: {len(vendors)} found", "cyber_green")
                
                if 'port_scanning' in results['phases']:
                    ps = results['phases']['port_scanning']
                    open_ports = ps.get('open_ports', [])
                    if open_ports:
                        self.update_output(f"\n[🎯] OPEN PORTS: {len(open_ports)} found", "success")
                        for port_info in open_ports[:10]:
                            service = port_info.get('service', 'unknown')
                            ssl_info = " (SSL)" if port_info.get('ssl') else ""
                            self.update_output(f"    • Port {port_info['port']} - {service}{ssl_info}")
                    else:
                        self.update_output(f"\n[🎯] No open ports found", "warning")
                
                if 'vulnerability_assessment' in results['phases']:
                    va = results['phases']['vulnerability_assessment']
                    vulns = va.get('vulnerabilities', [])
                    if vulns:
                        self.update_output(f"\n[⚠️] VULNERABILITIES: {len(vulns)} found", "error")
                        for vuln in vulns[:5]:
                            severity = vuln.get('severity', 'UNKNOWN')
                            severity_color = "error" if severity in ['HIGH', 'CRITICAL'] else "warning"
                            self.update_output(f"    • {vuln.get('issue', 'Unknown')} ({severity})", severity_color)
                    else:
                        self.update_output(f"\n[✓] No vulnerabilities found", "success")
                
            except Exception as e:
                self.update_output(f"[✗] Error during enhanced scan: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def quick_port_scan(self):
        """Quick port scan"""
        target = self.target_var.get().strip()
        if not target:
            self.update_output("[✗] Please enter a target", "error")
            return
        
        self.update_output(f"\n[🔍] Quick port scan on {target}", "info")
        self.update_status(f"Scanning ports on {target}")
        self.start_progress()
        
        def run():
            try:
                results = self.dootseal.enhanced_core.comprehensive_service_scan(target)
                successful_services = [s for s in results.get('services', []) if s.get('success', False)]
                
                if successful_services:
                    self.update_output(f"[✓] Found {len(successful_services)} open ports:", "success")
                    for service in successful_services:
                        port = service.get('port', 0)
                        service_name = service.get('service', 'unknown')
                        version = service.get('version', 'unknown')
                        ssl_info = " (SSL)" if service.get('ssl', False) else ""
                        
                        self.update_output(f"    Port {port}: {service_name} v{version}{ssl_info}")
                else:
                    self.update_output("[•] No open ports found", "warning")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def service_detection(self):
        """Service detection"""
        target = self.target_var.get().strip()
        if not target:
            self.update_output("[✗] Please enter a target", "error")
            return
        
        self.update_output(f"\n[🎯] Service detection on {target}", "info")
        self.update_status(f"Detecting services on {target}")
        self.start_progress()
        
        def run():
            try:
                ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]
                
                for port in ports:
                    result = self.dootseal.enhanced_core.probe_service(target, port)
                    
                    if result.get('success', False):
                        self.update_output(f"\n[•] Port {port}:")
                        self.update_output(f"    Service: {result.get('service', 'unknown')}", "success")
                        self.update_output(f"    Version: {result.get('version', 'unknown')}")
                        
                        if result.get('ssl', False):
                            self.update_output(f"    SSL: Enabled", "cyber_green")
                        
                        detected = result.get('detected', [])
                        if detected:
                            self.update_output(f"    Software: {', '.join(detected)}")
                    else:
                        self.update_output(f"[•] Port {port}: Closed or filtered", "warning")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def network_device_discovery(self):
        """Network device discovery with services"""
        network = simpledialog.askstring("Network Discovery", 
                                        "Enter network (e.g., 192.168.1.0/24):",
                                        initialvalue="192.168.1.0/24")
        if not network:
            return
        
        self.update_output(f"\n[📡] Network Device Discovery: {network}", "header")
        self.update_status(f"Network discovery: {network}")
        self.start_progress()
        
        def run():
            try:
                result = self.dootseal.network_discovery_tool(network)
                devices = result.get('devices', [])
                stats = result.get('statistics', {})
                
                self.update_output(f"\n[📊] DISCOVERY RESULTS:", "header")
                self.update_output(f"    Network: {result.get('network', network)}")
                self.update_output(f"    Total devices: {stats.get('total_devices', 0)}")
                self.update_output(f"    Open ports: {stats.get('open_ports', 0)}")
                self.update_output(f"    Unique services: {len(stats.get('unique_services', []))}")
                
                if devices:
                    self.update_output(f"\n[💻] DEVICES FOUND:", "cyber_purple")
                    for device in devices[:5]:
                        ip = device.get('ip', 'Unknown')
                        mac = device.get('mac', 'Unknown')
                        vendor = device.get('vendor', 'Unknown')
                        confidence = device.get('confidence', 0)
                        
                        self.update_output(f"\n[🏷️] {ip}")
                        self.update_output(f"    MAC: {mac}")
                        self.update_output(f"    Vendor: {vendor} ({confidence}% confidence)")
                else:
                    self.update_output(f"\n[❌] No devices discovered", "warning")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def subnet_discovery(self):
        """Subnet discovery"""
        target = self.target_var.get().strip()
        if not target:
            target = "192.168.1.1"
        
        network = target.rsplit('.', 1)[0] + ".0/24"
        
        self.update_output(f"\n[🌐] Discovering hosts in subnet: {network}", "header")
        self.update_status(f"Discovering hosts in {network}")
        self.start_progress()
        
        def run():
            try:
                devices = self.dootseal.enhanced_core.arp_scan_with_vendors(network)
                
                if devices:
                    self.update_output(f"[✓] Found {len(devices)} devices:", "success")
                    
                    by_vendor = defaultdict(list)
                    for device in devices:
                        vendor = device.get('vendor', 'Unknown')
                        by_vendor[vendor].append(device)
                    
                    for vendor, vendor_devices in sorted(by_vendor.items()):
                        self.update_output(f"\n[🏷️] {vendor}:")
                        for device in vendor_devices[:3]:
                            ip = device.get('ip', 'Unknown')
                            mac = device.get('mac', 'Unknown')
                            confidence = device.get('confidence', 0)
                            self.update_output(f"    • {ip} ({mac}) - {confidence}% confidence")
                else:
                    self.update_output("[•] No devices found in subnet", "warning")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def dns_lookup(self):
        """DNS lookup"""
        hostname = self.target_var.get().strip()
        if not hostname:
            self.update_output("[✗] Please enter a hostname", "error")
            return
        
        self.update_output(f"\n[🔗] DNS lookup for: {hostname}", "info")
        self.update_status(f"Resolving {hostname}")
        self.start_progress()
        
        def run():
            try:
                import socket
                addresses = list(set([addr[4][0] for addr in socket.getaddrinfo(hostname, None)]))
                
                if addresses:
                    self.update_output(f"[✓] Resolved to {len(addresses)} IP address(es):", "success")
                    for addr in addresses:
                        self.update_output(f"    • {addr}")
                else:
                    self.update_output(f"[✗] Could not resolve {hostname}", "error")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    # ============================================================================
    # MAC TOOLS OPERATIONS
    # ============================================================================
    
    def mac_vendor_lookup(self):
        """MAC vendor lookup"""
        mac_address = self.mac_var.get().strip()
        if not mac_address:
            self.update_output("[✗] Please enter a MAC address", "error")
            return
        
        self.update_output(f"\n[📟] MAC Vendor Lookup: {mac_address}", "header")
        self.update_status(f"Looking up MAC: {mac_address}")
        self.start_progress()
        
        def run():
            try:
                result = self.dootseal.mac_lookup_tool(mac_address)
                
                self.update_output(f"\n[📊] RESULTS:", "header")
                self.update_output(f"    MAC Address: {result.get('mac', mac_address)}")
                self.update_output(f"    Vendor: {result.get('vendor', 'Unknown')}")
                self.update_output(f"    Full Name: {result.get('full', 'Unknown Vendor')}")
                self.update_output(f"    Confidence: {result.get('confidence', 0)}%")
                self.update_output(f"    Source: {result.get('source', 'unknown')}")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def search_vendor_database(self):
        """Search vendor database"""
        search_term = self.vendor_search_var.get().strip()
        if not search_term:
            self.update_output("[✗] Please enter a search term", "error")
            return
        
        self.update_output(f"\n[🔎] Searching vendor database for: {search_term}", "header")
        self.update_status(f"Searching vendors: {search_term}")
        self.start_progress()
        
        def run():
            try:
                results = self.dootseal.enhanced_core.mac_lookup.search_vendor(search_term)
                
                if results:
                    self.update_output(f"\n[✅] FOUND {len(results)} VENDOR(S):", "success")
                    for i, vendor in enumerate(results[:10], 1):
                        self.update_output(f"\n    {i}. {vendor.get('prefix', 'Unknown')}")
                        self.update_output(f"       Short: {vendor.get('short', 'Unknown')}")
                        self.update_output(f"       Full: {vendor.get('full', 'Unknown')}")
                        self.update_output(f"       Source: {vendor.get('source', 'unknown')}")
                else:
                    self.update_output(f"\n[❌] No vendors found", "warning")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def batch_mac_lookup(self):
        """Batch MAC lookup"""
        macs_text = simpledialog.askstring("Batch MAC Lookup", 
                                          "Enter MAC addresses (one per line or comma separated):")
        if not macs_text:
            return
        
        macs = []
        for line in macs_text.split('\n'):
            for mac in line.split(','):
                mac = mac.strip()
                if mac:
                    macs.append(mac)
        
        if not macs:
            self.update_output("[✗] No valid MAC addresses provided", "error")
            return
        
        self.update_output(f"\n[📋] Batch MAC Lookup: {len(macs)} addresses", "header")
        self.update_status(f"Batch lookup: {len(macs)} MACs")
        self.start_progress()
        
        def run():
            try:
                results = self.dootseal.enhanced_core.mac_lookup.batch_lookup(macs)
                
                self.update_output(f"\n[📊] BATCH RESULTS:", "header")
                
                vendor_counts = defaultdict(int)
                for mac, info in results.items():
                    vendor = info.get('vendor', 'Unknown')
                    vendor_counts[vendor] += 1
                
                self.update_output(f"    Total MACs: {len(macs)}")
                self.update_output(f"    Unique vendors: {len(vendor_counts)}")
                
                self.update_output(f"\n[🏆] TOP VENDORS:")
                for vendor, count in sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                    self.update_output(f"    • {vendor}: {count} MACs")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def arp_scan_with_vendors(self):
        """ARP scan with vendor identification"""
        network = simpledialog.askstring("Network", 
                                        "Enter network (e.g., 192.168.1.0/24):",
                                        initialvalue="192.168.1.0/24")
        if not network:
            return
        
        self.update_output(f"\n[📡] ARP Scan with MAC Vendors: {network}", "header")
        self.update_status(f"ARP Scanning: {network}")
        self.start_progress()
        
        def run():
            try:
                devices = self.dootseal.enhanced_core.arp_scan_with_vendors(network)
                
                if devices:
                    self.update_output(f"\n[✅] FOUND {len(devices)} DEVICE(S):", "success")
                    
                    by_vendor = defaultdict(list)
                    for device in devices:
                        vendor = device.get('vendor', 'Unknown')
                        by_vendor[vendor].append(device)
                    
                    for vendor, vendor_devices in sorted(by_vendor.items()):
                        self.update_output(f"\n[🏷️] {vendor.upper()} ({len(vendor_devices)} devices):")
                        for device in vendor_devices[:3]:
                            ip = device.get('ip', 'Unknown')
                            mac = device.get('mac', 'Unknown')
                            confidence = device.get('confidence', 0)
                            
                            self.update_output(f"    • {ip} - {mac} ({confidence}% confidence)")
                else:
                    self.update_output(f"\n[❌] No devices found", "warning")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    # ============================================================================
    # SERVICE TOOLS OPERATIONS
    # ============================================================================
    
    def service_probe(self):
        """Service probe"""
        host = self.service_host_var.get().strip()
        if not host:
            self.update_output("[✗] Please enter a host", "error")
            return
        
        try:
            port = int(self.service_port_var.get().strip())
        except:
            self.update_output("[✗] Please enter a valid port number", "error")
            return
        
        self.update_output(f"\n[🔧] Service Probe: {host}:{port}", "header")
        self.update_status(f"Probing service: {host}:{port}")
        self.start_progress()
        
        def run():
            try:
                result = self.dootseal.service_probe_tool(host, port)
                
                self.update_output(f"\n[📊] SERVICE PROBE RESULTS:", "header")
                self.update_output(f"    Host: {result.get('host', host)}")
                self.update_output(f"    Port: {result.get('port', port)}")
                
                if result.get('success', False):
                    self.update_output(f"    Service: {result.get('service', 'unknown')}", "success")
                    self.update_output(f"    Version: {result.get('version', 'unknown')}")
                    
                    if result.get('ssl', False):
                        self.update_output(f"    SSL: Enabled", "cyber_green")
                    
                    detected = result.get('detected', [])
                    if detected:
                        self.update_output(f"    Detected Software: {', '.join(detected)}", "info")
                    
                    banner = result.get('banner', '')
                    if banner:
                        self.update_output(f"\n[📜] BANNER:")
                        banner_lines = banner[:200].split('\n')
                        for line in banner_lines[:5]:
                            self.update_output(f"    {line}")
                else:
                    error = result.get('error', 'Service not responding')
                    self.update_output(f"    Status: Failed - {error}", "error")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def quick_service_probe(self, port):
        """Quick service probe for common ports"""
        self.service_port_var.set(str(port))
        self.service_probe()
    
    def comprehensive_service_scan(self):
        """Comprehensive service scan"""
        host = self.service_host_var.get().strip()
        if not host:
            self.update_output("[✗] Please enter a host", "error")
            return
        
        self.update_output(f"\n[🎯] Comprehensive Service Scan: {host}", "header")
        self.update_status(f"Comprehensive scan: {host}")
        self.start_progress()
        
        def run():
            try:
                result = self.dootseal.enhanced_core.comprehensive_service_scan(host)
                successful_services = [s for s in result.get('services', []) if s.get('success', False)]
                
                self.update_output(f"\n[📊] SCAN RESULTS:", "header")
                self.update_output(f"    Host: {result.get('host', host)}")
                self.update_output(f"    Ports scanned: {result.get('ports_scanned', 0)}")
                self.update_output(f"    Successful probes: {result.get('successful', 0)}")
                
                if successful_services:
                    self.update_output(f"\n[✅] OPEN SERVICES FOUND:", "success")
                    
                    by_service = defaultdict(list)
                    for service in successful_services:
                        service_name = service.get('service', 'unknown')
                        by_service[service_name].append(service)
                    
                    for service_name, services in sorted(by_service.items()):
                        self.update_output(f"\n[🔧] {service_name.upper()} ({len(services)} port(s)):")
                        for service in services:
                            port = service.get('port', 0)
                            version = service.get('version', 'unknown')
                            ssl_info = " (SSL)" if service.get('ssl', False) else ""
                            
                            self.update_output(f"    • Port {port}: v{version}{ssl_info}")
                else:
                    self.update_output(f"\n[❌] No open services found", "warning")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    # ============================================================================
    # WEB SCANNING OPERATIONS
    # ============================================================================
    
    def full_web_scan(self):
        """Execute full web scan"""
        url = self.web_url_var.get().strip()
        if not url:
            self.update_output("[✗] Please enter a URL", "error")
            return
        
        self.update_output(f"\n[🌐] Full Web Scan on {url}", "header")
        self.update_status(f"Web scanning: {url}")
        self.start_progress()
        
        def run():
            try:
                host = self.dootseal.web_scanner._extract_hostname(url)
                port = self.dootseal.web_scanner._extract_port(url)
                
                result = self.dootseal.enhanced_core.probe_service(host, port)
                
                self.update_output(f"[✓] Web scan completed", "success")
                self.update_output("\n" + "═" * 60, "header")
                self.update_output("WEB SCAN RESULTS:", "header")
                self.update_output("═" * 60, "header")
                
                if result.get('success', False):
                    self.update_output(f"\n[•] SERVER DETECTION:")
                    self.update_output(f"    Service: {result.get('service', 'unknown')}")
                    self.update_output(f"    Version: {result.get('version', 'unknown')}")
                    
                    if result.get('ssl', False):
                        self.update_output("    SSL: Enabled", "success")
                    
                    if 'headers' in result:
                        headers = result.get('headers', {})
                        if 'server' in headers:
                            self.update_output(f"    Server: {headers['server']}", "info")
                    
                    if 'title' in result:
                        self.update_output(f"\n[•] PAGE TITLE:")
                        self.update_output(f"    {result.get('title')}")
                else:
                    self.update_output(f"\n[✗] Web server not responding", "error")
                
            except Exception as e:
                self.update_output(f"[✗] Error during web scan: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def check_web_server(self):
        """Check web server"""
        url = self.web_url_var.get().strip()
        if not url:
            self.update_output("[✗] Please enter a URL", "error")
            return
        
        self.update_output(f"\n[🔍] Checking web server: {url}", "info")
        self.update_status(f"Checking {url}")
        self.start_progress()
        
        def run():
            try:
                host = self.dootseal.web_scanner._extract_hostname(url)
                port = self.dootseal.web_scanner._extract_port(url)
                
                result = self.dootseal.enhanced_core.probe_service(host, port)
                
                self.update_output(f"\n[•] SERVER RESPONSE:", "header")
                self.update_output(f"    URL: {url}")
                
                if result.get('success', False):
                    self.update_output(f"    Status: Responding", "success")
                    self.update_output(f"    Service: {result.get('service', 'unknown')}")
                else:
                    error = result.get('error', 'No response')
                    self.update_output(f"    Status: {error}", "error")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def directory_enum(self):
        """Directory enumeration"""
        url = self.web_url_var.get().strip()
        if not url:
            self.update_output("[✗] Please enter a URL", "error")
            return
        
        self.update_output(f"\n[📁] Directory enumeration on: {url}", "info")
        self.update_status(f"Enumerating directories on {url}")
        self.start_progress()
        
        def run():
            try:
                results = self.dootseal.web_scanner.directory_enum(url)
                
                dirs = results.get('directories', [])
                files = results.get('files', [])
                
                if dirs or files:
                    if dirs:
                        self.update_output(f"\n[✓] Directories found: {len(dirs)}", "success")
                        for d in dirs:
                            status = d.get('status', '')
                            if '200' in status:
                                self.update_output(f"    ✓ {d['path']} ({status})", "success")
                            else:
                                self.update_output(f"    • {d['path']} ({status})")
                    
                    if files:
                        self.update_output(f"\n[✓] Files found: {len(files)}", "success")
                        for f in files:
                            status = f.get('status', '')
                            if '200' in status:
                                self.update_output(f"    ✓ {f['path']} ({status})", "success")
                            else:
                                self.update_output(f"    • {f['path']} ({status})")
                else:
                    self.update_output("[•] No directories or files found", "warning")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def tech_detection(self):
        """Technology detection"""
        url = self.web_url_var.get().strip()
        if not url:
            self.update_output("[✗] Please enter a URL", "error")
            return
        
        self.update_output(f"\n[🔬] Technology detection on: {url}", "info")
        self.update_status(f"Detecting technologies on {url}")
        self.start_progress()
        
        def run():
            try:
                host = self.dootseal.web_scanner._extract_hostname(url)
                port = self.dootseal.web_scanner._extract_port(url)
                
                result = self.dootseal.enhanced_core.probe_service(host, port)
                
                self.update_output(f"\n[•] TECHNOLOGY DETECTION:", "header")
                
                if result.get('success', False):
                    self.update_output(f"    Service: {result.get('service', 'unknown')}")
                    
                    detected = result.get('detected', [])
                    if detected:
                        self.update_output(f"\n[•] DETECTED TECHNOLOGIES:", "success")
                        for tech in detected:
                            self.update_output(f"    • {tech}")
                    else:
                        self.update_output(f"\n[•] No specific technologies detected", "warning")
                else:
                    self.update_output(f"    Could not detect technologies", "error")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def security_headers(self):
        """Check security headers"""
        url = self.web_url_var.get().strip()
        if not url:
            self.update_output("[✗] Please enter a URL", "error")
            return
        
        self.update_output(f"\n[🛡️] Checking security headers on: {url}", "info")
        self.update_status(f"Checking security headers on {url}")
        self.start_progress()
        
        def run():
            try:
                host = self.dootseal.web_scanner._extract_hostname(url)
                port = self.dootseal.web_scanner._extract_port(url)
                
                result = self.dootseal.enhanced_core.probe_service(host, port)
                
                self.update_output(f"\n[•] SECURITY HEADERS CHECK:", "header")
                
                if result.get('success', False) and 'headers' in result:
                    headers = result.get('headers', {})
                    
                    security_headers = {
                        'x-frame-options': 'Clickjacking protection',
                        'x-content-type-options': 'MIME sniffing prevention',
                        'x-xss-protection': 'XSS protection',
                        'content-security-policy': 'Content security policy',
                        'strict-transport-security': 'HTTPS enforcement',
                        'referrer-policy': 'Referrer information control'
                    }
                    
                    present = []
                    missing = []
                    
                    for header, description in security_headers.items():
                        if header in headers:
                            present.append((header, headers[header], description))
                        else:
                            missing.append((header, description))
                    
                    if present:
                        self.update_output(f"\n[✓] PRESENT SECURITY HEADERS:", "success")
                        for header, value, description in present:
                            self.update_output(f"    • {header}: {value}")
                    
                    if missing:
                        self.update_output(f"\n[✗] MISSING SECURITY HEADERS:", "error")
                        for header, description in missing:
                            self.update_output(f"    • {header}: {description}")
                else:
                    self.update_output(f"[✗] Could not retrieve headers", "error")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    # ============================================================================
    # PASSWORD AUDITING OPERATIONS
    # ============================================================================
    
    def ssh_bruteforce(self):
        """SSH brute force"""
        target = self.pass_target_var.get().strip()
        if not target:
            target = simpledialog.askstring("Target", "Enter SSH server IP/hostname:")
            if not target:
                return
        
        username = self.pass_user_var.get().strip()
        if not username:
            username = simpledialog.askstring("Username", "Enter username to test:")
            if not username:
                return
        
        passwords = ['password', '123456', 'admin', 'root', 'test']
        
        self.update_output(f"\n[🔑] SSH brute force on {target}", "header")
        self.update_output(f"    Username: {username}")
        self.update_output(f"    Passwords to try: {len(passwords)}")
        self.update_status(f"SSH brute force on {target}")
        self.start_progress()
        
        def run():
            try:
                results = self.dootseal.password_auditor.ssh_bruteforce(target, username, passwords)
                
                self.update_output(f"\n[•] BRUTE FORCE COMPLETE:", "header")
                self.update_output(f"    Attempts: {results.get('attempts', 0)}")
                
                successful = results.get('successful', [])
                if successful:
                    self.update_output(f"\n[!] CREDENTIALS FOUND!", "error")
                    for cred in successful:
                        self.update_output(f"    ✓ {cred['username']}:{cred['password']}", "success")
                else:
                    self.update_output(f"\n[•] No valid credentials found", "warning")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def http_auth_crack(self):
        """HTTP Basic Auth crack"""
        url = simpledialog.askstring("URL", "Enter protected URL:")
        if not url:
            return
        
        username = self.pass_user_var.get().strip()
        if not username:
            username = simpledialog.askstring("Username", "Enter username to test:")
            if not username:
                return
        
        passwords = ['password', 'admin', '123456', 'secret', 'letmein']
        
        self.update_output(f"\n[🌐] HTTP Basic Auth attack on {url}", "header")
        self.update_status(f"HTTP Auth attack on {url}")
        self.start_progress()
        
        def run():
            try:
                results = self.dootseal.password_auditor.http_basic_auth_bruteforce(url, username, passwords)
                
                self.update_output(f"\n[•] ATTACK COMPLETE:", "header")
                self.update_output(f"    Attempts: {results.get('attempts', 0)}")
                
                successful = results.get('successful', [])
                if successful:
                    self.update_output(f"\n[!] CREDENTIALS FOUND!", "error")
                    for cred in successful:
                        self.update_output(f"    ✓ {cred['username']}:{cred['password']}", "success")
                else:
                    self.update_output(f"\n[•] No valid credentials found", "warning")
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def test_credentials(self):
        """Test common credentials"""
        target = self.pass_target_var.get().strip()
        if not target:
            target = simpledialog.askstring("Target", "Enter target IP/hostname:")
            if not target:
                return
        
        self.update_output(f"\n[🧪] Testing common credentials on {target}", "header")
        self.update_status(f"Testing credentials on {target}")
        self.start_progress()
        
        def run():
            try:
                self.update_output("[•] Testing SSH...")
                ssh_result = self.dootseal.enhanced_core.probe_service(target, 22)
                
                if ssh_result.get('success', False):
                    self.update_output(f"[•] SSH port 22 is open", "info")
                else:
                    self.update_output(f"[•] SSH port 22 is closed", "warning")
                
                self.update_output("\n[•] Testing HTTP...")
                try:
                    conn = http.client.HTTPConnection(target, timeout=3)
                    conn.request("GET", "/")
                    response = conn.getresponse()
                    
                    if response.status in [200, 301, 302, 403]:
                        self.update_output(f"    • Web server responding ({response.status})", "info")
                    conn.close()
                except:
                    pass
                
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", "error")
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    # ============================================================================
    # TOOLS OPERATIONS
    # ============================================================================
    
    def generate_report(self):
        """Generate report from last scan"""
        self.update_output(f"\n[📊] Report generation would create a comprehensive PDF/HTML report", "header")
        self.update_output(f"    This feature would compile all scan data into a professional report", "info")
    
    def export_results(self):
        """Export results to file"""
        try:
            self.output_text.config(state=tk.NORMAL)
            content = self.output_text.get(1.0, tk.END)
            self.output_text.config(state=tk.DISABLED)
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=f"dootseal_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("DOOTSEAL v8.1 Output\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 70 + "\n\n")
                    f.write(content)
                
                self.update_output(f"\n[✓] Output exported to {filename}", "success")
                
        except Exception as e:
            self.update_output(f"[✗] Error exporting: {str(e)}", "error")
    
    def show_about(self):
        """Show about information"""
        about_text = f"""
╔═══════════════════════════════════════════════════════════════════╗
║                       DOOTSEAL v8.1                              ║
║                    by Dootmas © 2023                             ║
╚═══════════════════════════════════════════════════════════════════╝

[!] DOOTMAS INTEGRITY SHIELD ACTIVE v8.1
[!] LEGAL: Authorized Auditing Only. Don't be a "Bad Boy". :3

DATABASE STATS:
• MAC Vendors loaded: {self.dootseal.enhanced_core.mac_lookup.stats['total_entries']:,}
• Service probes: {len(self.dootseal.enhanced_core.service_prober.probes)}

FEATURES:
• Advanced MAC Vendor Database
• Service Probing Database
• Network Device Discovery with MAC Vendors
• Enhanced Service Detection
• Comprehensive Security Assessment

REMEMBER: With great power comes great responsibility. :3
"""
        self.update_output(about_text, "header")

# ============================================================================
# MAIN EXECUTION
# ============================================================================
def main():
    """Main function - Dootmas Edition"""
    print("\n" + "="*70)
    print("DOOTSEAL v8.1 - ADVANCED OPERATIONS CENTER")
    print("by Dootmas | Enhanced with MAC DB & Service Probing | Don't be a 'Bad Boy'. :3")
    print("="*70)
    
    print("[•] Checking requirements...")
    
    if NMAP_AVAILABLE:
        print("[✓] Nmap module available")
    else:
        print("[!] Nmap module not installed")
    
    if PARAMIKO_AVAILABLE:
        print("[✓] Paramiko available")
    else:
        print("[!] Paramiko not installed")
    
    if REQUESTS_AVAILABLE:
        print("[✓] Requests available")
    else:
        print("[!] Requests not installed")
    
    print("\n[•] Starting DOOTSEAL v8.1 GUI...")
    
    try:
        root = tk.Tk()
        app = DootsealCompleteGUI(root)
        
        try:
            root.iconbitmap(default='dootseal.ico')
        except:
            pass
        
        root.mainloop()
        
    except Exception as e:
        print(f"\n[✗] GUI Error: {e}")
        print("[!] Make sure you have tkinter installed")
        print("    On Ubuntu/Debian: sudo apt-get install python3-tk")
        print("    On Windows: tkinter is usually included")
        sys.exit(1)

if __name__ == "__main__":
    main()
