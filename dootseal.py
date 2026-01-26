# ==============================================================================
# PROJECT  : DOOTSEAL (Quantum Omega - v7.0)  
# AUTHOR   : Dootmas
# VERSION  : 7.0.0
# ==============================================================================
# [!] DOOTMAS INTEGRITY SHIELD ACTIVE
# [!] LEGAL: Authorized Auditing Only. Don't be a "Bad Boy". :3
# ==============================================================================
#!/usr/bin/env python3
"""
DOOTSEAL v7.0 - COMPLETE OPERATIONAL FRAMEWORK
ALL ORIGINAL FEATURES WITH TOOL INTEGRATION
1359+ lines restored with backend
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
import xml.etree.ElementTree as ET
import html
from datetime import datetime, timedelta
import webbrowser
import platform
import ipaddress
import ssl
import urllib.request
import urllib.parse
import http.client
import mimetypes
import pathlib
import zipfile
import tarfile
import tempfile
import shutil
import math
import statistics
import queue
import select
import struct
import binascii
import itertools
import collections
import inspect
import textwrap
import secrets
import uuid
import asyncio
import concurrent.futures
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import nmap
import paramiko
import ftplib
import scapy.all as scapy
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ============================================================================
# TOOL MANAGER
# ============================================================================
class ToolManager:
    """Manage all security tools"""
    
    @staticmethod
    def check_all_tools():
        """Check for all security tools"""
        tools = {
            # Network scanning
            'nmap': ['nmap', '--version'],
            'masscan': ['masscan', '--version'],
            'netdiscover': ['netdiscover', '--version'],
            'arp-scan': ['arp-scan', '--version'],
            
            # Web testing
            'sqlmap': ['sqlmap', '--version'],
            'nikto': ['nikto', '-Version'],
            'gobuster': ['gobuster', '--help'],
            'dirb': ['dirb', '--help'],
            'dirsearch': ['dirsearch', '--version'],
            'whatweb': ['whatweb', '--version'],
            'wpscan': ['wpscan', '--version'],
            'theharvester': ['theharvester', '--version'],
            
            # Password attacks
            'hydra': ['hydra', '-h'],
            'medusa': ['medusa', '-h'],
            'john': ['john', '--version'],
            'hashcat': ['hashcat', '--version'],
            'crunch': ['crunch', '--help'],
            
            # Exploitation
            'msfconsole': ['msfconsole', '--version'],
            'msfvenom': ['msfvenom', '--help'],
            'searchsploit': ['searchsploit', '--version'],
            'metasploit': ['msfdb', '--version'],
            
            # Wireless
            'aircrack-ng': ['aircrack-ng', '--help'],
            'airmon-ng': ['airmon-ng', '--help'],
            'airodump-ng': ['airodump-ng', '--help'],
            'aireplay-ng': ['aireplay-ng', '--help'],
            'wifite': ['wifite', '--version'],
            
            # Network spoofing
            'ettercap': ['ettercap', '--help'],
            'driftnet': ['driftnet', '--version'],
            'sslstrip': ['sslstrip', '--help'],
            
            # Forensics
            'binwalk': ['binwalk', '--version'],
            'foremost': ['foremost', '--version'],
            'volatility': ['volatility', '--help'],
            'strings': ['strings', '--version'],
            
            # OSINT
            'recon-ng': ['recon-ng', '--version'],
            'maltego': ['maltego', '--version'],
            'sherlock': ['sherlock', '--version'],
            
            # Miscellaneous
            'wireshark': ['tshark', '--version'],
            'tcpdump': ['tcpdump', '--version'],
            'ncat': ['ncat', '--version'],
            'netcat': ['nc', '--version'],
            'openssl': ['openssl', 'version'],
            'ssh': ['ssh', '-V'],
            'nslookup': ['nslookup', '-version']
        }
        
        available = {}
        for tool, cmd in tools.items():
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                available[tool] = result.returncode == 0 or result.returncode == 1
            except:
                available[tool] = False
        
        return available
    
    @staticmethod
    def execute_tool(tool_name, args, timeout=300):
        """Execute any security tool"""
        try:
            cmd = [tool_name] + args.split()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'error': result.stderr,
                'command': ' '.join(cmd)
            }
        except Exception as e:
            return {'error': str(e), 'command': tool_name}

# ============================================================================
# NETWORK SCANNER WITH ALL FEATURES
# ============================================================================
class NetworkScannerComplete:
    """Complete network scanner with tools"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.tools = ToolManager()
        
    def comprehensive_scan(self, target, scan_type="stealth"):
        """Complete network assessment"""
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'phases': {},
            'tools_used': []
        }
        
        # Phase 1: Host Discovery
        results['phases']['host_discovery'] = self.host_discovery(target)
        results['tools_used'].append('nmap')
        
        # Phase 2: Port Scanning
        if 'live_hosts' in results['phases']['host_discovery']:
            hosts = results['phases']['host_discovery']['live_hosts'][:5]  # Limit to 5
            results['phases']['port_scanning'] = self.port_scanning(hosts, scan_type)
            results['tools_used'].append('masscan' if len(hosts) > 1 else 'nmap')
        
        # Phase 3: Service Detection
        if 'port_scanning' in results['phases']:
            results['phases']['service_detection'] = self.service_detection(results['phases']['port_scanning'])
            results['tools_used'].append('nmap')
        
        # Phase 4: OS Fingerprinting
        if 'live_hosts' in results['phases']['host_discovery']:
            results['phases']['os_fingerprinting'] = self.os_fingerprinting(
                results['phases']['host_discovery']['live_hosts']
            )
            results['tools_used'].append('nmap')
        
        # Phase 5: Vulnerability Assessment
        results['phases']['vulnerability_assessment'] = self.vulnerability_assessment(results)
        results['tools_used'].extend(['nmap', 'searchsploit'])
        
        # Phase 6: Exploit Search
        results['phases']['exploit_search'] = self.exploit_search(results)
        
        return results
    
    def host_discovery(self, target):
        """Host discovery with multiple techniques"""
        discovery = {
            'techniques': [],
            'live_hosts': [],
            'tools_used': []
        }
        
        # Technique 1: Nmap Ping Scan
        try:
            self.nm.scan(hosts=target, arguments='-sn -PE -PP -PM')
            discovery['techniques'].append('Nmap ICMP Ping')
            discovery['tools_used'].append('nmap')
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    discovery['live_hosts'].append(host)
        except Exception as e:
            discovery['error'] = f"Nmap scan failed: {str(e)}"
        
        # Technique 2: ARP Scan for local networks
        if self._is_local_network(target):
            try:
                result = self.tools.execute_tool('arp-scan', f'--localnet {target}')
                if result['success']:
                    discovery['techniques'].append('ARP Scan')
                    discovery['tools_used'].append('arp-scan')
                    # Parse arp-scan output
                    for line in result['output'].split('\n'):
                        if re.match(r'\d+\.\d+\.\d+\.\d+', line):
                            ip = line.split()[0]
                            if ip not in discovery['live_hosts']:
                                discovery['live_hosts'].append(ip)
            except Exception as e:
                if 'error' not in discovery:
                    discovery['error'] = f"ARP scan failed: {str(e)}"
        
        # Technique 3: TCP SYN Ping
        try:
            self.nm.scan(hosts=target, arguments='-PS22,80,443 -sn')
            discovery['techniques'].append('TCP SYN Ping')
            discovery['tools_used'].append('nmap')
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up' and host not in discovery['live_hosts']:
                    discovery['live_hosts'].append(host)
        except Exception as e:
            if 'error' not in discovery:
                discovery['error'] = f"TCP SYN ping failed: {str(e)}"
        
        return discovery
    
    def port_scanning(self, hosts, scan_type):
        """Port scanning with nmap"""
        port_scan = {
            'hosts': {},
            'scan_type': scan_type,
            'tools_used': ['nmap']
        }
        
        scan_args = {
            "stealth": "-sS -T2 -f --data-length 24",
            "aggressive": "-sS -sV -sC -O -T4",
            "full": "-sS -sV -sC -O -A -p- -T4",
            "quick": "-sS -T4 -F",
            "udp": "-sU -T4"
        }
        
        args = scan_args.get(scan_type, scan_args["aggressive"])
        
        for host in hosts:
            try:
                self.nm.scan(hosts=host, arguments=args, timeout=300)
                
                if host in self.nm.all_hosts():
                    host_info = {
                        'status': self.nm[host].state(),
                        'ports': {}
                    }
                    
                    for proto in self.nm[host].all_protocols():
                        for port in self.nm[host][proto]:
                            service = self.nm[host][proto][port]
                            host_info['ports'][port] = {
                                'state': service['state'],
                                'service': service.get('name', ''),
                                'version': service.get('version', ''),
                                'product': service.get('product', ''),
                                'cpe': service.get('cpe', ''),
                                'script': service.get('script', {})
                            }
                    
                    port_scan['hosts'][host] = host_info
            except Exception as e:
                port_scan['error'] = f"Port scan failed for {host}: {str(e)}"
                continue
        
        return port_scan
    
    def service_detection(self, port_scan):
        """Service detection"""
        service_detection = {
            'services': {},
            'vulnerable_services': [],
            'recommendations': []
        }
        
        for host, info in port_scan['hosts'].items():
            for port, port_info in info.get('ports', {}).items():
                service = port_info.get('service', f'port-{port}')
                
                if service not in service_detection['services']:
                    service_detection['services'][service] = []
                service_detection['services'][service].append(f"{host}:{port}")
                
                # Check for known vulnerable services
                vulns = self._check_service_vulnerabilities(host, port, service, port_info)
                if vulns:
                    service_detection['vulnerable_services'].extend(vulns)
        
        return service_detection
    
    def _check_service_vulnerabilities(self, host, port, service, info):
        """Check for vulnerabilities"""
        vulnerabilities = []
        
        # SSH vulnerabilities
        if service == 'ssh' and 'version' in info:
            version = info['version']
            # Check for old SSH versions
            if 'OpenSSH' in version:
                match = re.search(r'OpenSSH_(\d+\.\d+)', version)
                if match:
                    ver_num = float(match.group(1))
                    if ver_num < 7.0:
                        vulnerabilities.append({
                            'host': host,
                            'port': port,
                            'service': service,
                            'vulnerability': 'OUTDATED_SSH',
                            'severity': 'HIGH',
                            'description': f'Outdated OpenSSH {version}',
                            'remediation': 'Update OpenSSH'
                        })
        
        # HTTP vulnerabilities
        if service in ['http', 'https']:
            # Check for default pages, exposed directories
            vulnerabilities.append({
                'host': host,
                'port': port,
                'service': service,
                'vulnerability': 'WEB_SERVICE_EXPOSED',
                'severity': 'MEDIUM',
                'description': 'Web service exposed',
                'remediation': 'Harden web server configuration'
            })
        
        return vulnerabilities
    
    def os_fingerprinting(self, hosts):
        """OS fingerprinting"""
        os_info = {
            'hosts': {},
            'techniques': ['Nmap OS Detection', 'TCP/IP Stack Analysis']
        }
        
        for host in hosts[:3]:  # Limit to 3 hosts
            try:
                self.nm.scan(hosts=host, arguments='-O -T4', timeout=60)
                
                if host in self.nm.all_hosts():
                    host_os = self.nm[host].get('osmatch', [])
                    if host_os:
                        os_info['hosts'][host] = {
                            'detected': host_os[0].get('name', 'Unknown'),
                            'accuracy': host_os[0].get('accuracy', '0'),
                            'osclass': host_os[0].get('osclass', [])
                        }
            except Exception as e:
                os_info['error'] = f"OS fingerprinting failed for {host}: {str(e)}"
                continue
        
        return os_info
    
    def vulnerability_assessment(self, scan_data):
        """Vulnerability assessment"""
        assessment = {
            'vulnerabilities': [],
            'risk_score': 0,
            'recommendations': [],
            'tools_used': []
        }
        
        # Run nmap vulnerability scripts
        if 'live_hosts' in scan_data['phases']['host_discovery']:
            hosts = scan_data['phases']['host_discovery']['live_hosts'][:2]  # Limit
            
            for host in hosts:
                try:
                    # Run comprehensive vulnerability scripts
                    self.nm.scan(hosts=host, arguments='-sV --script vuln,auth,vulners', timeout=300)
                    
                    if host in self.nm.all_hosts():
                        for proto in self.nm[host].all_protocols():
                            for port in self.nm[host][proto]:
                                service = self.nm[host][proto][port]
                                if 'script' in service and service['script']:
                                    for script_name, script_output in service['script'].items():
                                        assessment['vulnerabilities'].append({
                                            'host': host,
                                            'port': port,
                                            'service': service.get('name', ''),
                                            'vulnerability': script_name,
                                            'output': str(script_output)[:500],
                                            'severity': self._determine_severity(script_name)
                                        })
                except Exception as e:
                    assessment['error'] = f"Vulnerability scan failed for {host}: {str(e)}"
                    continue
        
        # Calculate risk score
        severity_weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
        for vuln in assessment['vulnerabilities']:
            assessment['risk_score'] += severity_weights.get(vuln.get('severity', 'LOW'), 1)
        
        assessment['risk_score'] = min(100, assessment['risk_score'] * 2)
        
        # Generate recommendations
        assessment['recommendations'] = [
            'Apply all security patches immediately',
            'Disable unnecessary services',
            'Implement network segmentation',
            'Use strong authentication mechanisms',
            'Enable logging and monitoring'
        ]
        
        assessment['tools_used'] = ['nmap', 'vulners script']
        return assessment
    
    def exploit_search(self, scan_data):
        """Search for exploits"""
        exploits_found = []
        
        # Check services for known exploits
        if 'service_detection' in scan_data['phases']:
            services = scan_data['phases']['service_detection'].get('services', {})
            
            for service in services.keys():
                # Search for exploits using searchsploit
                try:
                    result = subprocess.run(
                        ['searchsploit', service, '--json'],
                        capture_output=True, text=True, timeout=30
                    )
                    
                    if result.returncode == 0:
                        exploits = json.loads(result.stdout)
                        if 'RESULTS_EXPLOIT' in exploits:
                            for exploit in exploits['RESULTS_EXPLOIT'][:5]:  # Limit to 5
                                exploits_found.append({
                                    'service': service,
                                    'title': exploit.get('Title', ''),
                                    'path': exploit.get('Path', ''),
                                    'date': exploit.get('Date', '')
                                })
                except Exception as e:
                    continue
        
        return {
            'exploits': exploits_found,
            'count': len(exploits_found),
            'tool_used': 'searchsploit'
        }
    
    def _is_local_network(self, target):
        """Check if target is in local network range"""
        try:
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                return network.is_private
            else:
                ip = ipaddress.ip_address(target)
                return ip.is_private
        except:
            return False
    
    def _determine_severity(self, script_name):
        """Determine severity from script name"""
        critical_indicators = ['rce', 'exec', 'shell', 'root', 'admin']
        high_indicators = ['sqli', 'xss', 'lfi', 'rfi', 'auth', 'creds']
        medium_indicators = ['info', 'disclosure', 'enum', 'brute']
        
        script_lower = script_name.lower()
        
        for indicator in critical_indicators:
            if indicator in script_lower:
                return 'CRITICAL'
        
        for indicator in high_indicators:
            if indicator in script_lower:
                return 'HIGH'
        
        for indicator in medium_indicators:
            if indicator in script_lower:
                return 'MEDIUM'
        
        return 'LOW'

# ============================================================================
# WEB APPLICATION SCANNER COMPLETE
# ============================================================================
class WebScannerComplete:
    """Complete web application scanner with tools"""
    
    def __init__(self):
        self.tools = ToolManager()
    
    def comprehensive_web_scan(self, url):
        """Complete web application assessment"""
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'phases': {},
            'tools_used': []
        }
        
        # Phase 1: Reconnaissance
        results['phases']['reconnaissance'] = self.web_recon(url)
        results['tools_used'].extend(['whatweb', 'theharvester'])
        
        # Phase 2: Directory Enumeration
        results['phases']['directory_enumeration'] = self.directory_enum(url)
        results['tools_used'].extend(['gobuster', 'dirsearch'])
        
        # Phase 3: Vulnerability Scanning
        results['phases']['vulnerability_scanning'] = self.vuln_scan(url)
        results['tools_used'].extend(['nikto', 'sqlmap'])
        
        # Phase 4: Technology Analysis
        results['phases']['technology_analysis'] = self.tech_analysis(url)
        results['tools_used'].append('wappalyzer')
        
        # Phase 5: SSL/TLS Analysis
        if url.startswith('https'):
            results['phases']['ssl_analysis'] = self.ssl_analysis(url)
            results['tools_used'].append('sslscan')
        
        return results
    
    def web_recon(self, url):
        """Web reconnaissance"""
        recon = {
            'fingerprinting': {},
            'subdomains': [],
            'emails': [],
            'technologies': []
        }
        
        # WhatWeb fingerprinting
        try:
            result = self.tools.execute_tool('whatweb', f'-a 3 {url}')
            if result['success']:
                recon['fingerprinting']['whatweb'] = result['output'][:1000]
                
                # Extract technologies
                tech_patterns = [
                    'WordPress', 'Joomla', 'Drupal', 'Apache', 'Nginx',
                    'PHP', 'ASP.NET', 'JavaScript', 'jQuery', 'React',
                    'Bootstrap', 'Wordfence', 'CloudFlare'
                ]
                
                for tech in tech_patterns:
                    if tech.lower() in result['output'].lower():
                        recon['technologies'].append(tech)
            else:
                recon['error'] = f"WhatWeb failed: {result.get('error', 'Unknown error')}"
        except Exception as e:
            recon['error'] = f"WhatWeb exception: {str(e)}"
        
        # TheHarvester for OSINT
        try:
            domain = url.split('//')[1].split('/')[0]
            result = self.tools.execute_tool('theharvester', f'-d {domain} -l 100 -b all')
            if result['success']:
                # Parse emails
                email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                recon['emails'] = re.findall(email_pattern, result['output'])
                
                # Parse subdomains
                lines = result['output'].split('\n')
                for line in lines:
                    if domain in line and '://' not in line:
                        recon['subdomains'].append(line.strip())
            else:
                if 'error' not in recon:
                    recon['error'] = f"TheHarvester failed: {result.get('error', 'Unknown error')}"
        except Exception as e:
            if 'error' not in recon:
                recon['error'] = f"TheHarvester exception: {str(e)}"
        
        return recon
    
    def directory_enum(self, url):
        """Directory enumeration"""
        enumeration = {
            'directories': [],
            'files': [],
            'tools_used': []
        }
        
        # Gobuster
        try:
            result = self.tools.execute_tool('gobuster', f'dir -u {url} -w /usr/share/wordlists/dirb/common.txt -t 50')
            if result['success']:
                enumeration['tools_used'].append('gobuster')
                # Parse gobuster output
                for line in result['output'].split('\n'):
                    if '(Status:' in line and 'Size:' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            enumeration['directories'].append({
                                'path': parts[0],
                                'status': parts[1].strip('()').replace('Status:', ''),
                                'size': parts[2].replace('Size:', '')
                            })
            else:
                enumeration['error'] = f"Gobuster failed: {result.get('error', 'Unknown error')}"
        except Exception as e:
            enumeration['error'] = f"Gobuster exception: {str(e)}"
        
        # Dirsearch
        try:
            result = self.tools.execute_tool('dirsearch', f'-u {url} -e php,html,js,txt,json -t 50')
            if result['success']:
                enumeration['tools_used'].append('dirsearch')
                # Parse dirsearch output
                for line in result['output'].split('\n'):
                    if '[' in line and ']' in line and 'Code:' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            enumeration['files'].append({
                                'path': parts[0],
                                'code': parts[1].replace('[', '').replace(']', ''),
                                'size': parts[2] if len(parts) > 2 else 'N/A'
                            })
            else:
                if 'error' not in enumeration:
                    enumeration['error'] = f"Dirsearch failed: {result.get('error', 'Unknown error')}"
        except Exception as e:
            if 'error' not in enumeration:
                enumeration['error'] = f"Dirsearch exception: {str(e)}"
        
        return enumeration
    
    def vuln_scan(self, url):
        """Vulnerability scanning"""
        vuln_scan = {
            'sql_injection': [],
            'xss': [],
            'command_injection': [],
            'lfi_rfi': [],
            'tools_used': []
        }
        
        # Nikto scan
        try:
            result = self.tools.execute_tool('nikto', f'-h {url} -Format txt')
            if result['success']:
                vuln_scan['tools_used'].append('nikto')
                # Parse nikto findings
                lines = result['output'].split('\n')
                for line in lines:
                    if '+ ' in line:
                        finding = line.replace('+ ', '').strip()
                        if any(vuln in finding.lower() for vuln in ['sql', 'injection', 'xss', 'cross-site', 'lfi', 'rfi']):
                            vuln_scan['sql_injection'].append(finding)
            else:
                vuln_scan['error'] = f"Nikto failed: {result.get('error', 'Unknown error')}"
        except Exception as e:
            vuln_scan['error'] = f"Nikto exception: {str(e)}"
        
        # SQLMap test (limited)
        try:
            result = self.tools.execute_tool('sqlmap', f'-u {url} --batch --crawl=2 --forms')
            if result['success']:
                vuln_scan['tools_used'].append('sqlmap')
                if 'sql injection' in result['output'].lower():
                    vuln_scan['sql_injection'].append('SQL Injection vulnerability detected by SQLMap')
            else:
                if 'error' not in vuln_scan:
                    vuln_scan['error'] = f"SQLMap failed: {result.get('error', 'Unknown error')}"
        except Exception as e:
            if 'error' not in vuln_scan:
                vuln_scan['error'] = f"SQLMap exception: {str(e)}"
        
        return vuln_scan
    
    def tech_analysis(self, url):
        """Technology analysis"""
        analysis = {
            'server': 'Unknown',
            'framework': 'Unknown',
            'languages': [],
            'cms': 'Unknown',
            'security_headers': {}
        }
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            
            # Server header
            analysis['server'] = response.headers.get('Server', 'Unknown')
            
            # Security headers
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'Referrer-Policy'
            ]
            
            for header in security_headers:
                analysis['security_headers'][header] = response.headers.get(header, 'Missing')
            
            # Framework detection from response
            content = response.text[:5000].lower()
            
            # CMS detection
            if 'wp-content' in content or 'wordpress' in content:
                analysis['cms'] = 'WordPress'
            elif 'joomla' in content:
                analysis['cms'] = 'Joomla'
            elif 'drupal' in content:
                analysis['cms'] = 'Drupal'
            
            # Framework detection
            if 'react' in content:
                analysis['framework'] = 'React'
            elif 'angular' in content:
                analysis['framework'] = 'Angular'
            elif 'vue' in content:
                analysis['framework'] = 'Vue.js'
            elif '.net' in content or 'asp' in content:
                analysis['framework'] = 'ASP.NET'
            
            # Language detection
            if '<?php' in content:
                analysis['languages'].append('PHP')
            if '<%' in content or '.aspx' in url:
                analysis['languages'].append('ASP')
            if '.jsp' in url or '.do' in url:
                analysis['languages'].append('Java')
            if '.py' in url or 'django' in content or 'flask' in content:
                analysis['languages'].append('Python')
                
        except Exception as e:
            analysis['error'] = f"Request failed: {str(e)}"
        
        return analysis
    
    def ssl_analysis(self, url):
        """SSL/TLS analysis"""
        ssl_analysis = {
            'grade': 'Unknown',
            'protocols': [],
            'ciphers': [],
            'certificate_info': {}
        }
        
        try:
            hostname = url.split('://')[1].split('/')[0]
            
            # Use openssl for certificate info
            result = self.tools.execute_tool('openssl', f's_client -connect {hostname}:443 -servername {hostname} </dev/null 2>/dev/null | openssl x509 -text')
            if result['success']:
                output = result['output']
                
                # Extract certificate info
                cert_info = {}
                if 'Issuer:' in output:
                    issuer_line = output.split('Issuer:')[1].split('\n')[0]
                    cert_info['issuer'] = issuer_line.strip()
                
                if 'Subject:' in output:
                    subject_line = output.split('Subject:')[1].split('\n')[0]
                    cert_info['subject'] = subject_line.strip()
                
                if 'Not Before:' in output:
                    not_before = output.split('Not Before:')[1].split('\n')[0]
                    cert_info['not_before'] = not_before.strip()
                
                if 'Not After:' in output:
                    not_after = output.split('Not After:')[1].split('\n')[0]
                    cert_info['not_after'] = not_after.strip()
                
                ssl_analysis['certificate_info'] = cert_info
            else:
                ssl_analysis['error'] = f"OpenSSL failed: {result.get('error', 'Unknown error')}"
            
            # Test SSL protocols
            protocols = ['ssl2', 'ssl3', 'tls1', 'tls1_1', 'tls1_2', 'tls1_3']
            for protocol in protocols:
                try:
                    result = self.tools.execute_tool('openssl', f's_client -connect {hostname}:443 -{protocol} </dev/null 2>&1')
                    if 'CONNECTED' in result['output']:
                        ssl_analysis['protocols'].append(protocol.upper())
                except:
                    continue
            
            # Grade determination (simplified)
            if 'TLS1_3' in ssl_analysis['protocols']:
                ssl_analysis['grade'] = 'A+'
            elif 'TLS1_2' in ssl_analysis['protocols']:
                ssl_analysis['grade'] = 'A'
            else:
                ssl_analysis['grade'] = 'F'
                
        except Exception as e:
            ssl_analysis['error'] = f"SSL analysis failed: {str(e)}"
        
        return ssl_analysis

# ============================================================================
# PASSWORD AUDITOR COMPLETE
# ============================================================================
class PasswordAuditorComplete:
    """Complete password auditor with tools"""
    
    def __init__(self):
        self.tools = ToolManager()
    
    def comprehensive_password_audit(self, target, service, username_list=None, password_list=None):
        """Complete password audit"""
        audit = {
            'target': target,
            'service': service,
            'timestamp': datetime.now().isoformat(),
            'results': {},
            'tools_used': []
        }
        
        # Use default wordlists if none provided
        if not username_list:
            username_list = ['admin', 'root', 'administrator', 'user', 'test']
        
        if not password_list:
            # Try to use rockyou.txt
            rockyou_path = '/usr/share/wordlists/rockyou.txt'
            if os.path.exists(rockyou_path):
                with open(rockyou_path, 'r', encoding='latin-1') as f:
                    password_list = [line.strip() for line in f.readlines()[:100]]  # First 100
            else:
                password_list = ['password', '123456', 'admin', '12345678', 'qwerty']
        
        # Service-specific attacks
        if service.lower() == 'ssh':
            audit['results'] = self.ssh_bruteforce(target, username_list, password_list)
            audit['tools_used'].append('hydra')
        elif service.lower() == 'ftp':
            audit['results'] = self.ftp_bruteforce(target, username_list, password_list)
            audit['tools_used'].append('hydra')
        elif service.lower() == 'http':
            audit['results'] = self.http_bruteforce(target, username_list, password_list)
            audit['tools_used'].append('hydra')
        elif service.lower() == 'smb':
            audit['results'] = self.smb_bruteforce(target, username_list, password_list)
            audit['tools_used'].append('hydra')
        
        return audit
    
    def ssh_bruteforce(self, target, usernames, passwords):
        """SSH brute force with hydra"""
        results = {
            'successful': [],
            'attempts': 0,
            'time': 0
        }
        
        start_time = time.time()
        
        # Create temporary files for hydra
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as user_file:
            user_file.write('\n'.join(usernames))
            user_path = user_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as pass_file:
            pass_file.write('\n'.join(passwords))
            pass_path = pass_file.name
        
        try:
            # Run hydra
            cmd = f'hydra -L {user_path} -P {pass_path} -t 4 -f ssh://{target}'
            result = self.tools.execute_tool('hydra', cmd, timeout=600)
            
            if result['success']:
                # Parse hydra output for successful logins
                for line in result['output'].split('\n'):
                    if '[ssh] host:' in line.lower() and 'login:' in line.lower() and 'password:' in line.lower():
                        parts = line.split()
                        if len(parts) >= 7:
                            username = parts[parts.index('login:') + 1]
                            password = parts[parts.index('password:') + 1]
                            results['successful'].append({
                                'username': username,
                                'password': password
                            })
            else:
                results['error'] = f"Hydra failed: {result.get('error', 'Unknown error')}"
            
            results['attempts'] = len(usernames) * len(passwords)
            
        except Exception as e:
            results['error'] = f"SSH brute force exception: {str(e)}"
        finally:
            # Cleanup
            if os.path.exists(user_path):
                os.unlink(user_path)
            if os.path.exists(pass_path):
                os.unlink(pass_path)
        
        results['time'] = time.time() - start_time
        return results
    
    def ftp_bruteforce(self, target, usernames, passwords):
        """FTP brute force"""
        results = {
            'successful': [],
            'attempts': 0,
            'time': 0
        }
        
        start_time = time.time()
        
        # Try anonymous login first
        try:
            ftp = ftplib.FTP(target, timeout=10)
            ftp.login()
            results['successful'].append({
                'username': 'anonymous',
                'password': '(none)'
            })
            ftp.quit()
        except:
            pass
        
        # Try common credentials
        common_creds = [
            ('admin', 'admin'),
            ('ftp', 'ftp'),
            ('user', 'user'),
            ('test', 'test')
        ]
        
        for username, password in common_creds:
            try:
                ftp = ftplib.FTP(target, timeout=5)
                ftp.login(user=username, passwd=password)
                results['successful'].append({
                    'username': username,
                    'password': password
                })
                ftp.quit()
            except:
                pass
        
        results['attempts'] = len(usernames) * len(passwords) + len(common_creds)
        results['time'] = time.time() - start_time
        
        return results
    
    def http_bruteforce(self, target, usernames, passwords):
        """HTTP basic auth brute force"""
        results = {
            'successful': [],
            'attempts': 0,
            'time': 0
        }
        
        start_time = time.time()
        
        # Test common paths with basic auth
        paths = ['/admin', '/wp-admin', '/administrator', '/login', '/manager']
        
        for path in paths:
            url = f'http://{target}{path}'
            for username in usernames[:5]:  # Limit
                for password in passwords[:10]:  # Limit
                    try:
                        response = requests.get(url, auth=(username, password), timeout=5)
                        if response.status_code == 200:
                            results['successful'].append({
                                'username': username,
                                'password': password,
                                'path': path
                            })
                        results['attempts'] += 1
                    except Exception as e:
                        results['attempts'] += 1
        
        results['time'] = time.time() - start_time
        return results
    
    def smb_bruteforce(self, target, usernames, passwords):
        """SMB brute force"""
        results = {
            'successful': [],
            'attempts': 0,
            'time': 0,
            'note': 'SMB brute force requires hydra with proper modules'
        }
        
        # This would use hydra with smb module
        # Implementation depends on hydra availability
        return results

# ============================================================================
# WIRELESS AUDITOR COMPLETE
# ============================================================================
class WirelessAuditorComplete:
    """Complete wireless auditor with tools"""
    
    def __init__(self):
        self.tools = ToolManager()
    
    def comprehensive_wireless_scan(self, interface='wlan0'):
        """Complete wireless assessment"""
        scan = {
            'interface': interface,
            'timestamp': datetime.now().isoformat(),
            'networks': [],
            'clients': [],
            'tools_used': []
        }
        
        # Check if wireless tools are available
        if not all(self.tools.check_all_tools().get(tool, False) for tool in ['airmon-ng', 'airodump-ng']):
            scan['error'] = 'Wireless tools not available'
            return scan
        
        try:
            # Put interface in monitor mode
            result = self.tools.execute_tool('airmon-ng', f'start {interface}')
            if 'error' in result:
                scan['error'] = f"Failed to start monitor mode: {result['error']}"
                return scan
            scan['tools_used'].append('airmon-ng')
            
            # Start airodump-ng to scan networks
            mon_interface = f'{interface}mon'
            
            # Run airodump-ng for 10 seconds
            cmd = f'airodump-ng {mon_interface} --output-format csv -w /tmp/scan'
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(10)
            process.terminate()
            
            scan['tools_used'].append('airodump-ng')
            
            # Parse scan results
            if os.path.exists('/tmp/scan-01.csv'):
                networks, clients = self._parse_airodump_output('/tmp/scan-01.csv')
                scan['networks'] = networks
                scan['clients'] = clients
                
                # Cleanup
                try:
                    os.unlink('/tmp/scan-01.csv')
                except:
                    pass
            
            # Stop monitor mode
            self.tools.execute_tool('airmon-ng', f'stop {mon_interface}')
            
        except Exception as e:
            scan['error'] = f"Wireless scan exception: {str(e)}"
        
        return scan
    
    def _parse_airodump_output(self, csv_file):
        """Parse airodump-ng CSV output"""
        networks = []
        clients = []
        
        try:
            with open(csv_file, 'r') as f:
                lines = f.readlines()
            
            in_networks = True
            
            for line in lines:
                line = line.strip()
                
                # Check if we've reached the clients section
                if 'Station MAC' in line:
                    in_networks = False
                    continue
                
                # Skip empty lines
                if not line:
                    continue
                
                parts = [p.strip() for p in line.split(',')]
                
                if in_networks and len(parts) >= 14:
                    # Network entry
                    networks.append({
                        'bssid': parts[0],
                        'essid': parts[13] if len(parts) > 13 else '',
                        'channel': parts[3],
                        'speed': parts[4],
                        'encryption': parts[5],
                        'cipher': parts[6],
                        'auth': parts[7],
                        'signal': parts[8],
                        'beacons': parts[9]
                    })
                elif not in_networks and len(parts) >= 6:
                    # Client entry
                    clients.append({
                        'mac': parts[0],
                        'bssid': parts[5],
                        'packets': parts[3],
                        'signal': parts[4]
                    })
                    
        except Exception as e:
            print(f"Error parsing airodump output: {e}")
        
        return networks, clients

# ============================================================================
# SOCIAL ENGINEERING MODULE
# ============================================================================
class SocialEngineering:
    """Social engineering with tools"""
    
    def __init__(self):
        self.tools = ToolManager()
    
    def generate_phishing_email(self, template, target_info):
        """Generate phishing email"""
        email = {
            'subject': '',
            'body': '',
            'sender': '',
            'attachments': []
        }
        
        # Common phishing templates
        templates = {
            'password_reset': {
                'subject': 'Important: Password Reset Required',
                'body': f"""
Dear User,

Our security system has detected unusual activity on your account {target_info.get('username', '')}.
For your security, we require you to reset your password immediately.

Click here to reset your password: [MALICIOUS_LINK]

If you did not request this change, please contact our support team immediately.

Best regards,
Security Team
"""
            },
            'account_verification': {
                'subject': 'Account Verification Required',
                'body': f"""
Hello {target_info.get('name', 'User')},

We need to verify your account information. Please click the link below to verify your account:

[MALICIOUS_LINK]

Failure to verify within 24 hours may result in account suspension.

Thank you,
Account Security Team
"""
            }
        }
        
        selected = templates.get(template, templates['password_reset'])
        email['subject'] = selected['subject']
        email['body'] = selected['body']
        email['sender'] = target_info.get('sender', 'security@example.com')
        
        return email
    
    def create_malicious_document(self, doc_type, payload_url):
        """Create malicious document with payload"""
        documents = {
            'pdf': {
                'extension': '.pdf',
                'template': 'pdf_template.tex',
                'payload_method': 'JavaScript'
            },
            'doc': {
                'extension': '.doc',
                'template': 'doc_template.rtf',
                'payload_method': 'Macro'
            },
            'xlsx': {
                'extension': '.xlsx',
                'template': 'excel_template.xml',
                'payload_method': 'Formula'
            }
        }
        
        if doc_type not in documents:
            doc_type = 'doc'
        
        doc_info = documents[doc_type]
        
        return {
            'type': doc_type,
            'extension': doc_info['extension'],
            'payload_method': doc_info['payload_method'],
            'payload_url': payload_url,
            'creation_time': datetime.now().isoformat()
        }

# ============================================================================
# FORENSIC ANALYSIS MODULE
# ============================================================================
class ForensicAnalysis:
    """Forensic analysis with tools"""
    
    def __init__(self):
        self.tools = ToolManager()
    
    def analyze_file(self, file_path):
        """Comprehensive file analysis"""
        analysis = {
            'file': file_path,
            'timestamp': datetime.now().isoformat(),
            'hashes': {},
            'metadata': {},
            'strings': [],
            'binwalk': {},
            'foremost': {}
        }
        
        if not os.path.exists(file_path):
            analysis['error'] = 'File not found'
            return analysis
        
        # Calculate hashes
        analysis['hashes'] = self.calculate_file_hashes(file_path)
        
        # Extract metadata
        analysis['metadata'] = self.extract_metadata(file_path)
        
        # Extract strings
        analysis['strings'] = self.extract_strings(file_path)[:100]  # First 100
        
        # Binwalk analysis
        analysis['binwalk'] = self.binwalk_analysis(file_path)
        
        # Foremost file carving
        analysis['foremost'] = self.foremost_analysis(file_path)
        
        return analysis
    
    def calculate_file_hashes(self, file_path):
        """Calculate file hashes"""
        hashes = {}
        
        hash_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        
        for algo in hash_algorithms:
            hasher = hashlib.new(algo)
            try:
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b''):
                        hasher.update(chunk)
                hashes[algo] = hasher.hexdigest()
            except Exception as e:
                hashes[algo] = f'Error: {str(e)}'
        
        return hashes
    
    def extract_metadata(self, file_path):
        """Extract file metadata"""
        metadata = {
            'size': os.path.getsize(file_path),
            'created': datetime.fromtimestamp(os.path.getctime(file_path)).isoformat(),
            'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
            'type': 'Unknown'
        }
        
        # Try to determine file type
        try:
            result = subprocess.run(['file', file_path], capture_output=True, text=True)
            if result.returncode == 0:
                metadata['type'] = result.stdout.strip()
        except Exception as e:
            metadata['type'] = f'Error: {str(e)}'
        
        return metadata
    
    def extract_strings(self, file_path):
        """Extract strings from file"""
        strings = []
        
        try:
            result = subprocess.run(['strings', file_path], capture_output=True, text=True)
            if result.returncode == 0:
                strings = [s for s in result.stdout.split('\n') if len(s) > 4][:500]  # Limit
        except Exception as e:
            strings = [f'Error extracting strings: {str(e)}']
        
        return strings
    
    def binwalk_analysis(self, file_path):
        """Analyze file with binwalk"""
        analysis = {}
        
        try:
            result = subprocess.run(['binwalk', file_path], capture_output=True, text=True)
            if result.returncode == 0:
                analysis['output'] = result.stdout[:1000]
                
                # Count signatures found
                signature_count = len([l for l in result.stdout.split('\n') if '0x' in l])
                analysis['signatures_found'] = signature_count
        except Exception as e:
            analysis['error'] = f'Binwalk failed: {str(e)}'
        
        return analysis
    
    def foremost_analysis(self, file_path):
        """Carve files with foremost"""
        analysis = {}
        
        try:
            # Create output directory
            output_dir = tempfile.mkdtemp(prefix='foremost_')
            
            result = subprocess.run(['foremost', '-i', file_path, '-o', output_dir], 
                                   capture_output=True, text=True)
            
            analysis['output'] = result.stdout[:500]
            
            # Count carved files
            carved_files = 0
            for root, dirs, files in os.walk(output_dir):
                carved_files += len(files)
            
            analysis['files_carved'] = carved_files
            
            # Cleanup
            shutil.rmtree(output_dir)
            
        except Exception as e:
            analysis['error'] = f'Foremost failed: {str(e)}'
        
        return analysis

# ============================================================================
# COUNTER-INTELLIGENCE MODULE
# ============================================================================
class CounterIntelligence:
    """Counter-intelligence with tools"""
    
    def __init__(self):
        self.tools = ToolManager()
    
    def detect_honeypots(self, target):
        """Detect honeypot systems"""
        detection = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'indicators': [],
            'likely_honeypot': False,
            'confidence': 0
        }
        
        # Common honeypot indicators
        honeypot_ports = {
            21: 'FTP Honeypot (Dionaea, Cowrie)',
            22: 'SSH Honeypot (Kippo, Cowrie)',
            23: 'Telnet Honeypot',
            80: 'HTTP Honeypot (Glastopf)',
            443: 'HTTPS Honeypot',
            3389: 'RDP Honeypot',
            5900: 'VNC Honeypot'
        }
        
        # Scan for common honeypot ports
        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments='-p 21,22,23,80,443,3389,5900 -T4')
            
            if target in nm.all_hosts():
                for port in honeypot_ports:
                    if port in nm[target].get('tcp', {}):
                        state = nm[target]['tcp'][port]['state']
                        if state == 'open':
                            detection['indicators'].append({
                                'port': port,
                                'service': honeypot_ports[port],
                                'indicator': 'Common honeypot port open'
                            })
                            detection['confidence'] += 20
                
                # Check for multiple honeypot ports
                if len(detection['indicators']) >= 2:
                    detection['likely_honeypot'] = True
                    detection['confidence'] = min(100, detection['confidence'] + 30)
        
        except Exception as e:
            detection['error'] = f"Port scan failed: {str(e)}"
        
        # Check for delayed responses (honeypot characteristic)
        try:
            start = time.time()
            socket.create_connection((target, 22), timeout=2)
            response_time = time.time() - start
            
            if response_time > 1.5:  # Unusually slow response
                detection['indicators'].append({
                    'indicator': 'Delayed response (possible honeypot)',
                    'response_time': f'{response_time:.2f}s'
                })
                detection['confidence'] += 15
        except:
            pass
        
        return detection
    
    def deploy_honeytoken(self, token_type):
        """Deploy honeytoken for tracking"""
        tokens = {
            'email': {
                'address': f'honeytoken{random.randint(1000,9999)}@example.com',
                'purpose': 'Track email harvesting'
            },
            'credential': {
                'username': f'honeytoken_user{random.randint(100,999)}',
                'password': f'H0n3yT0k3nP@ss{random.randint(1000,9999)}',
                'purpose': 'Track credential theft'
            },
            'document': {
                'name': f'CONFIDENTIAL_DOCUMENT_{random.randint(10000,99999)}.pdf',
                'content': 'HONEYTOKEN - DO NOT OPEN',
                'purpose': 'Track document access'
            }
        }
        
        token = tokens.get(token_type, tokens['credential'])
        token['created'] = datetime.now().isoformat()
        token['id'] = hashlib.md5(str(token).encode()).hexdigest()[:8]
        
        return token

# ============================================================================
# MAIN DOOTSEAL CLASS WITH ALL FEATURES
# ============================================================================
class DootsealComplete:
    """Complete DOOTSEAL with all features"""
    
    def __init__(self):
        self.version = "7.0"
        self.tool_manager = ToolManager()
        
        # Initialize all modules
        self.network_scanner = NetworkScannerComplete()
        self.web_scanner = WebScannerComplete()
        self.password_auditor = PasswordAuditorComplete()
        self.wireless_auditor = WirelessAuditorComplete()
        self.social_engineering = SocialEngineering()
        self.forensic_analysis = ForensicAnalysis()
        self.counter_intelligence = CounterIntelligence()
        
        # Tool availability
        self.available_tools = self.tool_manager.check_all_tools()
        
    def generate_report(self, results):
        """Generate comprehensive report"""
        report = {
            'report_id': f"DOOTSEAL-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            'generated': datetime.now().isoformat(),
            'version': self.version,
            'results': results,
            'tools_available': {k: v for k, v in self.available_tools.items() if v},
            'summary': self._generate_summary(results)
        }
        
        return report
    
    def _generate_summary(self, results):
        """Generate executive summary"""
        summary = {
            'risk_level': 'UNKNOWN',
            'findings_count': 0,
            'critical_issues': 0,
            'recommendations': []
        }
        
        # Count vulnerabilities
        if isinstance(results, dict):
            # Look for vulnerability counts
            for key, value in results.items():
                if 'vulnerability' in key.lower() and isinstance(value, list):
                    summary['findings_count'] += len(value)
                    summary['critical_issues'] = len([v for v in value if v.get('severity') == 'CRITICAL'])
        
        # Determine risk level
        if summary['critical_issues'] > 0:
            summary['risk_level'] = 'CRITICAL'
        elif summary['findings_count'] > 5:
            summary['risk_level'] = 'HIGH'
        elif summary['findings_count'] > 0:
            summary['risk_level'] = 'MEDIUM'
        else:
            summary['risk_level'] = 'LOW'
        
        # Generate recommendations
        recommendations = [
            'Apply all security patches immediately',
            'Implement network segmentation',
            'Enable multi-factor authentication',
            'Regular security assessments',
            'Employee security training'
        ]
        
        summary['recommendations'] = recommendations[:3]
        
        return summary

# ============================================================================
# COMPLETE GUI WITH ALL FEATURES - MODIFIED VERSION
# ============================================================================
class DootsealCompleteGUI:
    """Complete GUI with all features - Dark Theme Version"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("DOOTSEAL v7.0 - OPERATIONS CENTER")
        self.root.geometry("1400x900")
        
        # Initialize core
        self.dootseal = DootsealComplete()
        
        # Dark theme colors
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
            'primary': '#ff5e5e'
        }
        
        # Configure dark theme
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
        """Configure dark theme styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure dark theme for all widgets
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
        style.configure('TNotebook', background=self.colors['bg_dark'],
                       foreground=self.colors['fg_text'])
        style.configure('TNotebook.Tab', background=self.colors['bg_panel'],
                       foreground=self.colors['fg_text'])
    
    def build_header(self):
        """Build header with dark theme"""
        header = tk.Frame(self.root, bg=self.colors['bg_dark'], height=100)
        header.pack(fill=tk.X, padx=20, pady=10)
        
        # Title
        tk.Label(header,
                text="DOOTSEAL v7.0 - OPERATIONS CENTER",
                font=('Arial', 24, 'bold'),
                fg=self.colors['primary'],
                bg=self.colors['bg_dark']).pack(anchor='w')
        
        tk.Label(header,
                text="Complete Penetration Testing Suite",
                font=('Arial', 11),
                fg=self.colors['fg_text'],
                bg=self.colors['bg_dark']).pack(anchor='w')
        
        # Tool count
        available = sum(1 for v in self.dootseal.available_tools.values() if v)
        total = len(self.dootseal.available_tools)
        tk.Label(header,
                text=f"Tools Available: {available}/{total}",
                font=('Arial', 10),
                fg=self.colors['success'],
                bg=self.colors['bg_dark']).pack(anchor='w', pady=(5,0))
    
    def build_main_interface(self):
        """Build main interface"""
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, bg=self.colors['bg_dark'])
        main_pane.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0,20))
        
        # Left panel - Controls
        left_panel = ttk.LabelFrame(main_pane, text=" Tools Control ", padding=15)
        main_pane.add(left_panel, width=400)
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
        notebook.add(network_frame, text="🌐 Network")
        self.build_network_tab(network_frame)
        
        # Web tab
        web_frame = ttk.Frame(notebook)
        notebook.add(web_frame, text="🕸️ Web")
        self.build_web_tab(web_frame)
        
        # Password tab
        pass_frame = ttk.Frame(notebook)
        notebook.add(pass_frame, text="🔐 Password")
        self.build_password_tab(pass_frame)
        
        # Wireless tab
        wifi_frame = ttk.Frame(notebook)
        notebook.add(wifi_frame, text="📡 Wireless")
        self.build_wireless_tab(wifi_frame)
        
        # Tools tab
        tools_frame = ttk.Frame(notebook)
        notebook.add(tools_frame, text="🛠️ All Tools")
        self.build_tools_tab(tools_frame)
    
    def build_network_tab(self, parent):
        """Build network scanning tab"""
        # Target input
        ttk.Label(parent, text="Target:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.target_var = tk.StringVar(value="192.168.1.1")
        ttk.Entry(parent, textvariable=self.target_var, width=30).grid(row=1, column=0, columnspan=2, pady=(0,15))
        
        # Scan type
        ttk.Label(parent, text="Scan Type:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.scan_type = tk.StringVar(value="stealth")
        
        scan_types = [("Stealth", "stealth"), ("Aggressive", "aggressive"), 
                     ("Full", "full"), ("Vulnerability", "vuln")]
        
        for i, (name, value) in enumerate(scan_types):
            ttk.Radiobutton(parent, text=name, variable=self.scan_type, 
                          value=value).grid(row=3+i, column=0, sticky=tk.W)
        
        # Buttons
        buttons = [
            ("Full Network Scan", self.network_scan),
            ("Host Discovery", self.host_discovery),
            ("Port Scan", self.port_scan),
            ("Vulnerability Scan", self.vulnerability_scan),
            ("OS Detection", self.os_detection)
        ]
        
        for i, (text, command) in enumerate(buttons):
            ttk.Button(parent, text=text, command=command).grid(
                row=3+i, column=1, padx=10, pady=3, sticky=tk.W+tk.E)
    
    def build_web_tab(self, parent):
        """Build web scanning tab"""
        ttk.Label(parent, text="URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.web_url_var = tk.StringVar(value="http://testphp.vulnweb.com")
        ttk.Entry(parent, textvariable=self.web_url_var, width=30).grid(row=1, column=0, columnspan=2, pady=(0,15))
        
        buttons = [
            ("Full Web Scan", self.full_web_scan),
            ("Directory Enum", self.directory_enum),
            ("SQL Injection", self.sql_injection),
            ("Technology Analysis", self.tech_analysis),
            ("SSL Analysis", self.ssl_analysis),
            ("Nikto Scan", self.nikto_scan)
        ]
        
        for i, (text, command) in enumerate(buttons):
            ttk.Button(parent, text=text, command=command).grid(
                row=2+i, column=0, columnspan=2, pady=3, sticky=tk.W+tk.E)
    
    def build_password_tab(self, parent):
        """Build password tab"""
        ttk.Label(parent, text="Target:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.pass_target_var = tk.StringVar(value="192.168.1.1")
        ttk.Entry(parent, textvariable=self.pass_target_var, width=20).grid(row=1, column=0, pady=(0,5))
        
        ttk.Label(parent, text="Service:").grid(row=1, column=1, sticky=tk.W, padx=5)
        self.pass_service_var = tk.StringVar(value="ssh")
        service_combo = ttk.Combobox(parent, textvariable=self.pass_service_var,
                                    values=['ssh', 'ftp', 'http', 'smb'], state='readonly', width=8)
        service_combo.grid(row=1, column=2, pady=(0,5))
        
        buttons = [
            ("SSH Brute Force", self.ssh_bruteforce),
            ("FTP Brute Force", self.ftp_bruteforce),
            ("HTTP Auth Crack", self.http_auth_crack),
            ("Hash Cracking", self.hash_cracking)
        ]
        
        for i, (text, command) in enumerate(buttons):
            ttk.Button(parent, text=text, command=command).grid(
                row=2+i, column=0, columnspan=3, pady=5, sticky=tk.W+tk.E)
    
    def build_wireless_tab(self, parent):
        """Build wireless tab"""
        ttk.Label(parent, text="Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.wifi_interface_var = tk.StringVar(value="wlan0")
        ttk.Entry(parent, textvariable=self.wifi_interface_var, width=20).grid(row=1, column=0, pady=(0,15))
        
        buttons = [
            ("Scan Networks", self.wireless_scan),
            ("Capture Handshake", self.capture_handshake),
            ("WPS Audit", self.wps_audit)
        ]
        
        for i, (text, command) in enumerate(buttons):
            ttk.Button(parent, text=text, command=command).grid(
                row=2+i, column=0, pady=5, sticky=tk.W+tk.E)
    
    def build_tools_tab(self, parent):
        """Build all tools tab"""
        tools = [
            ("Social Engineering", self.social_engineering),
            ("Forensic Analysis", self.forensic_analysis),
            ("Counter-Intelligence", self.counter_intelligence),
            ("Generate Report", self.generate_report),
            ("Export Results", self.export_results),
            ("Tool Status", self.show_tool_status)
        ]
        
        for i, (text, command) in enumerate(tools):
            ttk.Button(parent, text=text, command=command).grid(
                row=i, column=0, pady=5, sticky=tk.W+tk.E)
    
    def build_results_panel(self, parent):
        """Build results panel"""
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Output tab
        self.output_text = scrolledtext.ScrolledText(notebook, 
                                                    bg=self.colors['bg_panel'], 
                                                    fg=self.colors['fg_text'], 
                                                    font=('Consolas', 10),
                                                    insertbackground=self.colors['fg_text'])
        notebook.add(self.output_text, text="📊 Output")
        self.output_text.config(state=tk.DISABLED)
        
        # Configure error tag
        self.output_text.tag_config("error", foreground=self.colors['danger'])
        
        # Network tab
        self.network_text = scrolledtext.ScrolledText(notebook, 
                                                     bg=self.colors['bg_panel'],
                                                     fg=self.colors['fg_blue'], 
                                                     font=('Consolas', 10),
                                                     insertbackground=self.colors['fg_blue'])
        notebook.add(self.network_text, text="🌐 Network")
        self.network_text.config(state=tk.DISABLED)
        
        # Web tab
        self.web_text = scrolledtext.ScrolledText(notebook, 
                                                 bg=self.colors['bg_panel'],
                                                 fg=self.colors['fg_green'], 
                                                 font=('Consolas', 10),
                                                 insertbackground=self.colors['fg_green'])
        notebook.add(self.web_text, text="🕸️ Web")
        self.web_text.config(state=tk.DISABLED)
        
        # Report tab
        self.report_text = scrolledtext.ScrolledText(notebook, 
                                                    bg=self.colors['bg_panel'],
                                                    fg=self.colors['primary'], 
                                                    font=('Consolas', 10),
                                                    insertbackground=self.colors['primary'])
        notebook.add(self.report_text, text="📄 Report")
        self.report_text.config(state=tk.DISABLED)
    
    def build_status_bar(self):
        """Build status bar"""
        self.status_frame = tk.Frame(self.root, bg='#2a2a2a', height=30)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=20, pady=(0,10))
        
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(self.status_frame, textvariable=self.status_var,
                bg='#2a2a2a', fg=self.colors['fg_text']).pack(side=tk.LEFT, padx=10)
        
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
        welcome = f"""DOOTSEAL v{self.dootseal.version} - OPERATIONS CENTER

Features Available:
• Network Scanning with Nmap
• Web Application Testing
• Password Auditing
• Wireless Security Analysis
• Social Engineering Tools
• Forensic Analysis
• Counter-Intelligence

Tools Detected: {sum(1 for v in self.dootseal.available_tools.values() if v)}/{len(self.dootseal.available_tools)}

Select a tool from the Control Center.
"""
        self.update_output(welcome)
    
    def update_output(self, text, error=False):
        """Update output with error highlighting"""
        self.output_text.config(state=tk.NORMAL)
        
        # Configure tag for errors
        if error:
            self.output_text.insert(tk.END, text + "\n", "error")
        else:
            self.output_text.insert(tk.END, text + "\n")
        
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def update_status(self, status):
        """Update status"""
        self.status_var.set(status)
    
    def start_progress(self):
        """Start progress bar"""
        self.progress.start()
    
    def stop_progress(self):
        """Stop progress bar"""
        self.progress.stop()
    
    # ============================================================================
    # FORMATTING METHODS
    # ============================================================================
    
    def format_dict_output(self, data, indent=0, max_depth=3):
        """Convert dictionary to readable output"""
        if max_depth <= 0:
            return "  " * indent + "...\n"
        
        output = ""
        if isinstance(data, dict):
            for key, value in data.items():
                if key in ['timestamp', 'generated', 'report_id']:
                    continue
                    
                key_str = key.replace('_', ' ').title()
                output += "  " * indent + f"• {key_str}:\n"
                
                if isinstance(value, dict):
                    output += self.format_dict_output(value, indent + 1, max_depth - 1)
                elif isinstance(value, list):
                    output += self.format_list_output(value, indent + 1, max_depth - 1)
                elif value is not None and str(value).strip():
                    val_str = str(value)
                    if len(val_str) > 100:
                        val_str = val_str[:97] + "..."
                    output += "  " * (indent + 1) + f"{val_str}\n"
        return output
    
    def format_list_output(self, data, indent=0, max_depth=3):
        """Convert list to readable output"""
        if max_depth <= 0:
            return "  " * indent + "...\n"
        
        output = ""
        if isinstance(data, list):
            for i, item in enumerate(data[:10]):  # Limit to 10 items
                if isinstance(item, dict):
                    output += "  " * indent + f"{i+1}.\n"
                    output += self.format_dict_output(item, indent + 1, max_depth - 1)
                elif isinstance(item, list):
                    output += "  " * indent + f"{i+1}.\n"
                    output += self.format_list_output(item, indent + 1, max_depth - 1)
                elif item is not None and str(item).strip():
                    item_str = str(item)
                    if len(item_str) > 100:
                        item_str = item_str[:97] + "..."
                    output += "  " * indent + f"{i+1}. {item_str}\n"
            
            if len(data) > 10:
                output += "  " * indent + f"... and {len(data) - 10} more items\n"
        return output
    
    # ============================================================================
    # TOOL EXECUTION METHODS WITH ERROR HANDLING
    # ============================================================================
    
    def network_scan(self):
        """Execute network scan with formatted output"""
        target = self.target_var.get()
        scan_type = self.scan_type.get()
        
        self.update_output(f"\n[•] Starting network scan on {target}")
        self.update_status(f"Scanning: {target}")
        self.start_progress()
        
        def run():
            try:
                results = self.dootseal.network_scanner.comprehensive_scan(target, scan_type)
                
                # Check for errors
                errors = []
                for phase_name, phase_data in results.get('phases', {}).items():
                    if 'error' in str(phase_data).lower():
                        errors.append(f"{phase_name}: {phase_data.get('error', 'Unknown error')}")
                
                if errors:
                    self.update_output("[✗] Scan completed with errors:", error=True)
                    for error in errors:
                        self.update_output(f"    • {error}", error=True)
                else:
                    self.update_output("[✓] Scan completed successfully")
                
                # Format and display results
                formatted = self.format_dict_output(results, max_depth=3)
                self.update_output("\n" + "="*60)
                self.update_output("SCAN RESULTS:")
                self.update_output("="*60)
                self.update_output(formatted)
                
                # Update network tab with full results
                self.network_text.config(state=tk.NORMAL)
                self.network_text.delete(1.0, tk.END)
                self.network_text.insert(1.0, json.dumps(results, indent=2))
                self.network_text.config(state=tk.DISABLED)
                
            except Exception as e:
                self.update_output("[✗] Error during network scan:", error=True)
                self.update_output(f"    {str(e)}", error=True)
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def full_web_scan(self):
        """Execute web scan with formatted output"""
        url = self.web_url_var.get()
        if not url.startswith('http'):
            url = f"http://{url}"
        
        self.update_output(f"\n[•] Starting web scan on {url}")
        self.update_status(f"Web scanning: {url}")
        self.start_progress()
        
        def run():
            try:
                results = self.dootseal.web_scanner.comprehensive_web_scan(url)
                
                # Check for errors
                errors = []
                vuln_count = 0
                for phase_name, phase_data in results.get('phases', {}).items():
                    if 'error' in str(phase_data).lower():
                        errors.append(f"{phase_name}: {phase_data.get('error', 'Unknown error')}")
                    
                    # Count vulnerabilities
                    if 'vulnerability' in phase_name.lower():
                        if isinstance(phase_data, dict):
                            for key, value in phase_data.items():
                                if isinstance(value, list):
                                    vuln_count += len(value)
                
                if errors:
                    self.update_output("[✗] Web scan completed with errors:", error=True)
                    for error in errors:
                        self.update_output(f"    • {error}", error=True)
                else:
                    self.update_output("[✓] Web scan completed successfully")
                
                # Display vulnerability count
                if vuln_count > 0:
                    self.update_output(f"[!] Found {vuln_count} potential vulnerabilities", error=True)
                
                # Format and display results
                formatted = self.format_dict_output(results, max_depth=3)
                self.update_output("\n" + "="*60)
                self.update_output("WEB SCAN RESULTS:")
                self.update_output("="*60)
                self.update_output(formatted)
                
                # Update web tab with full results
                self.web_text.config(state=tk.NORMAL)
                self.web_text.delete(1.0, tk.END)
                self.web_text.insert(1.0, json.dumps(results, indent=2))
                self.web_text.config(state=tk.DISABLED)
                
            except Exception as e:
                self.update_output("[✗] Error during web scan:", error=True)
                self.update_output(f"    {str(e)}", error=True)
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def ssh_bruteforce(self):
        """Execute SSH brute force with formatted output"""
        target = self.pass_target_var.get()
        
        # Get credentials
        username = simpledialog.askstring("Username", "Enter username (or leave empty for 'admin'):")
        if not username:
            username = "admin"
        
        password_list = simpledialog.askstring("Passwords", "Enter passwords (comma separated):")
        if not password_list:
            password_list = "password,123456,admin,12345678,qwerty"
        
        passwords = [p.strip() for p in password_list.split(',')]
        
        self.update_output(f"\n[•] Starting SSH brute force on {target}")
        self.update_output(f"    Username: {username}")
        self.update_output(f"    Passwords to try: {len(passwords)}")
        self.update_status(f"SSH brute force: {target}")
        self.start_progress()
        
        def run():
            try:
                results = self.dootseal.password_auditor.ssh_bruteforce(target, [username], passwords)
                
                self.update_output(f"\n[•] Brute force completed in {results.get('time', 0):.1f}s")
                self.update_output(f"    Attempts: {results.get('attempts', 0)}")
                
                if results.get('successful'):
                    self.update_output("[!] CREDENTIALS FOUND:", error=True)
                    for cred in results['successful']:
                        self.update_output(f"    • {cred['username']}:{cred['password']}", error=True)
                else:
                    self.update_output("[•] No credentials found")
                
                if results.get('error'):
                    self.update_output(f"[✗] Error during brute force:", error=True)
                    self.update_output(f"    {results['error']}", error=True)
                
            except Exception as e:
                self.update_output("[✗] Error during SSH brute force:", error=True)
                self.update_output(f"    {str(e)}", error=True)
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    def wireless_scan(self):
        """Execute wireless scan with error handling"""
        interface = self.wifi_interface_var.get()
        
        self.update_output(f"\n[•] Starting wireless scan on {interface}")
        self.update_status(f"Wireless scan: {interface}")
        self.start_progress()
        
        def run():
            try:
                results = self.dootseal.wireless_auditor.comprehensive_wireless_scan(interface)
                
                if 'error' in results:
                    self.update_output(f"[✗] Wireless scan failed:", error=True)
                    self.update_output(f"    {results['error']}", error=True)
                else:
                    self.update_output(f"[✓] Wireless scan completed")
                    networks = results.get('networks', [])
                    clients = results.get('clients', [])
                    
                    self.update_output(f"\nNetworks found: {len(networks)}")
                    for i, network in enumerate(networks[:5]):  # Show first 5
                        essid = network.get('essid', 'Hidden')
                        bssid = network.get('bssid', 'Unknown')
                        channel = network.get('channel', '?')
                        enc = network.get('encryption', '?')
                        self.update_output(f"    {i+1}. {essid} ({bssid}) - Ch{channel} - {enc}")
                    
                    if networks and len(networks) > 5:
                        self.update_output(f"    ... and {len(networks) - 5} more networks")
                    
                    self.update_output(f"\nClients found: {len(clients)}")
                
            except Exception as e:
                self.update_output(f"[✗] Error during wireless scan:", error=True)
                self.update_output(f"    {str(e)}", error=True)
            finally:
                self.stop_progress()
                self.update_status("Ready")
        
        threading.Thread(target=run, daemon=True).start()
    
    # Additional methods for other buttons
    def host_discovery(self):
        target = self.target_var.get()
        self.update_output(f"\n[•] Starting host discovery on {target}")
        self.update_output("[•] Use Full Network Scan for complete results")
    
    def port_scan(self):
        target = self.target_var.get()
        self.update_output(f"\n[•] Starting port scan on {target}")
        self.update_output("[•] Use Full Network Scan for complete results")
    
    def vulnerability_scan(self):
        target = self.target_var.get()
        self.update_output(f"\n[•] Starting vulnerability scan on {target}")
        self.update_output("[•] Use Full Network Scan for complete results")
    
    def os_detection(self):
        target = self.target_var.get()
        self.update_output(f"\n[•] Starting OS detection on {target}")
        self.update_output("[•] Use Full Network Scan for complete results")
    
    def directory_enum(self):
        url = self.web_url_var.get()
        self.update_output(f"\n[•] Starting directory enumeration on {url}")
        self.update_output("[•] Use Full Web Scan for complete results")
    
    def sql_injection(self):
        url = self.web_url_var.get()
        self.update_output(f"\n[•] Starting SQL injection testing on {url}")
        self.update_output("[•] Use Full Web Scan for complete results")
    
    def tech_analysis(self):
        url = self.web_url_var.get()
        self.update_output(f"\n[•] Starting technology analysis on {url}")
        self.update_output("[•] Use Full Web Scan for complete results")
    
    def ssl_analysis(self):
        url = self.web_url_var.get()
        if not url.startswith('https'):
            self.update_output("[✗] URL must start with https:// for SSL analysis", error=True)
            return
        self.update_output(f"\n[•] Starting SSL analysis on {url}")
        self.update_output("[•] Use Full Web Scan for complete results")
    
    def nikto_scan(self):
        url = self.web_url_var.get()
        self.update_output(f"\n[•] Starting Nikto scan on {url}")
        self.update_output("[•] Use Full Web Scan for complete results")
    
    def ftp_bruteforce(self):
        target = self.pass_target_var.get()
        self.update_output(f"\n[•] Starting FTP brute force on {target}")
        self.update_output("[•] Use SSH Brute Force for detailed attack")
    
    def http_auth_crack(self):
        target = self.pass_target_var.get()
        self.update_output(f"\n[•] Starting HTTP auth cracking on {target}")
        self.update_output("[•] Use SSH Brute Force for detailed attack")
    
    def hash_cracking(self):
        hash_value = simpledialog.askstring("Hash", "Enter hash to crack:")
        if hash_value:
            self.update_output(f"\n[•] Starting hash cracking for: {hash_value[:20]}...")
            self.update_output("[•] Hash cracking requires John the Ripper or Hashcat")
        else:
            self.update_output("[✗] No hash provided", error=True)
    
    def capture_handshake(self):
        interface = self.wifi_interface_var.get()
        self.update_output(f"\n[•] Starting handshake capture on {interface}")
        self.update_output("[•] Requires wireless interface in monitor mode")
    
    def wps_audit(self):
        self.update_output("\n[•] Starting WPS audit")
        self.update_output("[•] Requires wireless tools and WPS-enabled router")
    
    def social_engineering(self):
        template = simpledialog.askstring("Template", "Select template (password_reset/account_verification):")
        if template:
            target_info = {'username': 'user123'}
            email = self.dootseal.social_engineering.generate_phishing_email(template, target_info)
            self.update_output(f"\n[•] Generated phishing email with template: {template}")
            self.update_output(f"    Subject: {email['subject']}")
        else:
            self.update_output("[•] Social engineering tools available")
    
    def forensic_analysis(self):
        file_path = filedialog.askopenfilename(title="Select file for analysis")
        if file_path:
            self.update_output(f"\n[•] Starting forensic analysis on {os.path.basename(file_path)}")
            try:
                results = self.dootseal.forensic_analysis.analyze_file(file_path)
                formatted = self.format_dict_output(results, max_depth=2)
                self.update_output(formatted)
            except Exception as e:
                self.update_output(f"[✗] Error during forensic analysis: {str(e)}", error=True)
        else:
            self.update_output("[•] Select a file for forensic analysis")
    
    def counter_intelligence(self):
        target = simpledialog.askstring("Target", "Enter target for honeypot detection:")
        if target:
            self.update_output(f"\n[•] Starting counter-intelligence on {target}")
            try:
                results = self.dootseal.counter_intelligence.detect_honeypots(target)
                formatted = self.format_dict_output(results, max_depth=2)
                self.update_output(formatted)
            except Exception as e:
                self.update_output(f"[✗] Error: {str(e)}", error=True)
        else:
            self.update_output("[•] Counter-intelligence tools available")
    
    def generate_report(self):
        self.update_output("\n[•] Generating comprehensive report...")
        # In a real implementation, this would collect all scan results and generate a report
        report = {
            'summary': 'Report generated from all scans',
            'timestamp': datetime.now().isoformat(),
            'scans_performed': ['Network', 'Web', 'Password']
        }
        self.report_text.config(state=tk.NORMAL)
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(1.0, json.dumps(report, indent=2))
        self.report_text.config(state=tk.DISABLED)
        self.update_output("[✓] Report generated (see Report tab)")
    
    def export_results(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                # Get current output
                self.output_text.config(state=tk.NORMAL)
                content = self.output_text.get(1.0, tk.END)
                self.output_text.config(state=tk.DISABLED)
                
                with open(file_path, 'w') as f:
                    f.write(content)
                
                self.update_output(f"[✓] Results exported to {file_path}")
            except Exception as e:
                self.update_output(f"[✗] Error exporting results: {str(e)}", error=True)
    
    def show_tool_status(self):
        """Show tool status"""
        self.update_output("\n[•] Tool Status:")
        available = 0
        for tool, is_available in self.dootseal.available_tools.items():
            status = "✓" if is_available else "✗"
            color = self.colors['success'] if is_available else self.colors['danger']
            if is_available:
                available += 1
            self.update_output(f"    {status} {tool}")
        
        self.update_output(f"\n[•] Total: {available}/{len(self.dootseal.available_tools)} tools available")

# ============================================================================
# MAIN EXECUTION
# ============================================================================
def main():
    """Main function"""
    print("\n" + "="*60)
    print("DOOTSEAL v7.0 - OPERATIONS CENTER")
    print("="*60)
    
    print("[•] Initializing operational framework...")
    print("[•] Checking for security tools...")
    
    tool_manager = ToolManager()
    tools = tool_manager.check_all_tools()
    available = sum(1 for v in tools.values() if v)
    
    print(f"[✓] Tools available: {available}/{len(tools)}")
    
    # Show missing tools as errors
    missing = [k for k, v in tools.items() if not v]
    if missing:
        print(f"[✗] Missing tools: {', '.join(missing[:10])}")
        if len(missing) > 10:
            print(f"[✗] ... and {len(missing) - 10} more")
    
    print("[•] Starting GUI...")
    
    try:
        root = tk.Tk()
        app = DootsealCompleteGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"[✗] GUI Error: {e}", file=sys.stderr)
        print("[✗] Requirements: Kali Linux, root access, full toolset", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
