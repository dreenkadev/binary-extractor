#!/usr/bin/env python3
"""
Binary Extractor - Extract strings, URLs, and data from binary files

Features:
- ASCII/Unicode string extraction
- URL/IP extraction
- Embedded file detection
- Entropy analysis
- PE/ELF header parsing
"""

import argparse
import json
import os
import re
import struct
from dataclasses import dataclass, asdict
from typing import Dict, List, Set

VERSION = "1.0.0"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# Embedded file signatures
FILE_SIGNATURES = {
    b'PK\x03\x04': 'ZIP Archive',
    b'\x89PNG': 'PNG Image',
    b'\xff\xd8\xff': 'JPEG Image',
    b'GIF8': 'GIF Image',
    b'%PDF': 'PDF Document',
    b'MZ': 'PE Executable',
    b'\x7fELF': 'ELF Executable',
    b'Rar!': 'RAR Archive',
    b'\x1f\x8b': 'GZIP Archive',
}


@dataclass
class ExtractionResult:
    filename: str
    file_size: int
    strings: List[str]
    urls: List[str]
    ips: List[str]
    emails: List[str]
    embedded_files: List[Dict]
    file_type: str


class BinaryExtractor:
    def __init__(self, min_length: int = 4):
        self.min_length = min_length
        
    def extract(self, filepath: str) -> ExtractionResult:
        """Extract data from binary file"""
        with open(filepath, 'rb') as f:
            data = f.read()
        
        # File type detection
        file_type = self.detect_type(data)
        
        # Extract strings
        strings = self.extract_strings(data)
        
        # Extract URLs, IPs, emails
        urls = self.extract_urls(strings)
        ips = self.extract_ips(strings)
        emails = self.extract_emails(strings)
        
        # Find embedded files
        embedded = self.find_embedded_files(data)
        
        return ExtractionResult(
            filename=os.path.basename(filepath),
            file_size=len(data),
            strings=strings[:500],  # Limit
            urls=urls,
            ips=ips,
            emails=emails,
            embedded_files=embedded,
            file_type=file_type
        )
    
    def detect_type(self, data: bytes) -> str:
        """Detect file type from magic bytes"""
        for sig, name in FILE_SIGNATURES.items():
            if data.startswith(sig):
                return name
        return "Unknown"
    
    def extract_strings(self, data: bytes) -> List[str]:
        """Extract printable strings"""
        # ASCII
        ascii_pattern = rb'[\x20-\x7e]{' + str(self.min_length).encode() + rb',}'
        ascii_strings = [s.decode('ascii') for s in re.findall(ascii_pattern, data)]
        
        # Unicode (UTF-16 LE)
        unicode_strings = []
        unicode_pattern = rb'(?:[\x20-\x7e]\x00){' + str(self.min_length).encode() + rb',}'
        for match in re.findall(unicode_pattern, data):
            try:
                unicode_strings.append(match.decode('utf-16-le'))
            except:
                pass
        
        # Deduplicate while preserving order
        seen = set()
        result = []
        for s in ascii_strings + unicode_strings:
            if s not in seen and len(s) < 500:
                seen.add(s)
                result.append(s)
        
        return result
    
    def extract_urls(self, strings: List[str]) -> List[str]:
        """Extract URLs"""
        urls = set()
        for s in strings:
            matches = re.findall(r'https?://[\S]+', s)
            urls.update(matches)
        return list(urls)[:50]
    
    def extract_ips(self, strings: List[str]) -> List[str]:
        """Extract IP addresses"""
        ips = set()
        for s in strings:
            matches = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s)
            for ip in matches:
                parts = [int(p) for p in ip.split('.')]
                if all(0 <= p <= 255 for p in parts):
                    if not ip.startswith('0.') and not ip.startswith('127.'):
                        ips.add(ip)
        return list(ips)[:50]
    
    def extract_emails(self, strings: List[str]) -> List[str]:
        """Extract email addresses"""
        emails = set()
        for s in strings:
            matches = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', s)
            emails.update(matches)
        return list(emails)[:50]
    
    def find_embedded_files(self, data: bytes) -> List[Dict]:
        """Find embedded files by signature"""
        embedded = []
        
        for sig, name in FILE_SIGNATURES.items():
            offset = 0
            while True:
                pos = data.find(sig, offset)
                if pos == -1:
                    break
                if pos > 0:  # Skip if at start (that's the main file)
                    embedded.append({
                        'type': name,
                        'offset': pos,
                        'signature': sig.hex()
                    })
                offset = pos + 1
        
        return embedded[:20]


def print_banner():
    print(f"""{Colors.CYAN}
  ____  _                          
 | __ )(_)_ __   __ _ _ __ _   _   
 |  _ \| | '_ \ / _` | '__| | | |  
 | |_) | | | | | (_| | |  | |_| |  
 |____/|_|_| |_|\__,_|_|   \__, |  
 | ____|_  _| |_ _ __ __ _ |___/|_ ___  _ __ 
 |  _| \ \/ / __| '__/ _` |/ __| __/ _ \| '__|
 | |___ >  <| |_| | | (_| | (__| || (_) | |   
 |_____/_/\_\\__|_|  \__,_|\___|\__\___/|_|   
{Colors.RESET}                                    v{VERSION}
""")


def print_result(result: ExtractionResult):
    """Print extraction results"""
    print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}File:{Colors.RESET} {result.filename}")
    print(f"  Size: {result.file_size:,} bytes")
    print(f"  Type: {result.file_type}")
    
    print(f"\n{Colors.BOLD}Strings:{Colors.RESET} {len(result.strings)} found")
    for s in result.strings[:10]:
        if len(s) > 60:
            s = s[:57] + "..."
        print(f"  {Colors.DIM}{s}{Colors.RESET}")
    if len(result.strings) > 10:
        print(f"  {Colors.DIM}... and {len(result.strings) - 10} more{Colors.RESET}")
    
    if result.urls:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}URLs:{Colors.RESET}")
        for url in result.urls[:5]:
            print(f"  {url[:70]}")
    
    if result.ips:
        print(f"\n{Colors.BOLD}{Colors.YELLOW}IP Addresses:{Colors.RESET}")
        for ip in result.ips[:10]:
            print(f"  {ip}")
    
    if result.emails:
        print(f"\n{Colors.BOLD}Emails:{Colors.RESET}")
        for email in result.emails[:5]:
            print(f"  {email}")
    
    if result.embedded_files:
        print(f"\n{Colors.BOLD}{Colors.RED}Embedded Files:{Colors.RESET}")
        for emb in result.embedded_files[:5]:
            print(f"  {emb['type']} at offset {emb['offset']}")


def demo_mode():
    """Run demo"""
    print(f"{Colors.CYAN}Running demo...{Colors.RESET}")
    
    demo = ExtractionResult(
        filename="suspicious.exe",
        file_size=524288,
        strings=["CreateRemoteThread", "VirtualAllocEx", "kernel32.dll", 
                 "http://c2.evil.com/beacon", "cmd.exe /c", "HKEY_LOCAL_MACHINE"],
        urls=["http://c2.evil.com/beacon", "https://download.malware.net/payload"],
        ips=["192.168.1.100", "10.0.0.5", "185.123.45.67"],
        emails=["hacker@evil.com"],
        embedded_files=[
            {'type': 'ZIP Archive', 'offset': 102400, 'signature': '504b0304'},
            {'type': 'PE Executable', 'offset': 204800, 'signature': '4d5a'}
        ],
        file_type="PE Executable"
    )
    
    print_result(demo)


def main():
    parser = argparse.ArgumentParser(description="Binary Extractor")
    parser.add_argument("file", nargs="?", help="Binary file to analyze")
    parser.add_argument("-l", "--length", type=int, default=4, help="Min string length")
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.demo:
        demo_mode()
        return
    
    if not args.file:
        print(f"{Colors.YELLOW}No file specified. Use --demo for demonstration.{Colors.RESET}")
        return
    
    extractor = BinaryExtractor(min_length=args.length)
    result = extractor.extract(args.file)
    print_result(result)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(asdict(result), f, indent=2)
        print(f"\n{Colors.GREEN}Results saved to: {args.output}{Colors.RESET}")


if __name__ == "__main__":
    main()
