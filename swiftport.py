#!/usr/bin/env python3
"""
SwiftPort Scanner - A lightweight network port scanner
Author: Scott Thornton
"""

import argparse
import socket
import sys
import time
import ipaddress
import concurrent.futures
from colorama import init, Fore, Style

# Initialize colorama
init()

def print_banner():
    """Print the scanner banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════╗
║  {Fore.GREEN}SwiftPort Scanner v1.0{Fore.CYAN}                 ║
║  {Fore.WHITE}Fast, lightweight network port scanner{Fore.CYAN}  ║
╚═══════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def is_valid_ip(ip):
    """Check if the provided IP address is valid"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_network(network):
    """Check if the provided network is valid"""
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False

def scan_port(ip, port, timeout):
    """Scan a single port on the specified IP"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = "unknown"
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    pass
                return port, True, service
            return port, False, None
    except socket.error:
        return port, False, None

def scan_host(ip, ports, timeout, max_workers):
    """Scan multiple ports on a host"""
    open_ports = []
    
    print(f"\n{Fore.BLUE}[*] {Fore.WHITE}Scanning host: {Fore.YELLOW}{ip}{Style.RESET_ALL}")
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port 
            for port in ports
        }
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_port)):
            port, is_open, service = future.result()
            if i % 500 == 0 and i > 0:
                print(f"{Fore.BLUE}[*] {Fore.WHITE}Scanned {i}/{len(ports)} ports...")
            
            if is_open:
                open_ports.append((port, service))
                if service != "unknown":
                    print(f"{Fore.GREEN}[+] {Fore.WHITE}Port {Fore.GREEN}{port}{Fore.WHITE} is open: {Fore.CYAN}{service}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] {Fore.WHITE}Port {Fore.GREEN}{port}{Fore.WHITE} is open{Style.RESET_ALL}")

    duration = time.time() - start_time
    return open_ports, duration

def main():
    parser = argparse.ArgumentParser(description="SwiftPort Scanner - A lightweight network port scanner")
    parser.add_argument("target", help="Target IP address, hostname, or network (CIDR notation)")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (e.g., '1-1000' or '22,80,443')")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout in seconds (default: 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Maximum number of worker threads (default: 100)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between each host scan in seconds (default: 0)")
    
    args = parser.parse_args()
    
    print_banner()
    
    # Parse target
    target = args.target
    
    # Parse ports
    ports_to_scan = []
    for part in args.ports.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports_to_scan.extend(range(start, end + 1))
        else:
            ports_to_scan.append(int(part))
    
    # Check if target is IP, network, or hostname
    if is_valid_ip(target):
        hosts = [target]
    elif is_valid_network(target):
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        print(f"{Fore.BLUE}[*] {Fore.WHITE}Scanning network {Fore.YELLOW}{target}{Fore.WHITE} ({len(hosts)} hosts){Style.RESET_ALL}")
    else:
        try:
            ip = socket.gethostbyname(target)
            hosts = [ip]
            print(f"{Fore.BLUE}[*] {Fore.WHITE}Hostname {Fore.YELLOW}{target}{Fore.WHITE} resolved to {Fore.YELLOW}{ip}{Style.RESET_ALL}")
        except socket.gaierror:
            print(f"{Fore.RED}[!] {Fore.WHITE}Could not resolve hostname: {Fore.RED}{target}{Style.RESET_ALL}")
            return
    
    total_open_ports = 0
    start_time_all = time.time()
    
    print(f"{Fore.BLUE}[*] {Fore.WHITE}Scanning {len(ports_to_scan)} ports per host{Style.RESET_ALL}")
    
    for i, host in enumerate(hosts):
        if i > 0 and args.delay > 0:
            time.sleep(args.delay)
            
        open_ports, duration = scan_host(host, ports_to_scan, args.timeout, args.workers)
        total_open_ports += len(open_ports)
        
        if open_ports:
            print(f"{Fore.BLUE}[*] {Fore.WHITE}Found {Fore.GREEN}{len(open_ports)}{Fore.WHITE} open ports on {Fore.YELLOW}{host}{Fore.WHITE} in {duration:.2f} seconds{Style.RESET_ALL}")
        else:
            print(f"{Fore.BLUE}[*] {Fore.WHITE}No open ports found on {Fore.YELLOW}{host}{Fore.WHITE} in {duration:.2f} seconds{Style.RESET_ALL}")
    
    total_duration = time.time() - start_time_all
    print(f"\n{Fore.BLUE}[*] {Fore.WHITE}Scan completed: {Fore.GREEN}{total_open_ports}{Fore.WHITE} open ports found across {Fore.YELLOW}{len(hosts)}{Fore.WHITE} hosts in {total_duration:.2f} seconds{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] {Fore.WHITE}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
