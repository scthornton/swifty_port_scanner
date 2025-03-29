#!/usr/bin/env python3
"""
SwiftPort Scanner - A lightweight network port scanner
Author: Scott Thornton

This script provides a fast, multi-threaded port scanning tool that can scan
individual hosts or entire networks for open ports. It identifies common services
running on open ports and provides color-coded output for better readability.
"""

import argparse
import socket
import sys
import time
import ipaddress
import concurrent.futures
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal output
init()


def print_banner():
    """
    Print the application banner with styling.

    This function displays the program name, version, and a brief description
    using colored text via the colorama library.
    """
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════╗
║  {Fore.GREEN}SwiftPort Scanner v1.0{Fore.CYAN}                 ║
║  {Fore.WHITE}Fast, lightweight network port scanner{Fore.CYAN}  ║
╚═══════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)


def is_valid_ip(ip):
    """
    Check if the provided IP address is valid.

    Args:
        ip (str): The IP address to validate

    Returns:
        bool: True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_network(network):
    """
    Check if the provided network address in CIDR notation is valid.

    Args:
        network (str): Network address in CIDR notation (e.g., '192.168.1.0/24')

    Returns:
        bool: True if valid network address, False otherwise
    """
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False


def scan_port(ip, port, timeout):
    """
    Scan a single port on the specified IP address.

    This function attempts to establish a TCP connection to the specified port.
    If the connection succeeds, the port is considered open.

    Args:
        ip (str): The IP address to scan
        port (int): The port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        tuple: (port, is_open, service_name)
            - port (int): The port that was scanned
            - is_open (bool): True if port is open, False otherwise
            - service_name (str or None): Service name if identified, None if closed
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = "unknown"
                try:
                    # Try to identify the service running on the port
                    service = socket.getservbyport(port)
                except OSError:
                    pass
                return port, True, service
            return port, False, None
    except socket.error:
        return port, False, None


def scan_host(ip, ports, timeout, max_workers):
    """
    Scan multiple ports on a host using a thread pool for faster scanning.

    Args:
        ip (str): The IP address to scan
        ports (list): List of port numbers to scan
        timeout (float): Connection timeout in seconds
        max_workers (int): Maximum number of concurrent threads

    Returns:
        tuple: (open_ports, duration)
            - open_ports (list): List of tuples containing (port, service) for open ports
            - duration (float): Time taken to complete the scan in seconds
    """
    open_ports = []

    print(
        f"\n{Fore.BLUE}[*] {Fore.WHITE}Scanning host: {Fore.YELLOW}{ip}{Style.RESET_ALL}")
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create a mapping of Future objects to ports for tracking results
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }

        # Process results as they complete
        for i, future in enumerate(concurrent.futures.as_completed(future_to_port)):
            port, is_open, service = future.result()
            if i % 500 == 0 and i > 0:
                print(
                    f"{Fore.BLUE}[*] {Fore.WHITE}Scanned {i}/{len(ports)} ports...")

            if is_open:
                open_ports.append((port, service))
                if service != "unknown":
                    print(
                        f"{Fore.GREEN}[+] {Fore.WHITE}Port {Fore.GREEN}{port}{Fore.WHITE} is open: {Fore.CYAN}{service}{Style.RESET_ALL}")
                else:
                    print(
                        f"{Fore.GREEN}[+] {Fore.WHITE}Port {Fore.GREEN}{port}{Fore.WHITE} is open{Style.RESET_ALL}")

    duration = time.time() - start_time
    return open_ports, duration


def main():
    """
    Main function to parse arguments and coordinate the scanning process.

    This function handles command-line arguments, validates the target,
    determines scan parameters, and executes the port scanning operation.
    """
    parser = argparse.ArgumentParser(
        description="SwiftPort Scanner - A lightweight network port scanner")
    parser.add_argument(
        "target", help="Target IP address, hostname, or network (CIDR notation)")
    parser.add_argument("-p", "--ports", default="1-1000",
                        help="Port range to scan (e.g., '1-1000' or '22,80,443')")
    parser.add_argument("-t", "--timeout", type=float,
                        default=1.0, help="Timeout in seconds (default: 1.0)")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="Maximum number of worker threads (default: 100)")
    parser.add_argument("--delay", type=float, default=0,
                        help="Delay between each host scan in seconds (default: 0)")

    args = parser.parse_args()

    print_banner()

    # Parse target
    target = args.target

    # Parse ports
    ports_to_scan = []
    for part in args.ports.split(','):
        if '-' in part:
            # Handle port ranges (e.g., 1-1000)
            start, end = map(int, part.split('-'))
            ports_to_scan.extend(range(start, end + 1))
        else:
            # Handle individual ports
            ports_to_scan.append(int(part))

    # Check if target is IP, network, or hostname
    if is_valid_ip(target):
        # Single IP address
        hosts = [target]
    elif is_valid_network(target):
        # Network in CIDR notation
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        print(
            f"{Fore.BLUE}[*] {Fore.WHITE}Scanning network {Fore.YELLOW}{target}{Fore.WHITE} ({len(hosts)} hosts){Style.RESET_ALL}")
    else:
        try:
            # Hostname that needs to be resolved
            ip = socket.gethostbyname(target)
            hosts = [ip]
            print(
                f"{Fore.BLUE}[*] {Fore.WHITE}Hostname {Fore.YELLOW}{target}{Fore.WHITE} resolved to {Fore.YELLOW}{ip}{Style.RESET_ALL}")
        except socket.gaierror:
            print(
                f"{Fore.RED}[!] {Fore.WHITE}Could not resolve hostname: {Fore.RED}{target}{Style.RESET_ALL}")
            return

    total_open_ports = 0
    start_time_all = time.time()

    print(
        f"{Fore.BLUE}[*] {Fore.WHITE}Scanning {len(ports_to_scan)} ports per host{Style.RESET_ALL}")

    # Scan each host
    for i, host in enumerate(hosts):
        if i > 0 and args.delay > 0:
            # Add delay between host scans if specified
            time.sleep(args.delay)

        open_ports, duration = scan_host(
            host, ports_to_scan, args.timeout, args.workers)
        total_open_ports += len(open_ports)

        # Print summary for this host
        if open_ports:
            print(f"{Fore.BLUE}[*] {Fore.WHITE}Found {Fore.GREEN}{len(open_ports)}{Fore.WHITE} open ports on {Fore.YELLOW}{host}{Fore.WHITE} in {duration:.2f} seconds{Style.RESET_ALL}")
        else:
            print(
                f"{Fore.BLUE}[*] {Fore.WHITE}No open ports found on {Fore.YELLOW}{host}{Fore.WHITE} in {duration:.2f} seconds{Style.RESET_ALL}")

    # Print overall summary
    total_duration = time.time() - start_time_all
    print(f"\n{Fore.BLUE}[*] {Fore.WHITE}Scan completed: {Fore.GREEN}{total_open_ports}{Fore.WHITE} open ports found across {Fore.YELLOW}{len(hosts)}{Fore.WHITE} hosts in {total_duration:.2f} seconds{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(
            f"\n{Fore.RED}[!] {Fore.WHITE}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
