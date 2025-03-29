
# SwiftPort Scanner

A fast, lightweight network port scanner written in Python.

## Features

- Scan individual IP addresses, hostnames, or entire networks (CIDR notation)
- Specify custom port ranges to scan
- Multi-threaded scanning for improved performance
- Color-coded terminal output
- Service name identification for common ports

## Installation

1. Clone this repository or download the files
2. Install the required dependencies:

```
pip install -r requirements.txt
```

3. Make the script executable (Linux/macOS):

```
chmod +x swiftport.py
```

## Usage

Basic usage:

```
python swiftport.py [target]
```

Examples:

```
# Scan a single host with default options (ports 1-1000)
python swiftport.py 192.168.1.1

# Scan specific ports on a host
python swiftport.py 192.168.1.1 -p 22,80,443

# Scan a port range
python swiftport.py 192.168.1.1 -p 1-1000

# Scan an entire network
python swiftport.py 192.168.1.0/24

# Scan with a longer timeout
python swiftport.py 192.168.1.1 -t 2.0

# Scan with more worker threads for faster scanning
python swiftport.py 192.168.1.1 -w 200
```

## Command Line Options

```
positional arguments:
  target                Target IP address, hostname, or network (CIDR notation)

optional arguments:
  -h, --help            Show this help message and exit
  -p, --ports PORTS     Port range to scan (e.g., '1-1000' or '22,80,443')
  -t, --timeout TIMEOUT Timeout in seconds (default: 1.0)
  -w, --workers WORKERS Maximum number of worker threads (default: 100)
  --delay DELAY         Delay between each host scan in seconds (default: 0)
```

## Notes

- Increasing the number of worker threads with `-w` can speed up scanning but might be more detectable on the network
- For stealthy scanning, use `--delay` to add pauses between host scans
- Port scanning without permission can be illegal; only scan networks you have permission to test

## License

This project is licensed under the MIT License.

## Author

Created by Scott Thornton
