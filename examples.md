
# SwiftPort Scanner Examples

Here are some common usage examples for SwiftPort Scanner.

## Basic Scanning

Scan a single host with default settings:

```bash
python swiftport.py 192.168.1.1
```

## Scanning Specific Ports

Scan only specific ports on a target:

```bash
python swiftport.py 192.168.1.1 -p 22,80,443,3306,8080
```

## Scanning Port Ranges

Scan a range of ports:

```bash
python swiftport.py 192.168.1.1 -p 1-1000
```

Scan multiple port ranges:

```bash
python swiftport.py 192.168.1.1 -p 1-100,443,8000-8100
```

## Network Scanning

Scan an entire network (subnet):

```bash
python swiftport.py 192.168.1.0/24
```

## Adjusting Scan Speed and Performance

For faster scanning with more threads:

```bash
python swiftport.py 192.168.1.1 -w 200
```

For more reliable scanning with longer timeouts:

```bash
python swiftport.py 192.168.1.1 -t 2.0
```

## Stealthy Scanning

Add delays between host scans to be less detectable:

```bash
python swiftport.py 192.168.0.0/24 --delay 0.5
```

## Scanning Remote Hosts

Scan a remote website by hostname:

```bash
python swiftport.py example.com -p 80,443
```

## Saving Scan Results

You can save the scan results to a file by redirecting the output:

```bash
python swiftport.py 192.168.1.0/24 > scan_results.txt
```

## Common Port Groups

### Web Servers
```bash
python swiftport.py 192.168.1.1 -p 80,443,8080,8443
```

### Mail Servers
```bash
python swiftport.py 192.168.1.1 -p 25,110,143,465,587,993,995
```

### Database Servers
```bash
python swiftport.py 192.168.1.1 -p 1433,1521,3306,5432,6379,27017
```

### Remote Access
```bash
python swiftport.py 192.168.1.1 -p 22,23,3389,5900
```
