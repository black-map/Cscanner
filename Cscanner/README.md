# CScanner - Advanced Network Scanner in C

A high-performance, modular network scanner written in C for Linux.

## Features

- **Multiple Scan Types**: SYN, CONNECT, FIN, XMAS, NULL, ACK, UDP
- **High Performance**: Multi-threaded with epoll/I/O async
- **Raw Packet Handling**: Manual IP/TCP/UDP header construction
- **Service Detection**: Banner grabbing for 30+ services
- **OS Fingerprinting**: TCP-based OS detection
- **Multiple Output Formats**: Normal, XML, JSON, Grepable

## Architecture

```
Cscanner/
├── network/        # Raw sockets, packet building, checksums
├── scanners/       # SYN, CONNECT, ACK, FIN, NULL, XMAS, UDP
├── detection/      # Service detection, banner grabbing
├── cli/            # Command-line interface
└── include/        # Header files
```

## Compilation

```bash
cd Cscanner
make
```

## Usage

```bash
./cscanner <target> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-p <ports>` | Ports to scan (e.g., 22,80,443 or 1-1000) |
| `-s <type>` | Scan type: connect, syn, fin, xmas, null, ack, udp |
| `-T <1-5>` | Timing template (T1=slow, T5=fast) |
| `-c <n>` | Concurrent threads |
| `-sV` | Service version detection |
| `-oN <file>` | Normal output |
| `-oX <file>` | XML output |
| `-oJ <file>` | JSON output |
| `-oG <file>` | Grepable output |
| `-v` | Verbose mode |

### Examples

```bash
# Basic scan
./cscanner 192.168.1.1 -p 1-1000

# SYN scan with service detection
./cscanner 192.168.1.1 -p 1-1000 -sS -sV

# Fast scan
./cscanner target.com -p 1-10000 -T5
```

## License

MIT License
