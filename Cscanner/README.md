# CScanner v1.4 - Advanced Network Scanner in C

A high-performance, modular network scanner written in C for Linux.

## Features

- **Multiple Scan Types**: SYN, CONNECT, FIN, XMAS, NULL, ACK, UDP, SCTP
- **High Performance**: Multi-threaded with epoll async I/O
- **Raw Packet Handling**: Manual IP/TCP/UDP header construction
- **Service Detection**: Banner grabbing for 30+ services
- **OS Fingerprinting**: TCP-based OS detection (TTL, window size)
- **Adaptive Scan Rate**: Automatically adjusts based on latency/congestion
- **Pipeline Optimization**: Batch packet processing
- **Multiple Output Formats**: Normal, XML, JSON, Grepable, CSV
- **Color Output**: Terminal color-coded results
- **Lua Scripting**: Post-scan automation (requires liblua5.3-dev)

## Architecture

```
Cscanner/
├── network/          # Raw sockets, packet building, checksums
│   ├── io_uring_async.c    # Epoll-based async I/O
│   ├── adaptive_engine.c   # Adaptive scan rate
│   └── pipeline_optimizer.c # Packet batching
├── scanners/         # SYN, CONNECT, ACK, FIN, NULL, XMAS, UDP, SCTP
├── detection/        # Service detection, OS fingerprinting
├── output/          # Color output, CSV export
├── scripting/       # Lua automation
├── cli/             # Command-line interface
└── include/         # Header files
```

## Compilation

```bash
cd Cscanner
make
```

Requires root privileges for raw socket scans (SYN, FIN, XMAS, NULL, ACK).

## Usage

```bash
./cscanner -t <target> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-t <target>` | Target IP or hostname (required) |
| `-p <ports>` | Ports (e.g., 22,80,443 or 1-1000 or 1-65535 or all) |
| `-s <type>` | Scan type: connect, syn, fin, xmas, null, udp, ack, sctp |
| `-T <ms>` | Timeout in milliseconds (default: 2000) |
| `-c <n>` | Concurrent threads (default: 50, max: 500) |
| `-r <rate>` | Packet rate limit |
| `-sV` | Service version detection |
| `-O` | OS fingerprinting (requires root) |
| `-A` | Enable all detections |
| `-oN <file>` | Normal output |
| `-oX <file>` | XML output |
| `-oJ <file>` | JSON output |
| `-oG <file>` | Grepable output |
| `-oC <file>` | CSV output |
| `--color` | Color output (terminal) |
| `--adaptive` | Enable adaptive scan rate |
| `-i <interface>` | Network interface |
| `-L <script>` | Lua post-scan script |
| `-v` | Verbose mode |

### Examples

```bash
# Basic scan
./cscanner -t 192.168.1.1 -p 1-1000

# SYN scan with service detection
./cscanner -t 192.168.1.1 -p 1-1000 -sS -sV

# Fast scan with adaptive rate
./cscanner -t target.com -p 1-10000 -T4 --adaptive

# Full port scan with OS fingerprinting
./cscanner -t target.com -p 1-65535 -sS -O -oJ results.json

# Color output
./cscanner -t target.com -p 22,80,443 --color
```

## Adaptive Engine

The adaptive engine automatically adjusts scan parameters based on:
- Latency measurements
- Congestion factor (latency variance)
- Success/failure rates

Modes:
- `ADAPTIVE_SLOW`: 50 packets/sec
- `ADAPTIVE_NORMAL`: 500 packets/sec
- `ADAPTIVE_FAST`: 2000 packets/sec
- `ADAPTIVE_INSANE`: 8000 packets/sec

## OS Fingerprinting

OS detection uses:
- **TTL analysis**: Determines approximate OS family
- **TCP Window size**: Identifies specific OS versions

## CSV Export

Export results to CSV for spreadsheet analysis:
```bash
./cscanner -t target.com -p 1-1000 -oC results.csv
```

CSV format includes: IP, Port, Protocol, State, Service, Version, Response Time, TTL, Window, OS Guess

## Lua Scripting

Post-scan automation with Lua scripts:

```lua
function on_scan_complete(results)
    for i, result in ipairs(results) do
        if result.state == 1 then  -- OPEN
            print("Open port: " .. result.port .. " (" .. result.service .. ")")
        end
    end
end
```

Enable with: `-L script.lua` (requires liblua5.3-dev)

## License

MIT License
