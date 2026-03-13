# Cscanner

Cscanner is an ultra-fast advanced network scanner written in **C and C++**, designed for high-performance port scanning, service detection, and network analysis.

## Features

- High-performance scanning engine
- Multi-threaded architecture
- TCP and UDP scanning
- TCP Connect, SYN, ACK, FIN, NULL, Xmas scans
- Full port range scanning (1-65535)
- Service detection and banner grabbing
- Basic OS fingerprinting
- CIDR and multi-host scanning
- Adaptive scanning engine
- Colorized terminal output

## Installation

git clone https://github.com/black-map/Cscanner.git  
cd Cscanner  
make

## Usage

Basic scan:

./cscanner example.com

Full port scan:

./cscanner -t example.com -p 1-65535

Network scan:

./cscanner -t 192.168.1.0/24

## Example Output

HOST: scanme.nmap.org

PORT      STATE    SERVICE
22/tcp    OPEN     ssh
80/tcp    OPEN     http
443/tcp   OPEN     https

## Requirements

- Linux
- GCC / G++
- Root privileges for raw socket scans

## Security Notice

Use this tool only on networks you own or have permission to test.

## License

MIT License

Author: black-map
