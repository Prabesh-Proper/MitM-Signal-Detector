# Rogue Internet Behavior Detector

A practical script for pentesting scenarios that detects rogue internet behavior by comparing expected vs observed network behavior and flags common man-in-the-middle tactics.

## Features

This tool detects:
- **DNS Hijacking** - Compares system DNS vs public resolvers
- **Fake Captive Portals** - Tests all major portal detection endpoints
- **Transparent Proxies** - Header analysis + IP mismatch detection
- **SSL Stripping/Interception** - Suspicious certificate issuers
- **Routing Anomalies** - Unexpected default gateways

## Installation

### Prerequisites
- Python 3.6 or higher
- `requests` library

### Install Dependencies
```bash
pip install requests
```

### Make Executable (Linux/Mac)
```bash
chmod +x rogue_detector.py
```

## Usage

### Basic Scan
```bash
python3 rogue_detector.py
```

### Advanced Usage
```bash
# Run in target network and save output
python3 rogue_detector.py > network_assessment.txt

# Combine with traffic capture
sudo tcpdump -i eth0 -w capture.pcap &
python3 rogue_detector.py
# Then analyze capture.pcap with Wireshark
```

## Output

The script performs comprehensive tests and outputs:
- 🔍 Test progress indicators
- ❌ Detected issues with details
- 📊 Summary of findings
- 🚨 MITM detection alerts

## Expected vs Observed Behavior

The script builds dynamic baselines from multiple trust anchors, adapting to network changes while flagging statistical outliers and suspicious patterns.

## Pro Tips for Pentesting

- Run on suspicious networks during red team engagements
- Combine with network traffic analysis tools
- Use in conjunction with other reconnaissance tools
- Monitor for false positives in complex network environments

## License

This project is for educational and pentesting purposes only. Use responsibly and with permission.

## Contributing

Feel free to submit issues and enhancement requests!
