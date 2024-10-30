# MAC AUTO Cloner

A cross-platform Python tool for changing MAC addresses, scanning network devices, and cloning MAC addresses from discovered devices. Supports Linux, macOS, and Windows with enhanced features for network discovery.

## Features

- 🔄 MAC address modification
- 🔍 Network device scanning
- 👥 MAC address cloning from discovered devices
- 🖥️ Cross-platform support (Linux, macOS, Windows)
- 🤖 Interactive mode for ease of use
- 🔐 Built-in security checks and validations

## Requirements

### Python Version
- Python 3.7 or higher

### Dependencies
Install required packages using:
```bash
pip install -r requirements.txt
```

Required packages:
- scapy>=2.5.0: For network scanning
- argparse>=1.4.0: For command-line argument parsing
- dataclasses>=0.6: For Python versions < 3.7
- typing>=3.7.4: For Python versions < 3.5
- netifaces>=0.11.0: For network interface handling
- mac-vendor-lookup>=0.12.0: For MAC vendor identification

### System Requirements

#### Linux
- Must be run as root
- `ip` command-line tool installed

#### macOS
- Must be run as root (sudo)
- For Wi-Fi interfaces:
  - `spoof-mac` recommended: `brew install spoof-mac`
  - May require SIP (System Integrity Protection) to be disabled
  - Some Apple Silicon Macs may have additional restrictions

#### Windows
- Must be run as Administrator
- `netsh` command-line tool access

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/mac-changer.git
cd mac-changer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. For macOS users (recommended):
```bash
brew install spoof-mac
```

## Usage

### Interactive Mode
Simply run the script without arguments:
```bash
# Linux/macOS
sudo python3 macchanger.py

# Windows (as Administrator)
python macchanger.py
```

### Command Line Options
```bash
usage: python3 macchanger.py [-h] [-i INTERFACE] [-m MAC] [-r] [-s] [-c CLONE]

options:
  -h, --help            Show this help message
  -i INTERFACE          Network interface to modify
  -m MAC               New MAC address
  -r, --random         Generate random MAC address
  -s, --scan           Scan network for devices
  -c CLONE             IP address to clone MAC from
```

### Examples

1. List available interfaces and scan network (Interactive Mode):
```bash
sudo python3 macchanger.py
```

2. Change to a specific MAC address:
```bash
sudo python3 macchanger.py -i eth0 -m 00:11:22:33:44:55
```

3. Set random MAC address:
```bash
sudo python3 macchanger.py -i eth0 -r
```

4. Scan network for devices:
```bash
sudo python3 macchanger.py -i eth0 -s
```

5. Clone MAC address from device:
```bash
sudo python3 macchanger.py -i eth0 -c 192.168.1.100
```

## Troubleshooting

### Linux
- Ensure you have root privileges
- Verify the interface exists using `ip link show`
- Make sure the interface isn't blocked by rfkill

### macOS
- For Wi-Fi interfaces:
  ```bash
  # Check current MAC address
  ifconfig en0 | grep ether
  
  # If MAC change fails, try spoof-mac directly
  sudo spoof-mac set XX:XX:XX:XX:XX:XX en0
  ```
- System Integrity Protection (SIP) might prevent MAC changes
- Some Apple Silicon Macs have additional security measures
- Consider using an external USB network adapter

### Windows
- Run as Administrator
- Check if the interface name is correct in Network Connections
- Some wireless adapters might not support MAC address changes

## Common Issues

1. "Permission denied":
   - Make sure you're running with sudo (Linux/macOS) or as Administrator (Windows)

2. "Interface not found":
   - Verify interface name using:
     - Linux: `ip link show`
     - macOS: `networksetup -listallhardwareports`
     - Windows: `netsh interface show interface`

3. "Invalid MAC address":
   - Ensure MAC address format is XX:XX:XX:XX:XX:XX
   - First byte must be even (unicast address)

4. macOS MAC change fails:
   - Try installing and using spoof-mac
   - Check if your Mac model supports MAC address changes
   - Consider using an external USB network adapter

## Security Considerations

- MAC address changes might be detected by network administrators
- Some networks might block devices with changed MAC addresses
- Changing MAC addresses might temporarily disrupt network connectivity
- Some operating systems reset MAC addresses after reboot

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and legal testing purposes only. Users are responsible for complying with local network policies and laws. The authors are not responsible for any misuse or damage caused by this program.
