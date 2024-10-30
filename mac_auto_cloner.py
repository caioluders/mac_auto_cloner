#!/usr/bin/env python3

import argparse
import ctypes
import subprocess
from dataclasses import dataclass
from platform import system
from random import randint
import re
import scapy.all as scapy
from typing import List, Optional, Dict, Set
import os
import netifaces
import sys
import threading
import queue
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class NetworkDevice:
    ip: str
    mac: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    ports: Optional[List[int]] = None
    
    def __hash__(self):
        return hash(self.ip + self.mac)

class NetworkScanner:
    """Enhanced network scanning capabilities"""
    
    def __init__(self, interface: str):
        self.interface = interface
        self.network_range = self._get_network_range()
        self.devices: Set[NetworkDevice] = set()
        self.lock = threading.Lock()
        
    def _get_network_range(self) -> str:
        """Get network range based on interface IP and netmask"""
        try:
            ip = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['addr']
            netmask = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]['netmask']
            # Calculate network address
            ip_parts = [int(part) for part in ip.split('.')]
            mask_parts = [int(part) for part in netmask.split('.')]
            network = [ip_parts[i] & mask_parts[i] for i in range(4)]
            return f"{'.'.join(map(str, network))}/24"
        except Exception:
            return '192.168.1.0/24'

    def _arp_scan(self):
        """ARP scanning method"""
        arp = scapy.ARP(pdst=self.network_range)
        ether = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = ether/arp

        try:
            result = scapy.srp(packet, timeout=3, verbose=False, iface=self.interface)[0]
            
            for sent, received in result:
                device = NetworkDevice(
                    ip=received.psrc,
                    mac=received.hwsrc
                )
                with self.lock:
                    self.devices.add(device)
        except Exception as e:
            print(f"ARP scan error: {str(e)}")

    def _ping_scan(self):
        """ICMP ping sweep"""
        base_ip = self.network_range.split('/')[0]
        base_parts = base_ip.split('.')
        
        def ping_host(ip):
            try:
                if system() == "Windows":
                    ping_cmd = ['ping', '-n', '1', '-w', '100', ip]
                else:
                    ping_cmd = ['ping', '-c', '1', '-W', '1', ip]
                    
                result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode == 0:
                    # Try to get MAC address for responding hosts
                    if system() == "Windows":
                        arp_cmd = ['arp', '-a', ip]
                    else:
                        arp_cmd = ['arp', '-n', ip]
                    
                    arp_result = subprocess.run(arp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', arp_result.stdout)
                    
                    if mac_match:
                        device = NetworkDevice(
                            ip=ip,
                            mac=mac_match.group(0)
                        )
                        with self.lock:
                            self.devices.add(device)
            except Exception:
                pass

        # Create IP range
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for i in range(1, 255):
                ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}"
                futures.append(executor.submit(ping_host, ip))
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    def _tcp_scan(self):
        """Quick TCP scan on common ports"""
        common_ports = [80, 443, 22, 445, 139]  # Add more common ports if needed
        
        def scan_host_port(ip: str, port: int):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    # Try to get MAC address for responding hosts
                    if system() == "Windows":
                        arp_cmd = ['arp', '-a', ip]
                    else:
                        arp_cmd = ['arp', '-n', ip]
                    
                    arp_result = subprocess.run(arp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', arp_result.stdout)
                    
                    if mac_match:
                        device = NetworkDevice(
                            ip=ip,
                            mac=mac_match.group(0),
                            ports=[port]
                        )
                        with self.lock:
                            self.devices.add(device)
            except Exception:
                pass

        base_ip = self.network_range.split('/')[0]
        base_parts = base_ip.split('.')
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for i in range(1, 255):
                ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}"
                for port in common_ports:
                    futures.append(executor.submit(scan_host_port, ip, port))
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

    def _resolve_hostnames(self):
        """Resolve hostnames for discovered devices"""
        for device in self.devices:
            try:
                hostname = socket.gethostbyaddr(device.ip)[0]
                device.hostname = hostname
            except Exception:
                pass

    def scan(self) -> List[NetworkDevice]:
        """Perform comprehensive network scan using multiple methods"""
        print("\nPerforming network scan (this may take a minute)...")
        print("Using multiple scanning methods for better device discovery...")
        
        # Create threads for different scanning methods
        threads = [
            threading.Thread(target=self._arp_scan),
            threading.Thread(target=self._ping_scan),
            threading.Thread(target=self._tcp_scan)
        ]
        
        # Start all scanning threads
        for thread in threads:
            thread.start()
        
        # Wait for all scans to complete
        for thread in threads:
            thread.join()
            
        # Resolve hostnames for discovered devices
        self._resolve_hostnames()
        
        return sorted(list(self.devices), key=lambda x: socket.inet_aton(x.ip))        

class MACChanger:
    def __init__(self):
        self.os = system()
        self.parser = self._create_parser()
        
    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description='Change MAC address and scan network devices')
        parser.add_argument('-i', '--interface', help='Network interface')
        parser.add_argument('-m', '--mac', help='New MAC address')
        parser.add_argument('-r', '--random', action='store_true', help='Use random MAC')
        parser.add_argument('-s', '--scan', action='store_true', help='Scan network devices')
        parser.add_argument('-c', '--clone', help='IP address to clone MAC from')
        return parser

    def _check_privileges(self):
        if self.os == "Windows":
            if not ctypes.windll.shell32.IsUserAnAdmin():
                raise PermissionError("Run as administrator")
        elif not os.geteuid() == 0:
            raise PermissionError("Run as root")

    def _get_interfaces(self) -> Dict[str, str]:
        """Get available network interfaces with their current MAC addresses."""
        interfaces = {}
        
        for iface in netifaces.interfaces():
            # Skip loopback and non-physical interfaces
            if iface == 'lo' or ':' in iface:
                continue
                
            try:
                # Get MAC address
                mac = netifaces.ifaddresses(iface).get(netifaces.AF_LINK)
                if mac:
                    mac = mac[0].get('addr')
                    
                # Get IP address
                ip = netifaces.ifaddresses(iface).get(netifaces.AF_INET)
                ip = ip[0].get('addr') if ip else 'No IP'
                
                if mac:  # Only add interfaces with MAC addresses (physical interfaces)
                    interfaces[iface] = f"MAC: {mac:<17} IP: {ip}"
            except Exception:
                continue
                
        return interfaces

    def _validate_mac(self, mac: str) -> bool:
        return bool(re.match("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", mac) 
                   and int(mac.split(':')[0], 16) % 2 == 0)

    def _generate_random_mac(self) -> str:
        while True:
            mac = ":".join([f"{randint(0, 255):02x}" for _ in range(6)])
            if self._validate_mac(mac):
                return mac

    def _get_network_range(self, interface: str) -> str:
        """Get the network range for scanning based on interface IP."""
        try:
            ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
            netmask = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['netmask']
            # Convert IP and netmask to network address
            ip_parts = [int(part) for part in ip.split('.')]
            mask_parts = [int(part) for part in netmask.split('.')]
            network = [ip_parts[i] & mask_parts[i] for i in range(4)]
            return f"{'.'.join(map(str, network))}/24"  # Using /24 for common networks
        except Exception:
            return '192.168.1.0/24'  # Fallback to common private network range

    def _scan_network(self, interface: str) -> List[NetworkDevice]:
        scanner = NetworkScanner(interface)
        devices = scanner.scan()
        
        print(f"\nFound {len(devices)} devices:")
        print("\nIP Address       MAC Address       Hostname")
        print("-" * 50)
        
        for device in devices:
            hostname = device.hostname if device.hostname else "N/A"
            print(f"{device.ip:<15} {device.mac:<15} {hostname[:30]}")
            if device.ports:
                print(f"   └─ Open ports: {', '.join(map(str, device.ports))}")
        
        return devices

    def _is_wifi_interface(self, interface: str) -> bool:
        """Check if the interface is a WiFi interface on macOS"""
        try:
            result = subprocess.run(
                ['networksetup', '-listallhardwareports'],
                capture_output=True,
                text=True
            )
            output = result.stdout
            
            # Find the section for our interface
            sections = output.split('\n\n')
            for section in sections:
                if interface in section:
                    return 'Wi-Fi' in section
            return False
        except Exception:
            return False

    def _get_hardware_port(self, interface: str) -> str:
        """Get the hardware port name for the interface on macOS"""
        try:
            result = subprocess.run(
                ['networksetup', '-listallhardwareports'],
                capture_output=True,
                text=True
            )
            output = result.stdout
            
            # Parse the output to find the hardware port name
            lines = output.split('\n')
            for i, line in enumerate(lines):
                if f'Device: {interface}' in line and i > 0:
                    # Hardware port name is in the format "Hardware Port: <name>"
                    port_line = lines[i-1]
                    if port_line.startswith('Hardware Port: '):
                        return port_line.split(': ')[1]
            return ""
        except Exception:
            return ""

    def _get_wifi_info_macos(self):
        """Get Wi-Fi interface and service name on macOS"""
        try:
            # Get all hardware ports
            result = subprocess.run(
                ['networksetup', '-listallhardwareports'],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse the output to find Wi-Fi interface
            lines = result.stdout.split('\n')
            wifi_device = None
            wifi_service = None
            
            for i, line in enumerate(lines):
                if 'Wi-Fi' in line or 'AirPort' in line:
                    # Look for the device name in the next lines
                    for j in range(i, min(i + 3, len(lines))):
                        if 'Device: ' in lines[j]:
                            wifi_device = lines[j].split('Device: ')[1].strip()
                            break
            
            # Get network services to find Wi-Fi service name
            if wifi_device:
                services_result = subprocess.run(
                    ['networksetup', '-listallnetworkservices'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                for service in services_result.stdout.split('\n'):
                    if 'Wi-Fi' in service or 'AirPort' in service:
                        wifi_service = service.strip()
                        break
            
            return wifi_device, wifi_service
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Error getting Wi-Fi information: {e}")

    def _change_mac_macos(self, interface: str, new_mac: str):
        """macOS specific MAC address changing with Wi-Fi support"""
        try:
            print("\nGetting Wi-Fi information...")
            wifi_device, wifi_service = self._get_wifi_info_macos()
            
            if not wifi_device or not wifi_service:
                raise RuntimeError("Could not identify Wi-Fi interface and service name")
                
            print(f"Found Wi-Fi Device: {wifi_device}")
            print(f"Found Wi-Fi Service: {wifi_service}")

            # Disable Wi-Fi
            print("\nDisabling Wi-Fi...")
            subprocess.run(
                ['networksetup', '-setairportpower', wifi_device, 'off'],
                check=True
            )
            time.sleep(1)

            # Try multiple methods to change MAC address
            methods = [
                # Method 1: Using ifconfig
                lambda: subprocess.run(['sudo', 'ifconfig', wifi_device, 'ether', new_mac], check=True),
                
                # Method 2: Using NetworksetupConfiguration
                lambda: subprocess.run(
                    ['sudo', '/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport', 
                     '-z'],
                    check=True
                ),
                
                # Method 3: Using en0 reference
                lambda: subprocess.run(['sudo', 'ifconfig', 'en0', 'lladdr', new_mac], check=True)
            ]

            success = False
            for method in methods:
                try:
                    method()
                    success = True
                    break
                except subprocess.CalledProcessError:
                    continue

            if not success:
                print("\nWarning: Standard methods to change MAC address failed.")
                print("Attempting alternative method...")
                
                # Alternative method using spoof-mac if available
                try:
                    subprocess.run(['spoof-mac', 'set', new_mac, wifi_device], check=True)
                    success = True
                except FileNotFoundError:
                    print("spoof-mac not found. You can install it with: brew install spoof-mac")
                except subprocess.CalledProcessError as e:
                    print(f"spoof-mac failed: {e}")

            # Re-enable Wi-Fi
            print("\nRe-enabling Wi-Fi...")
            subprocess.run(
                ['networksetup', '-setairportpower', wifi_device, 'on'],
                check=True
            )
            time.sleep(2)

            # Verify the change
            print("\nVerifying MAC address change...")
            verify_cmd = subprocess.run(
                ['ifconfig', wifi_device],
                capture_output=True,
                text=True,
                check=True
            )
            
            if new_mac.lower().replace(':', '').replace('-', '') not in \
               verify_cmd.stdout.lower().replace(':', '').replace('-', ''):
                print("\nWarning: MAC address change could not be verified.")
                print("\nPossible solutions:")
                print("1. Install spoof-mac: brew install spoof-mac")
                print("2. Disable System Integrity Protection (SIP)")
                print("3. Use an external USB Wi-Fi adapter")
                print("\nNote: Modern macOS versions have increased security that may prevent MAC address changes.")
                
                # Get current MAC for debugging
                print("\nCurrent MAC address information:")
                subprocess.run(['ifconfig', wifi_device], check=True)
            else:
                print(f"\nSuccessfully changed MAC address of {wifi_device} to {new_mac}")

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Error changing MAC address: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error: {e}")

    def _change_mac(self, interface: str, new_mac: str):
        """Change MAC address with OS-specific handling"""
        if self.os == "Darwin":  # macOS
            self._change_mac_macos(interface, new_mac)
        elif self.os == "Linux":
            commands = [
                ["ip", "link", "set", interface, "down"],
                ["ip", "link", "set", interface, "address", new_mac],
                ["ip", "link", "set", interface, "up"]
            ]
            
            try:
                for cmd in commands:
                    subprocess.run(cmd, check=True)
                print(f"\nSuccessfully changed MAC address of {interface} to {new_mac}")
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Failed to change MAC address: {e}")
                
        elif self.os == "Windows":
            commands = [
                ["netsh", "interface", "set", "interface", interface, "admin=disable"],
                ["netsh", "interface", "set", "interface", interface, f"ethernet={new_mac}", "admin=enable"]
            ]
            
            try:
                for cmd in commands:
                    subprocess.run(cmd, check=True)
                print(f"\nSuccessfully changed MAC address of {interface} to {new_mac}")
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Failed to change MAC address: {e}")
        else:
            raise OSError(f"Unsupported OS: {self.os}")

    def _interactive_mode(self):
        """Interactive mode when no arguments are provided."""
        print("\n=== MAC Address AUTO Cloner ===")
        
        # List and select interface
        interfaces = self._get_interfaces()
        if not interfaces:
            print("No suitable network interfaces found.")
            return 1

        print("\nAvailable interfaces:")
        for idx, (iface, info) in enumerate(interfaces.items(), 1):
            print(f"{idx}. {iface:<15} {info}")

        while True:
            try:
                choice = int(input("\nSelect interface number: "))
                if 1 <= choice <= len(interfaces):
                    selected_interface = list(interfaces.keys())[choice - 1]
                    break
                print("Invalid choice. Please try again.")
            except ValueError:
                print("Please enter a number.")

        # Scan network and select device to clone
        devices = self._scan_network(selected_interface)
        
        if not devices:
            print("\nNo devices found on the network.")
            print("Would you like to:")
            print("1. Use a random MAC address")
            print("2. Enter a MAC address manually")
            print("3. Exit")
            
            while True:
                try:
                    choice = int(input("\nEnter your choice: "))
                    if choice == 1:
                        new_mac = self._generate_random_mac()
                        break
                    elif choice == 2:
                        while True:
                            mac = input("Enter MAC address (format: xx:xx:xx:xx:xx:xx): ")
                            if self._validate_mac(mac):
                                new_mac = mac
                                break
                            print("Invalid MAC address format. Please try again.")
                        break
                    elif choice == 3:
                        return 0
                    print("Invalid choice. Please try again.")
                except ValueError:
                    print("Please enter a number.")
        else:
            print("\nDetected devices:")
            for i, device in enumerate(devices, 1):
                print(f"{i}. IP: {device.ip:<15} MAC: {device.mac}")
            print(f"{len(devices) + 1}. Use random MAC")
            print(f"{len(devices) + 2}. Enter MAC manually")

            while True:
                try:
                    choice = int(input("\nSelect device number to clone MAC or other option: "))
                    if 1 <= choice <= len(devices):
                        new_mac = devices[choice - 1].mac
                        break
                    elif choice == len(devices) + 1:
                        new_mac = self._generate_random_mac()
                        break
                    elif choice == len(devices) + 2:
                        while True:
                            mac = input("Enter MAC address (format: xx:xx:xx:xx:xx:xx): ")
                            if self._validate_mac(mac):
                                new_mac = mac
                                break
                            print("Invalid MAC address format. Please try again.")
                        break
                    print("Invalid choice. Please try again.")
                except ValueError:
                    print("Please enter a number.")

        # Change MAC address
        try:
            self._change_mac(selected_interface, new_mac)
            return 0
        except Exception as e:
            print(f"Error: {str(e)}")
            return 1

    def run(self):
        args = self.parser.parse_args()
        
        try:
            self._check_privileges()

            # If no arguments provided, run interactive mode
            if len(sys.argv) == 1:
                return self._interactive_mode()

            if args.scan:
                if not args.interface:
                    raise ValueError("Interface required for scanning")
                devices = self._scan_network(args.interface)
                print("\nDetected devices:")
                for i, device in enumerate(devices, 1):
                    print(f"{i}. IP: {device.ip:15} MAC: {device.mac}")
                return 0

            if args.clone:
                if not args.interface:
                    raise ValueError("Interface required for cloning")
                devices = self._scan_network(args.interface)
                target_device = next((d for d in devices if d.ip == args.clone), None)
                if not target_device:
                    raise ValueError(f"No device found with IP {args.clone}")
                self._change_mac(args.interface, target_device.mac)
                return 0

            if not args.interface:
                raise ValueError("Interface required")
            
            new_mac = None
            if args.random:
                new_mac = self._generate_random_mac()
            elif args.mac:
                if not self._validate_mac(args.mac):
                    raise ValueError("Invalid MAC address format")
                new_mac = args.mac
            else:
                raise ValueError("Specify either --mac or --random")

            self._change_mac(args.interface, new_mac)
            return 0

        except Exception as e:
            print(f"Error: {str(e)}")
            return 1

if __name__ == "__main__":
    changer = MACChanger()
    sys.exit(changer.run())
