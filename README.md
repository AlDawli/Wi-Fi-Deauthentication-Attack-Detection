# Wi-Fi-Deauthentication-Attack-Detection
comprehensive instructions for setting up a defensive Wi-Fi security lab to study deauthentication attacks and test detection systems. All activities described are for authorized testing environments only.

# Authorized Use Cases
Personal home networks you own
Corporate networks with proper authorization
Isolated lab environments
Educational/research environments with approval

# Lab Environment Setup
Hardware Requirements
Essential Equipment
Linux-capable computer (laptop preferred for mobility)

# USB Wi-Fi adapters with monitor mode support:
Recommended: Alfa AWUS036ACS, AWUS036NHA, or similar
Alternative: Internal Wi-Fi cards with ath9k/ath10k drivers
Access Point for controlled testing
Test client devices (phones, laptops, IoT devices)

# Software Requirements
Linux Distribution Setup
Recommended distributions:

Kali Linux (security-focused, tools pre-installed)
Ubuntu/Debian (general purpose, manual tool installation)
Parrot Security OS (security-focused alternative)

# Essential Software Installation
# Ubuntu/Debian installation
sudo apt update
sudo apt install -y python3 python3-pip aircrack-ng wireshark tcpdump

# Python dependencies
pip3 install scapy pandas matplotlib seaborn numpy

# Optional: Install additional monitoring tools
sudo apt install -y kismet hostapd dnsmasq
Driver Installation for USB Wi-Fi Adapters
bash# For Realtek adapters (common in Alfa cards)
sudo apt install realtek-rtl88xxau-dkms

# For Atheros adapters
sudo apt install firmware-atheros

# Verify monitor mode capability
sudo airmon-ng
Setting Up the Test Environment
1. Isolated Test Network Create a dedicated test SSID that's isolated from production networks:
Create a dedicated test SSID that's isolated from production networks:
bash# Configure test access point with hostapd
sudo nano /etc/hostapd/hostapd.conf
2. Network Interface Configuration
bash# Put interface in monitor mode
sudo airmon-ng start wlan0

# Verify monitor mode
iwconfig wlan0mon

# Set specific channel for monitoring
sudo iwconfig wlan0mon channel 6
Mitigation testing recommendations (safe)
Focus on defensive validation:
PMF/802.11w: Enable on AP and check clients that support it — verify that unsolicited deauth/disassoc frames are ignored or rejected (check client logs).
AP rate-limiting: Configure vendor AP management frame throttling and validate that device connectivity remains stable under high management-frame load.
Segmentation: Move critical devices to a separate SSID/VLAN with stricter management frame handling and monitor for decreased impact.
Monitoring: Integrate JSON output from this tool into a SIEM (via a simple ingestion script) and create automated alerting when anomaly_score or number of suspicious sources exceeds threshold.
