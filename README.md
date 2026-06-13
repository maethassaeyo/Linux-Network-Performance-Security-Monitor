# Linux Network Performance & Security Monitor

An all-in-one C++/Qt5 desktop application for real-time network monitoring, security analysis, and performance testing on Linux systems.

## Features

### 1. Performance Monitoring (Real-time)
*   **Live Throughput:** Real-time Download and Upload speed monitoring by interfacing directly with `/proc/net/dev`.
*   **Latency Tracking:** Continuous ICMP ping monitoring to external DNS (8.8.8.8) to measure connection stability.
*   **Integrated Speed Test:** Built-in speed test functionality powered by the official Speedtest CLI (Ookla) to measure maximum bandwidth.

### 2. Security & Traffic Analysis
*   **Packet Sniffing:** Deep packet inspection using `libpcap` to monitor active network connections.
*   **IP Ranking:** Real-time display of the **Top 5** connections consuming the most bandwidth (sorted by packet size).
*   **Geo-IP Mapping:** Automatic geolocation of destination IPs using the MaxMind GeoLite2 database to identify connection origins/destinations.
*   **Security Blacklist:** Real-time alerting system that highlights potentially malicious or blacklisted IP addresses in red.

### 3. Protocol Insights
*   **Protocol Distribution:** Visual breakdown and percentage calculation of network traffic types (TCP, UDP, DNS, ICMP).

## Architecture
The application is built with a **Multi-threaded Architecture** to ensure high performance and UI responsiveness:
*   **Main Thread:** Handles the Qt5 GUI event loop and real-time UI updates.
*   **Worker Threads:** Dedicated threads for packet sniffing, speed calculation, and latency testing to prevent UI freezing during heavy network activity.

## Prerequisites
*   **OS:** Linux (Tested on Fedora/Ubuntu)
*   **Libraries:** 
    *   Qt5 (Widgets, Core, Gui)
    *   libpcap-devel
    *   libmaxminddb-devel
*   **Tools:**
    *   speedtest-cli (for the Speed Test feature)

## Installation & Compilation

1. **Install Dependencies (Fedora):**
   ```bash
   sudo dnf install qt5-qtbase-devel libpcap-devel libmaxminddb-devel speedtest-cli
   ```

2. **Compile the Application:**
   ```bash
   # Create build directory
   mkdir -p build
   
   # Generate Meta-Object code for Qt
   /usr/lib64/qt5/bin/moc src/NetworkMonitorGUI.cpp -o src/NetworkMonitorGUI.moc

   # Compile with G++
   g++ src/NetworkMonitorGUI.cpp -o NetworkMonitorGUI \
   -DQT_WIDGETS_LIB -I/usr/include/qt5/QtWidgets -I/usr/include/qt5 \
   -DQT_GUI_LIB -I/usr/include/qt5/QtGui -DQT_CORE_LIB -I/usr/include/qt5/QtCore \
   -lQt5Widgets -lQt5Gui -lQt5Core -lpcap -lmaxminddb -lpthread -fPIC
   ```

## Project Structure
- `src/`: Source code for GUI and CLI versions.
- `data/`: Database files (GeoLite2, Blacklists).
- `update_databases.sh`: Script to update GeoIP and security databases.
- `README.md`: Project documentation.

## Updating Databases
To keep the Geo-IP and Security Blacklist up to date, run the included update script:

```bash
chmod +x update_databases.sh
./update_databases.sh
```
This script downloads the latest weekly GeoLite2-Country database and a real-time malicious IP blocklist from Emerging Threats.

## Usage
The application requires root privileges to access raw network sockets via `libpcap`.

```bash
sudo ./NetworkMonitorGUI
```

## License
This project uses the GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).
