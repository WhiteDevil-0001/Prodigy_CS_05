# Packet Sniffer Tool

This is a simple packet sniffer tool built using Python with a graphical user interface (GUI). It captures and analyzes network packets in real time, displaying information such as source and destination IP addresses, protocols, and payload data.

## Features

- Captures network packets in real-time.
- Displays:
  - Source IP Address
  - Destination IP Address
  - Protocol (in numeric form)
  - Payload (in hexadecimal)
- **Start/Stop functionality** to control packet capturing.
- Status indicator (RUNNING/STOPPED) for ease of use.
- Simple and user-friendly GUI for easy interaction.
- Option to clear the displayed output.

The tool is intended for educational use and should be used responsibly in controlled environments.

## Prerequisites
- Python 3.x
- Scapy library (`pip install scapy`)
- Tkinter (usually comes pre-installed with Python)

## Usage
1. **Clone the repository:**
   git clone https://github.com/WhiteDevil-0001/Prodigy_CS_05.git

2. Navigate to the directory:
    cd Prodigy_CS_05   

3. Install dependencies:
    Ensure you have scapy installed. You can install it using:
     `pip install scapy`.

4. Run the script:
    `python packet_sniffer.py`.

5. Start/Stop Sniffer:
- Press the "Start Capture" button to begin sniffing packets.
- Press the "Stop Capture" button to stop the sniffing process.
- The status label will indicate whether the sniffer is RUNNING or STOPPED.

## GUI Overview
- Start Sniffer: Starts capturing network packets in real-time.
- Stop Sniffer: Stops capturing network packets.
- Clear Output: Clears the displayed packet information.
- Status Indicator: Shows whether the sniffer is running or stopped.

## Disclaimer
This tool is for educational purposes only. Ensure you have permission to sniff network traffic on the network you are using this tool on. Unauthorized use may violate local, state, or federal laws.

